"""Git diff and isolated command-result collection for model attempts."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, Sequence

from .artifact_store import (
    default_runs_root,
    list_attempts,
    load_manifest,
    run_lock,
    write_attempt_result,
)
from .inventory import (
    GITLINK_MODE,
    REGULAR_MODE,
    EXECUTABLE_MODE,
    SPECIAL_MODE,
    blob_id,
    parse_tree,
    walk_worktree,
    write_loose_blob,
)
from .run_manager import update_run_status
from .sandbox import (
    MAX_WORKSPACE_BYTES,
    BubblewrapCommandRunner,
    SandboxUnavailable,
    prepare_workspace,
    remove_workspace,
    run_git_bytes,
    run_sandboxed_git,
    run_scratch_git,
    scratch_index_env,
)
from .schemas import (
    ATTESTATION_KEYS,
    AttemptResult,
    AttestationStatus,
    CommandResult,
    RunStatus,
    SENSITIVE_PATH_PATTERNS,
    aggregate_attestations,
    aggregate_boundary_signals,
    attestation_block,
)


HISTORY_MUTATIONS = frozenset({"head_changed", "refs_changed"})


class EvaluationEngineError(ValueError):
    pass


class GitExecutor(Protocol):
    def snapshot(self, baseline_sha: str) -> dict[str, Any]: ...

    def state(self) -> tuple[dict[str, str], list[str]]: ...

    def history_delta(
        self, before: dict[str, str], after: dict[str, str]
    ) -> dict[str, int]: ...


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult: ...


def collect_run_results(
    *,
    run_id: str,
    runs_root: Path | None = None,
    git_executor_factory: Any | None = None,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Collect each registered attempt deterministically and fail closed."""

    root = (runs_root or default_runs_root()).resolve()
    run = load_manifest(root, run_id)
    attempts = list_attempts(root, run_id)
    if not attempts:
        raise EvaluationEngineError("no_attempts_registered")

    collected: list[dict[str, Any]] = []
    attestations: list[dict[str, Any]] = []
    signals: list[dict[str, bool | None]] = []
    runner = command_runner or BubblewrapCommandRunner()
    sandbox_error = _preflight(runner) if run.required_tests or run.required_builds else None

    with run_lock(root, run_id):
        for attempt in attempts:
            worktree = Path(attempt.worktree_path)
            executor = (
                git_executor_factory(worktree)
                if git_executor_factory
                else SubprocessGitExecutor(worktree, _repo_root(run.repo_root))
            )
            result = _collect_attempt(run, attempt, executor, runner, sandbox_error)
            path = write_attempt_result(result, root)
            attestations.append(result.attestations)
            signals.append(result.boundary_signals)
            collected.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "model_provider": attempt.model_provider,
                    "result_path": str(path),
                    "files_changed": len(result.files_changed),
                    "scope_violations": len(result.scope_violations),
                    "prohibited_violations": len(result.prohibited_violations),
                    "sensitive_paths": len(result.sensitive_paths_found),
                    "tests_passed": result.tests_passed,
                    "tests_total": result.tests_total,
                    "builds_passed": result.builds_passed,
                    "builds_total": result.builds_total,
                    "collection_errors": result.collection_errors,
                    "repository_mutations": result.repository_mutations,
                    "boundary_signals": result.boundary_signals,
                }
            )

    update_run_status(root, run_id, RunStatus.EVALUATED)
    return {
        "ok": True,
        "run_id": run_id,
        "collected": collected,
        **attestation_block(
            aggregate_attestations(attestations),
            aggregate_boundary_signals(signals),
        ),
    }


def _repo_root(value: str) -> Path | None:
    return Path(value) if value else None


def _preflight(runner: CommandRunner) -> str | None:
    preflight = getattr(runner, "preflight", None)
    if preflight is None:
        return None
    try:
        preflight()
    except SandboxUnavailable as exc:
        return f"sandbox_unavailable: {exc}"
    return None


def _collect_attempt(
    run: Any,
    attempt: Any,
    executor: GitExecutor,
    runner: CommandRunner,
    sandbox_error: str | None = None,
) -> AttemptResult:
    errors: list[str] = []
    before: dict[str, str] | None = None
    files: list[str] = []
    snapshot: dict[str, Any] = {
        "files_changed": [],
        "untracked_files": [],
        "lines_added": 0,
        "lines_deleted": 0,
    }
    try:
        snapshot = executor.snapshot(attempt.baseline_commit)
        before, files = executor.state()
    except EvaluationEngineError as exc:
        errors.append(str(exc))

    raw_paths = [str(path) for path in snapshot["files_changed"]]
    sensitive_raw = [path for path in raw_paths if _is_sensitive(path)]
    visible_paths = [path for path in raw_paths if not _is_sensitive(path)]
    untracked_visible = [
        path for path in snapshot.get("untracked_files", []) if not _is_sensitive(path)
    ]
    ignored_visible = [
        path for path in snapshot.get("ignored_files", []) if not _is_sensitive(path)
    ]

    blocked_reason = sandbox_error
    if blocked_reason is None and before is None:
        blocked_reason = "repository_state_unavailable"
    if blocked_reason and (run.required_tests or run.required_builds):
        errors.append(blocked_reason)

    worktree = Path(attempt.worktree_path)
    test_results = [
        _run_validation(command, worktree, files, runner, blocked_reason, errors).to_dict()
        for command in run.required_tests
    ]
    build_results = [
        _run_validation(command, worktree, files, runner, blocked_reason, errors).to_dict()
        for command in run.required_builds
    ]

    mutations, after = _detect_mutations(executor, before, errors)
    history_changed = bool(HISTORY_MUTATIONS.intersection(mutations))
    history = _history_delta(executor, before, after) if history_changed else None
    state_verified = before is not None and after is not None
    command_results = [*test_results, *build_results]
    attestations = _build_attestations(
        command_results=command_results,
        runner=runner,
        state_verified=state_verified,
        mutations=mutations,
        sensitive_found=bool(sensitive_raw),
        history=history,
    )
    boundary_signals: dict[str, bool | None] = {
        "sensitive_path_changed": bool(sensitive_raw) if before is not None else None,
        "repository_history_changed": history_changed if state_verified else None,
    }

    tests_passed = sum(bool(result["passed"]) for result in test_results)
    builds_passed = sum(bool(result["passed"]) for result in build_results)
    builds_total = len(build_results)

    return AttemptResult(
        attempt_id=attempt.attempt_id,
        run_id=run.run_id,
        model_provider=attempt.model_provider,
        model_name=attempt.model_name,
        files_changed=visible_paths,
        lines_added=int(snapshot["lines_added"]),
        lines_deleted=int(snapshot["lines_deleted"]),
        untracked_files=untracked_visible,
        scope_violations=_scope_violations(visible_paths, run.allowed_paths),
        prohibited_violations=_prohibited_violations(
            sorted({*visible_paths, *ignored_visible}), run.prohibited_paths
        ),
        sensitive_paths_found=[_redact_sensitive_path(path) for path in sensitive_raw],
        test_results=test_results,
        build_results=build_results,
        tests_passed=tests_passed,
        tests_total=len(test_results),
        builds_passed=builds_passed,
        builds_total=builds_total,
        build_passed=(builds_passed == builds_total) if builds_total else None,
        collection_errors=errors,
        attestations=attestations,
        repository_mutations=mutations,
        boundary_signals=boundary_signals,
    )


def _not_executed(command: Sequence[str], reason: str) -> CommandResult:
    return CommandResult(
        argv=list(command),
        passed=False,
        returncode=126,
        duration_seconds=0.0,
        summary=f"not_executed: {reason}"[:2000],
    )


def _run_validation(
    command: Sequence[str],
    worktree: Path,
    files: list[str],
    runner: CommandRunner,
    blocked_reason: str | None,
    errors: list[str],
) -> CommandResult:
    if blocked_reason:
        return _not_executed(command, blocked_reason)
    workspace: Path | None = None
    try:
        workspace = prepare_workspace(worktree, files, _is_sensitive)
        return runner.run(command, workspace)
    except (SandboxUnavailable, OSError, subprocess.SubprocessError) as exc:
        reason = f"sandbox_unavailable: {exc}"
        if reason not in errors:
            errors.append(reason)
        return _not_executed(command, reason)
    finally:
        if workspace is not None:
            remove_workspace(workspace)


def _detect_mutations(
    executor: GitExecutor,
    before: dict[str, str] | None,
    errors: list[str],
) -> tuple[list[str], dict[str, str] | None]:
    if before is None:
        return [], None
    try:
        after, _files = executor.state()
    except EvaluationEngineError as exc:
        errors.append(str(exc))
        return ["state_after_unavailable"], None
    changed = [f"{key}_changed" for key in sorted(before) if before[key] != after.get(key)]
    return changed, after


def _history_delta(
    executor: GitExecutor,
    before: dict[str, str] | None,
    after: dict[str, str] | None,
) -> dict[str, int] | None:
    if before is None or after is None:
        return None
    try:
        return executor.history_delta(before, after)
    except (EvaluationEngineError, AttributeError, ValueError):
        return None


def _build_attestations(
    *,
    command_results: list[dict[str, Any]],
    runner: CommandRunner,
    state_verified: bool,
    mutations: list[str],
    sensitive_found: bool,
    history: dict[str, int] | None,
) -> dict[str, dict[str, str]]:
    isolated = bool(getattr(runner, "isolated", False)) and all(
        result.get("sandboxed") for result in command_results
    )
    verified = isolated and state_verified
    if not command_results:
        absent_evidence = "no validation commands ran"
    else:
        absent_evidence = "commands ran on a disposable copy with no network or host access"

    items: dict[str, dict[str, str]] = {}
    for key in ATTESTATION_KEYS:
        if not verified:
            status = AttestationStatus.UNVERIFIED
            evidence = "isolation or repository state could not be established"
        elif mutations:
            status = AttestationStatus.UNVERIFIED
            evidence = "repository changed during validation"
        else:
            status = AttestationStatus.VERIFIED_ABSENT
            evidence = absent_evidence
        items[key] = {"status": status.value, "evidence": evidence}

    if history and history["commits"] > 0:
        items["git_commit_performed"] = {
            "status": AttestationStatus.OBSERVED.value,
            "evidence": f"{history['commits']} new commit(s) reachable from changed refs",
        }
    if history and history["merges"] > 0:
        items["git_merge_performed"] = {
            "status": AttestationStatus.OBSERVED.value,
            "evidence": f"{history['merges']} new merge commit(s) reachable from changed refs",
        }
    if sensitive_found:
        items["secrets_written"] = {
            "status": AttestationStatus.UNVERIFIED.value,
            "evidence": "a sensitive path changed; its contents were not inspected",
        }
    return items


class SubprocessGitExecutor:
    """Compare real files with the baseline commit, ignoring attempt-controlled Git state."""

    def __init__(self, worktree: Path, repo_root: Path | None = None) -> None:
        self.worktree = worktree.resolve()
        self.repo_root = repo_root.resolve() if repo_root else None
        self._baseline: str | None = None

    def snapshot(self, baseline_sha: str) -> dict[str, Any]:
        if not self.worktree.is_dir():
            raise EvaluationEngineError(f"worktree_not_found: {self.worktree}")
        self._baseline = baseline_sha
        try:
            with tempfile.TemporaryDirectory(prefix="crucible-inventory-") as temporary:
                scratch = Path(temporary)
                inventory = self._inventory(baseline_sha, scratch)
                changed, added, deleted = self._changes(baseline_sha, inventory, scratch)
        except OSError as exc:
            raise EvaluationEngineError(f"worktree_unreadable: {exc}") from exc

        indexed = self._bytes(["ls-files", "--cached", "-z"], "git_index_failed")
        cached = {os.fsdecode(path) for path in indexed.split(b"\0") if path}
        untracked = [path for path in inventory["new"] if path not in cached]
        return {
            "files_changed": sorted({_display_path(path) for path in changed}),
            "untracked_files": sorted({_display_path(path) for path in untracked}),
            "ignored_files": sorted({_display_path(path) for path in inventory["ignored"]}),
            "lines_added": added,
            "lines_deleted": deleted,
        }

    def state(self) -> tuple[dict[str, str], list[str]]:
        """Fingerprint HEAD, refs, status and real file contents without storing raw paths."""

        if self._baseline is None:
            raise EvaluationEngineError("snapshot_required")
        head = self._checked(["rev-parse", "HEAD"], "git_head_failed")
        refs = self._checked(
            ["for-each-ref", "--format=%(objectname) %(refname)"], "git_refs_failed"
        )
        status = self._checked(
            ["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            "git_status_failed",
        )
        try:
            with tempfile.TemporaryDirectory(prefix="crucible-inventory-") as temporary:
                files = self._inventory(self._baseline, Path(temporary))["live"]
            content = _content_digest(self.worktree, files)
        except OSError as exc:
            raise EvaluationEngineError(f"worktree_unreadable: {exc}") from exc
        return (
            {
                "head": head.strip(),
                "refs": refs,
                "status": _digest(status),
                "content": content,
            },
            files,
        )

    def _inventory(self, baseline: str, scratch: Path) -> dict[str, Any]:
        listing = self._bytes(
            ["ls-tree", "-r", "-z", "--full-tree", baseline], "git_tree_failed"
        )
        tracked = parse_tree(listing)
        gitlinks = {path for path, (mode, _oid) in tracked.items() if mode == GITLINK_MODE}
        found = walk_worktree(self.worktree, gitlinks)
        new = sorted(set(found) - set(tracked))
        ignored = self._baseline_ignored(tracked, new, scratch)
        live_new = [path for path in new if path not in ignored]
        return {
            "tracked": tracked,
            "found": found,
            "new": live_new,
            "ignored": sorted(ignored),
            "live": sorted({*(set(found) & set(tracked)), *live_new}),
        }

    def _baseline_ignored(
        self,
        tracked: dict[str, tuple[str, str]],
        candidates: list[str],
        scratch: Path,
    ) -> set[str]:
        """Apply only the baseline's .gitignore files, which the attempt cannot edit."""

        rules = {
            path: oid
            for path, (mode, oid) in tracked.items()
            if PurePosixPath(path).name == ".gitignore"
            and mode in {REGULAR_MODE, EXECUTABLE_MODE}
        }
        eligible = [path for path in candidates if ".git" not in PurePosixPath(path).parts]
        if not rules or not eligible:
            return set()

        init = self._scratch_git(scratch, ["init", "-q", "ignore"])
        if init.returncode != 0:
            raise EvaluationEngineError("git_ignore_repo_failed")
        root = scratch / "ignore"
        for path, oid in rules.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self._bytes(["cat-file", "blob", oid], "git_ignore_read_failed"))
        payload = b"".join(os.fsencode(path) + b"\0" for path in eligible)
        checked = self._scratch_git(
            scratch,
            ["check-ignore", "-z", "--stdin", "--no-index"],
            directory="ignore",
            input_bytes=payload,
        )
        if checked.returncode not in {0, 1}:
            raise EvaluationEngineError("git_ignore_check_failed")
        return {os.fsdecode(path) for path in checked.stdout.split(b"\0") if path}

    def _changes(
        self,
        baseline: str,
        inventory: dict[str, Any],
        scratch: Path,
    ) -> tuple[list[str], int, int]:
        tracked = inventory["tracked"]
        found = inventory["found"]
        algorithm = self._bytes(
            ["rev-parse", "--show-object-format"], "git_object_format_failed"
        ).decode("ascii").strip()
        null_oid = "0" * hashlib.new(algorithm).digest_size * 2
        objects = scratch / "objects"
        objects.mkdir()
        env = scratch_index_env(self.worktree, self.repo_root)

        changed: list[str] = []
        removals: list[bytes] = []
        additions: list[bytes] = []
        copied_bytes = 0
        for path, (_mode, _oid) in tracked.items():
            if path not in found:
                changed.append(path)
                removals.append(f"0 {null_oid}\t".encode() + os.fsencode(path) + b"\0")
        for path in inventory["live"]:
            mode = found[path]
            previous = tracked.get(path)
            if mode == GITLINK_MODE:
                if previous is None or previous[0] != GITLINK_MODE:
                    changed.append(path)
                continue
            if mode == SPECIAL_MODE:
                changed.append(path)
                if previous is not None:
                    removals.append(f"0 {null_oid}\t".encode() + os.fsencode(path) + b"\0")
                continue
            full = self.worktree / path
            if previous == (mode, blob_id(full, mode, algorithm)):
                continue
            changed.append(path)
            copied_bytes += full.lstat().st_size
            if copied_bytes > MAX_WORKSPACE_BYTES:
                raise EvaluationEngineError("changed_files_too_large")
            oid = write_loose_blob(objects, full, mode, algorithm)
            additions.append(f"{mode} {oid}\t".encode() + os.fsencode(path) + b"\0")

        if not changed:
            return [], 0, 0
        self._bytes(["read-tree", baseline], "git_index_failed", scratch=scratch, env=env)
        if removals or additions:
            self._bytes(
                ["update-index", "-z", "--index-info"],
                "git_index_failed",
                scratch=scratch,
                env=env,
                input_bytes=b"".join([*removals, *additions]),
            )
        numstat = self._bytes(
            [
                "diff-index",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--numstat",
                "-z",
                baseline,
            ],
            "git_diff_failed",
            scratch=scratch,
            env=env,
        )
        lines_added = 0
        lines_deleted = 0
        for record in numstat.split(b"\0"):
            parts = record.split(b"\t", 2)
            if len(parts) != 3:
                continue
            if parts[0].isdigit():
                lines_added += int(parts[0])
            if parts[1].isdigit():
                lines_deleted += int(parts[1])
        return changed, lines_added, lines_deleted

    def _bytes(
        self,
        args: list[str],
        error: str,
        *,
        scratch: Path | None = None,
        env: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> bytes:
        try:
            completed = run_git_bytes(
                self.worktree,
                self.repo_root,
                args,
                timeout=120,
                scratch=scratch,
                env=env,
                input_bytes=input_bytes,
            )
        except SandboxUnavailable as exc:
            raise EvaluationEngineError(f"sandbox_unavailable: {exc}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvaluationEngineError(f"git_unavailable: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise EvaluationEngineError(f"{error}: {detail}")
        return completed.stdout

    def _scratch_git(
        self,
        scratch: Path,
        args: list[str],
        *,
        directory: str = ".",
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return run_scratch_git(
                scratch,
                args,
                timeout=60,
                directory=directory,
                input_bytes=input_bytes,
            )
        except SandboxUnavailable as exc:
            raise EvaluationEngineError(f"sandbox_unavailable: {exc}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvaluationEngineError(f"git_unavailable: {exc}") from exc

    def history_delta(self, before: dict[str, str], after: dict[str, str]) -> dict[str, int]:
        """Count commits and merges that only the post-validation refs can reach."""

        known = _ref_tips(before)
        new_tips = sorted(_ref_tips(after) - known)
        if not new_tips:
            return {"commits": 0, "merges": 0}
        selection = [*new_tips, "--not", *sorted(known)]
        commits = self._checked(["rev-list", "--count", *selection], "git_history_failed")
        merges = self._checked(
            ["rev-list", "--count", "--merges", *selection], "git_history_failed"
        )
        return {"commits": int(commits.strip()), "merges": int(merges.strip())}

    def _checked(self, args: list[str], error: str) -> str:
        completed = self._git(args, timeout=60)
        if completed.returncode != 0:
            raise EvaluationEngineError(f"{error}: {completed.stderr.strip()[:300]}")
        return completed.stdout

    def _git(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        try:
            return run_sandboxed_git(self.worktree, self.repo_root, args, timeout=timeout)
        except SandboxUnavailable as exc:
            raise EvaluationEngineError(f"sandbox_unavailable: {exc}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvaluationEngineError(f"git_unavailable: {exc}") from exc


def _display_path(path: str) -> str:
    """Make any filesystem path safe to store in UTF-8 JSON."""

    return path.encode("utf-8", errors="backslashreplace").decode("utf-8")


def _ref_tips(state: dict[str, str]) -> set[str]:
    tips = {line.split(" ", 1)[0] for line in state["refs"].splitlines() if line}
    tips.add(state["head"])
    return tips


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()


def _content_digest(worktree: Path, files: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in files:
        digest.update(relative.encode("utf-8", errors="surrogateescape") + b"\0")
        path = worktree / relative
        try:
            info = path.lstat()
            digest.update(f"{stat.S_IFMT(info.st_mode)}:{stat.S_IMODE(info.st_mode)}\0".encode())
            if stat.S_ISLNK(info.st_mode):
                digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            elif stat.S_ISREG(info.st_mode):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
        except OSError as exc:
            digest.update(f"unreadable:{exc.errno}".encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _normalize_git_path(value: str) -> str:
    return value.replace("\\", "/").strip().strip("/")


def _is_sensitive(path: str) -> bool:
    lower = f"/{path.lower()}"
    return any(pattern in lower for pattern in SENSITIVE_PATH_PATTERNS)


def _redact_sensitive_path(path: str) -> str:
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]
    return f"<sensitive-path:{digest}>"


def _scope_violations(paths: list[str], allowed: list[str]) -> list[str]:
    if not allowed:
        return []
    return [path for path in paths if not any(_is_under(path, scope) for scope in allowed)]


def _prohibited_violations(paths: list[str], prohibited: list[str]) -> list[str]:
    return [
        path for path in paths if any(_is_under(path, scope) for scope in prohibited)
    ]


def _is_under(path: str, scope: str) -> bool:
    target = PurePosixPath(path)
    root = PurePosixPath(scope)
    return target == root or root in target.parents
