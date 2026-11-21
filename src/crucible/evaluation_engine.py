"""Git diff and isolated command-result collection for model attempts."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, Sequence

from .artifact_store import (
    default_runs_root,
    list_attempts,
    load_manifest,
    run_lock,
    write_attempt_result,
)
from .run_manager import update_run_status
from .sandbox import (
    BubblewrapCommandRunner,
    SandboxUnavailable,
    prepare_workspace,
    remove_workspace,
    run_sandboxed_git,
)
from .schemas import (
    ATTESTATION_KEYS,
    AttemptResult,
    AttestationStatus,
    CommandResult,
    RunStatus,
    SENSITIVE_PATH_PATTERNS,
    aggregate_attestations,
    attestation_block,
)


class EvaluationEngineError(ValueError):
    pass


class GitExecutor(Protocol):
    def snapshot(self, baseline_sha: str) -> dict[str, Any]: ...

    def state(self) -> tuple[dict[str, str], list[str]]: ...


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
                }
            )

    update_run_status(root, run_id, RunStatus.EVALUATED)
    return {
        "ok": True,
        "run_id": run_id,
        "collected": collected,
        **attestation_block(aggregate_attestations(attestations)),
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

    mutations = _detect_mutations(executor, before, errors)
    command_results = [*test_results, *build_results]
    attestations = _build_attestations(
        command_results=command_results,
        runner=runner,
        state_verified=before is not None and "state_after_unavailable" not in mutations,
        mutations=mutations,
        sensitive_found=bool(sensitive_raw),
    )

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
            visible_paths, run.prohibited_paths
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
) -> list[str]:
    if before is None:
        return []
    try:
        after, _files = executor.state()
    except EvaluationEngineError as exc:
        errors.append(str(exc))
        return ["state_after_unavailable"]
    return [f"{key}_changed" for key in sorted(before) if before[key] != after.get(key)]


def _build_attestations(
    *,
    command_results: list[dict[str, Any]],
    runner: CommandRunner,
    state_verified: bool,
    mutations: list[str],
    sensitive_found: bool,
) -> dict[str, dict[str, str]]:
    isolated = bool(getattr(runner, "isolated", False)) and all(
        result.get("sandboxed") for result in command_results
    )
    verified = isolated and state_verified
    history_changed = bool({"head_changed", "refs_changed"}.intersection(mutations))
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

    if history_changed:
        items["git_commit_performed"] = {
            "status": AttestationStatus.OBSERVED.value,
            "evidence": "HEAD or refs changed during validation",
        }
    if sensitive_found:
        items["secrets_written"] = {
            "status": AttestationStatus.OBSERVED.value,
            "evidence": "attempt diff contains a sensitive path",
        }
    return items


class SubprocessGitExecutor:
    def __init__(self, worktree: Path, repo_root: Path | None = None) -> None:
        self.worktree = worktree.resolve()
        self.repo_root = repo_root.resolve() if repo_root else None

    def snapshot(self, baseline_sha: str) -> dict[str, Any]:
        if not self.worktree.is_dir():
            raise EvaluationEngineError(f"worktree_not_found: {self.worktree}")

        diff = self._git(
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--numstat",
                "-z",
                baseline_sha,
                "--",
            ],
            timeout=60,
        )
        if diff.returncode != 0:
            raise EvaluationEngineError(
                f"git_diff_failed: {diff.stderr.strip()[:300]}"
            )

        files_changed: list[str] = []
        lines_added = 0
        lines_deleted = 0
        for line in diff.stdout.split("\0"):
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            added, deleted, path = parts
            files_changed.append(_normalize_git_path(path))
            if added.isdigit():
                lines_added += int(added)
            if deleted.isdigit():
                lines_deleted += int(deleted)

        untracked = self._git(
            ["ls-files", "--others", "--exclude-standard", "-z"],
            timeout=30,
        )
        if untracked.returncode != 0:
            raise EvaluationEngineError(
                f"git_untracked_failed: {untracked.stderr.strip()[:300]}"
            )
        untracked_files = [
            _normalize_git_path(path)
            for path in untracked.stdout.split("\0")
            if path
        ]
        for relative in untracked_files:
            if relative not in files_changed:
                files_changed.append(relative)
            path = self.worktree / relative
            if path.is_file() and not path.is_symlink():
                try:
                    with path.open("rb") as handle:
                        sample = handle.read(8192)
                    if b"\0" not in sample:
                        with path.open(
                            "r", encoding="utf-8", errors="replace"
                        ) as handle:
                            lines_added += sum(1 for _ in handle)
                except OSError:
                    pass

        return {
            "files_changed": sorted(set(files_changed)),
            "untracked_files": sorted(set(untracked_files)),
            "lines_added": lines_added,
            "lines_deleted": lines_deleted,
        }

    def state(self) -> tuple[dict[str, str], list[str]]:
        """Fingerprint HEAD, refs, status and file contents without storing raw paths."""

        head = self._checked(["rev-parse", "HEAD"], "git_head_failed")
        refs = self._checked(
            ["for-each-ref", "--format=%(objectname) %(refname)"], "git_refs_failed"
        )
        status = self._checked(
            ["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            "git_status_failed",
        )
        listed = self._checked(
            ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            "git_files_failed",
        )
        files = sorted({path for path in listed.split("\0") if path})
        return (
            {
                "head": head.strip(),
                "refs": _digest(refs),
                "status": _digest(status),
                "content": _content_digest(self.worktree, files),
            },
            files,
        )

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
