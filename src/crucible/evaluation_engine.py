"""Git diff and command-result collection for model attempts."""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, Sequence

from .artifact_store import (
    default_runs_root,
    list_attempts,
    load_manifest,
    run_lock,
    write_attempt_result,
)
from .schemas import (
    AttemptResult,
    CommandResult,
    NO_SIDE_EFFECTS,
    SENSITIVE_PATH_PATTERNS,
    RunStatus,
)
from .run_manager import update_run_status


class EvaluationEngineError(ValueError):
    pass


class GitExecutor(Protocol):
    def snapshot(self, baseline_sha: str) -> dict[str, Any]: ...


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult: ...


def collect_run_results(
    *,
    run_id: str,
    runs_root: Path | None = None,
    git_executor_factory: Any | None = None,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Collect each registered attempt deterministically and fail visibly."""

    root = (runs_root or default_runs_root()).resolve()
    run = load_manifest(root, run_id)
    attempts = list_attempts(root, run_id)
    if not attempts:
        raise EvaluationEngineError("no_attempts_registered")

    collected: list[dict[str, Any]] = []
    runner = command_runner or SubprocessCommandRunner()

    with run_lock(root, run_id):
        for attempt in attempts:
            worktree = Path(attempt.worktree_path)
            executor = (
                git_executor_factory(worktree)
                if git_executor_factory
                else SubprocessGitExecutor(worktree)
            )
            result = _collect_attempt(run, attempt, executor, runner)
            path = write_attempt_result(result, root)
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
                }
            )

    update_run_status(root, run_id, RunStatus.EVALUATED)
    return {
        "ok": True,
        "run_id": run_id,
        "collected": collected,
        **NO_SIDE_EFFECTS,
    }


def _collect_attempt(
    run: Any,
    attempt: Any,
    executor: GitExecutor,
    runner: CommandRunner,
) -> AttemptResult:
    errors: list[str] = []
    try:
        snapshot = executor.snapshot(attempt.baseline_commit)
    except EvaluationEngineError as exc:
        snapshot = {
            "files_changed": [],
            "untracked_files": [],
            "lines_added": 0,
            "lines_deleted": 0,
        }
        errors.append(str(exc))

    raw_paths = [str(path) for path in snapshot["files_changed"]]
    sensitive_raw = [path for path in raw_paths if _is_sensitive(path)]
    visible_paths = [path for path in raw_paths if not _is_sensitive(path)]
    untracked_visible = [
        path for path in snapshot.get("untracked_files", []) if not _is_sensitive(path)
    ]

    test_results = [
        runner.run(command, Path(attempt.worktree_path)).to_dict()
        for command in run.required_tests
    ]
    build_results = [
        runner.run(command, Path(attempt.worktree_path)).to_dict()
        for command in run.required_builds
    ]

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
    )


class SubprocessGitExecutor:
    def __init__(self, worktree: Path) -> None:
        self.worktree = worktree.resolve()

    def snapshot(self, baseline_sha: str) -> dict[str, Any]:
        if not self.worktree.is_dir():
            raise EvaluationEngineError(f"worktree_not_found: {self.worktree}")

        diff = self._git(
            ["diff", "--numstat", "--find-renames", baseline_sha, "--"],
            timeout=60,
        )
        if diff.returncode != 0:
            raise EvaluationEngineError(
                f"git_diff_failed: {diff.stderr.strip()[:300]}"
            )

        files_changed: list[str] = []
        lines_added = 0
        lines_deleted = 0
        for line in diff.stdout.splitlines():
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
            if path.is_file():
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

    def _git(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", *args],
                cwd=self.worktree,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise EvaluationEngineError(f"git_unavailable: {exc}") from exc


class SubprocessCommandRunner:
    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult:
        if not argv:
            raise EvaluationEngineError("empty_command")
        started = time.monotonic()
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "PYTHONUNBUFFERED": "1",
        }
        try:
            completed = subprocess.run(
                list(argv),
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            duration = time.monotonic() - started
            summary = _bounded_output(completed.stdout, completed.stderr)
            return CommandResult(
                argv=list(argv),
                passed=completed.returncode == 0,
                returncode=completed.returncode,
                duration_seconds=round(duration, 3),
                summary=summary,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return CommandResult(
                argv=list(argv),
                passed=False,
                returncode=-1,
                duration_seconds=round(duration, 3),
                summary=_bounded_output(exc.stdout or "", exc.stderr or ""),
                timed_out=True,
            )
        except FileNotFoundError as exc:
            duration = time.monotonic() - started
            return CommandResult(
                argv=list(argv),
                passed=False,
                returncode=127,
                duration_seconds=round(duration, 3),
                summary=str(exc)[:500],
            )


def _bounded_output(stdout: str | bytes, stderr: str | bytes) -> str:
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    value = stdout or stderr or ""
    value = value.replace("\x00", "")
    return value[-2000:]


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
