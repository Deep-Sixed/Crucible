"""Harness run and attempt lifecycle."""

from __future__ import annotations

import datetime as dt
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any, Sequence

from .artifact_store import (
    ArtifactStoreError,
    default_runs_root,
    list_attempt_results,
    list_attempts,
    list_run_ids,
    load_latest_comparison,
    load_manifest,
    run_dir,
    run_lock,
    validate_id,
    write_attempt,
    write_baseline,
    write_manifest,
)
from .schemas import HarnessRun, ModelAttempt, RunStatus, unverified_attestations, utc_now

PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class RunManagerError(ValueError):
    pass


def create_harness_run(
    *,
    task_summary: str,
    baseline_ref: str,
    repo_root: Path | str,
    workspace: str = "EVECOR",
    allowed_paths: Sequence[str] | None = None,
    prohibited_paths: Sequence[str] | None = None,
    required_tests: Sequence[Sequence[str] | str] | None = None,
    required_builds: Sequence[Sequence[str] | str] | None = None,
    run_id: str | None = None,
    runs_root: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create a run bound to an immutable Git baseline."""

    summary = _required_text(task_summary, "task_summary", max_length=1000)
    repo = Path(repo_root).resolve()
    _validate_git_repo(repo)
    resolved_sha = _resolve_ref(baseline_ref, repo)
    root = (runs_root or default_runs_root()).resolve()
    rid = run_id or _generate_run_id()
    try:
        validate_id(rid, "run_id")
    except ArtifactStoreError as exc:
        raise RunManagerError(str(exc)) from exc

    run = HarnessRun(
        run_id=rid,
        workspace=_required_text(workspace, "workspace", max_length=128),
        task_summary=summary,
        repo_root=str(repo),
        baseline_commit=resolved_sha,
        baseline_ref=_required_text(baseline_ref, "baseline_ref", max_length=256),
        allowed_paths=_normalize_scopes(allowed_paths or []),
        prohibited_paths=_normalize_scopes(prohibited_paths or []),
        required_tests=_normalize_commands(required_tests or []),
        required_builds=_normalize_commands(required_builds or []),
    )
    baseline = {
        "schema_version": run.schema_version,
        "run_id": rid,
        "repo_root": str(repo),
        "baseline_ref": run.baseline_ref,
        "baseline_commit": resolved_sha,
        "resolved_at": dt.datetime.now(dt.UTC).isoformat(),
    }

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "run_id": rid,
            "baseline_commit": resolved_sha,
            "run_dir": str(run_dir(root, rid)),
            "manifest": run.to_dict(),
            **unverified_attestations(),
        }

    with run_lock(root, rid):
        manifest_path = run_dir(root, rid) / "manifest.json"
        if manifest_path.exists():
            existing = load_manifest(root, rid)
            if (
                existing.baseline_commit != resolved_sha
                or existing.repo_root != str(repo)
            ):
                raise RunManagerError(
                    f"run_already_exists_with_different_baseline: {rid}"
                )
            return {
                "ok": True,
                "already_exists": True,
                "run_id": rid,
                "baseline_commit": resolved_sha,
                "run_dir": str(run_dir(root, rid)),
                **unverified_attestations(),
            }

        written_manifest = write_manifest(run, root)
        baseline_path = write_baseline(rid, baseline, root)
        (run_dir(root, rid) / "attempts").mkdir(parents=True, exist_ok=True)
        (run_dir(root, rid) / "comparisons").mkdir(parents=True, exist_ok=True)

    return {
        "ok": True,
        "run_id": rid,
        "baseline_commit": resolved_sha,
        "run_dir": str(run_dir(root, rid)),
        "manifest_path": str(written_manifest),
        "baseline_path": str(baseline_path),
        **unverified_attestations(),
    }


def register_model_attempt(
    *,
    run_id: str,
    model_provider: str,
    model_name: str,
    ide_host: str,
    worktree_path: Path | str,
    attempt_id: str | None = None,
    runs_root: Path | None = None,
) -> dict[str, Any]:
    """Register one agent/model attempt against an existing run."""

    root = (runs_root or default_runs_root()).resolve()
    provider = _validate_provider(model_provider)
    worktree = Path(worktree_path).resolve()
    _validate_git_repo(worktree)

    with run_lock(root, run_id):
        run = load_manifest(root, run_id)
        _verify_commit_exists(worktree, run.baseline_commit)
        aid = attempt_id or f"{provider}-{uuid.uuid4().hex[:8]}"
        try:
            validate_id(aid, "attempt_id")
        except ArtifactStoreError as exc:
            raise RunManagerError(str(exc)) from exc

        path = run_dir(root, run_id) / "attempts" / f"{aid}.json"
        if path.exists():
            existing = next(
                (a for a in list_attempts(root, run_id) if a.attempt_id == aid),
                None,
            )
            if existing and existing.worktree_path == str(worktree):
                return {
                    "ok": True,
                    "already_exists": True,
                    "run_id": run_id,
                    "attempt_id": aid,
                    "attempt_path": str(path),
                    **unverified_attestations(),
                }
            raise RunManagerError(f"attempt_already_exists: {aid}")

        attempt = ModelAttempt(
            attempt_id=aid,
            run_id=run_id,
            model_provider=provider,
            model_name=_required_text(model_name, "model_name", max_length=256),
            ide_host=_required_text(ide_host, "ide_host", max_length=128),
            worktree_path=str(worktree),
            baseline_commit=run.baseline_commit,
        )
        written = write_attempt(attempt, root)

    return {
        "ok": True,
        "run_id": run_id,
        "attempt_id": aid,
        "attempt_path": str(written),
        **unverified_attestations(),
    }


def get_harness_status(
    *,
    run_id: str | None = None,
    runs_root: Path | None = None,
) -> dict[str, Any]:
    root = (runs_root or default_runs_root()).resolve()
    if run_id:
        run = load_manifest(root, run_id)
        attempts = list_attempts(root, run_id)
        results = list_attempt_results(root, run_id)
        comparison = load_latest_comparison(root, run_id)
        return {
            "ok": True,
            "run": run.to_dict(),
            "attempt_count": len(attempts),
            "result_count": len(results),
            "latest_comparison": comparison.to_dict() if comparison else None,
            "blockers": _collect_blockers(root, run_id),
            **unverified_attestations(),
        }

    runs: list[dict[str, Any]] = []
    for rid in list_run_ids(root):
        run = load_manifest(root, rid)
        runs.append(
            {
                "run_id": rid,
                "status": run.status,
                "task_summary": run.task_summary[:120],
                "baseline_commit": run.baseline_commit[:12],
                "attempt_count": len(list_attempts(root, rid)),
                "result_count": len(list_attempt_results(root, rid)),
                "blockers": _collect_blockers(root, rid),
            }
        )
    return {"ok": True, "runs": runs, **unverified_attestations()}


def update_run_status(
    runs_root: Path,
    run_id: str,
    status: RunStatus | str,
) -> HarnessRun:
    with run_lock(runs_root, run_id):
        run = load_manifest(runs_root, run_id)
        run.status = str(status)
        run.updated_at = utc_now()
        write_manifest(run, runs_root)
        return run


def _collect_blockers(runs_root: Path, run_id: str) -> list[str]:
    blockers: list[str] = []
    if not list_attempts(runs_root, run_id):
        blockers.append("no_attempts_registered")
    if not list_attempt_results(runs_root, run_id):
        blockers.append("results_not_collected")
    if load_latest_comparison(runs_root, run_id) is None:
        blockers.append("no_comparison_generated")
    if not (run_dir(runs_root, run_id) / "closeout.json").exists():
        blockers.append("closeout_pending")
    return blockers


def _generate_run_id() -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d")
    return f"crucible-run-{stamp}-{uuid.uuid4().hex[:8]}"


def _validate_provider(value: str) -> str:
    provider = value.strip().lower()
    if not PROVIDER_RE.fullmatch(provider):
        raise RunManagerError(f"invalid_model_provider: {value!r}")
    return provider


def _required_text(value: str, field: str, *, max_length: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise RunManagerError(f"{field}_required")
    if len(normalized) > max_length:
        raise RunManagerError(f"{field}_too_long")
    return normalized


def _normalize_commands(
    commands: Sequence[Sequence[str] | str],
) -> list[list[str]]:
    import shlex

    normalized: list[list[str]] = []
    for command in commands:
        argv = shlex.split(command) if isinstance(command, str) else [str(x) for x in command]
        if not argv or any("\x00" in part for part in argv):
            raise RunManagerError("invalid_command")
        normalized.append(argv)
    return normalized


def _normalize_scopes(paths: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for value in paths:
        path = value.replace("\\", "/").strip().strip("/")
        if not path or path == "." or path.startswith("../") or "/../" in f"/{path}/":
            raise RunManagerError(f"invalid_scope_path: {value!r}")
        normalized.append(path)
    return sorted(set(normalized))


def _validate_git_repo(path: Path) -> None:
    if not path.is_dir():
        raise RunManagerError(f"repo_not_found: {path}")
    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise RunManagerError(f"not_a_git_worktree: {path}")


def _resolve_ref(ref: str, repo: Path) -> str:
    normalized = _required_text(ref, "baseline_ref", max_length=256)
    result = subprocess.run(
        ["git", "rev-parse", f"{normalized}^{{commit}}"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RunManagerError(f"invalid_baseline_ref: {normalized}")
    return result.stdout.strip().lower()


def _verify_commit_exists(worktree: Path, commit: str) -> None:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=worktree,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RunManagerError(
            f"baseline_commit_missing_from_worktree: {commit[:12]}: {worktree}"
        )
