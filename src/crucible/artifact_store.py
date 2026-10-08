"""Atomic, locked local artifact persistence."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterator, TypeVar

from .schemas import (
    AttemptResult,
    ComparisonResult,
    HarnessCloseout,
    HarnessRun,
    ModelAttempt,
)

T = TypeVar("T")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ArtifactStoreError(ValueError):
    pass


def component_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd()


def default_runs_root(component: Path | None = None) -> Path:
    return (component or component_root()) / "var" / "runs"


def validate_id(value: str, field: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise ArtifactStoreError(f"invalid_{field}: {value!r}")
    return value


def run_dir(runs_root: Path, run_id: str) -> Path:
    validate_id(run_id, "run_id")
    root = runs_root.resolve()
    target = (root / run_id).resolve()
    if root not in target.parents:
        raise ArtifactStoreError("run_path_escape")
    return target


@contextlib.contextmanager
def run_lock(runs_root: Path, run_id: str) -> Iterator[None]:
    directory = run_dir(runs_root, run_id)
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / ".lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return path


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ArtifactStoreError(f"artifact_not_found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactStoreError(f"artifact_invalid: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactStoreError(f"artifact_not_object: {path}")
    return value


def write_manifest(run: HarnessRun, runs_root: Path) -> Path:
    return atomic_write_json(run_dir(runs_root, run.run_id) / "manifest.json", run.to_dict())


def write_baseline(run_id: str, baseline: dict[str, Any], runs_root: Path) -> Path:
    return atomic_write_json(run_dir(runs_root, run_id) / "baseline.json", baseline)


def write_attempt(attempt: ModelAttempt, runs_root: Path) -> Path:
    validate_id(attempt.attempt_id, "attempt_id")
    return atomic_write_json(
        run_dir(runs_root, attempt.run_id) / "attempts" / f"{attempt.attempt_id}.json",
        attempt.to_dict(),
    )


def write_attempt_result(result: AttemptResult, runs_root: Path) -> Path:
    validate_id(result.attempt_id, "attempt_id")
    return atomic_write_json(
        run_dir(runs_root, result.run_id)
        / "attempts"
        / f"{result.attempt_id}_result.json",
        result.to_dict(),
    )


def write_comparison(comparison: ComparisonResult, runs_root: Path) -> Path:
    validate_id(comparison.comparison_id, "comparison_id")
    return atomic_write_json(
        run_dir(runs_root, comparison.run_id)
        / "comparisons"
        / f"{comparison.comparison_id}.json",
        comparison.to_dict(),
    )


def write_closeout(closeout: HarnessCloseout, runs_root: Path) -> Path:
    return atomic_write_json(
        run_dir(runs_root, closeout.run_id) / "closeout.json",
        closeout.to_dict(),
    )


def load_manifest(runs_root: Path, run_id: str) -> HarnessRun:
    return HarnessRun.from_dict(read_json(run_dir(runs_root, run_id) / "manifest.json"))


def load_attempt(runs_root: Path, run_id: str, attempt_id: str) -> ModelAttempt:
    validate_id(attempt_id, "attempt_id")
    return ModelAttempt.from_dict(
        read_json(run_dir(runs_root, run_id) / "attempts" / f"{attempt_id}.json")
    )


def load_attempt_result(runs_root: Path, run_id: str, attempt_id: str) -> AttemptResult:
    validate_id(attempt_id, "attempt_id")
    return AttemptResult.from_dict(
        read_json(
            run_dir(runs_root, run_id) / "attempts" / f"{attempt_id}_result.json"
        )
    )


def list_attempts(runs_root: Path, run_id: str) -> list[ModelAttempt]:
    directory = run_dir(runs_root, run_id) / "attempts"
    if not directory.exists():
        return []
    attempts: list[ModelAttempt] = []
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith("_result.json"):
            continue
        attempts.append(ModelAttempt.from_dict(read_json(path)))
    return attempts


def list_attempt_results(runs_root: Path, run_id: str) -> list[AttemptResult]:
    directory = run_dir(runs_root, run_id) / "attempts"
    if not directory.exists():
        return []
    return [
        AttemptResult.from_dict(read_json(path))
        for path in sorted(directory.glob("*_result.json"))
    ]


def list_comparisons(runs_root: Path, run_id: str) -> list[ComparisonResult]:
    directory = run_dir(runs_root, run_id) / "comparisons"
    if not directory.exists():
        return []
    return [
        ComparisonResult.from_dict(read_json(path))
        for path in sorted(directory.glob("*.json"))
    ]


def load_latest_comparison(
    runs_root: Path, run_id: str
) -> ComparisonResult | None:
    comparisons = list_comparisons(runs_root, run_id)
    return comparisons[-1] if comparisons else None


def list_run_ids(runs_root: Path) -> list[str]:
    if not runs_root.exists():
        return []
    return sorted(
        path.name
        for path in runs_root.iterdir()
        if path.is_dir() and (path / "manifest.json").exists()
    )
