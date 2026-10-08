from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from crucible import (
    CloseoutError,
    collect_run_results,
    compare_model_results,
    create_harness_run,
    get_harness_status,
    record_harness_closeout,
    register_model_attempt,
)
from crucible.schemas import NO_SIDE_EFFECTS


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=root,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=root,
        check=True,
    )
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=root, check=True)
    return root


@pytest.fixture
def runs_root(tmp_path: Path) -> Path:
    return tmp_path / "runs"


def create_run(repo: Path, runs_root: Path, **kwargs):
    return create_harness_run(
        task_summary="Evaluate agent implementation",
        baseline_ref="HEAD",
        repo_root=repo,
        runs_root=runs_root,
        run_id="run-1",
        **kwargs,
    )


def test_create_is_idempotent(repo: Path, runs_root: Path) -> None:
    first = create_run(repo, runs_root)
    second = create_run(repo, runs_root)
    assert first["ok"] is True
    assert second["already_exists"] is True
    manifest = json.loads(
        (runs_root / "run-1" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == 2
    assert manifest["repo_root"] == str(repo.resolve())


def test_dry_run_has_no_artifacts(repo: Path, runs_root: Path) -> None:
    result = create_harness_run(
        task_summary="Dry run",
        baseline_ref="HEAD",
        repo_root=repo,
        runs_root=runs_root,
        run_id="dry-run",
        dry_run=True,
    )
    assert result["dry_run"] is True
    assert not runs_root.exists()


def test_full_workflow_collects_uncommitted_and_untracked(
    repo: Path, runs_root: Path
) -> None:
    created = create_run(
        repo,
        runs_root,
        allowed_paths=["src", "tests"],
        prohibited_paths=["deploy"],
        required_tests=[["python", "-c", "print('ok')"]],
        required_builds=[["python", "-c", "print('build')"]],
    )
    (repo / "src").mkdir()
    (repo / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_main.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    attempt = register_model_attempt(
        run_id=created["run_id"],
        model_provider="codex",
        model_name="coding-model",
        ide_host="Codex",
        worktree_path=repo,
        attempt_id="codex-1",
        runs_root=runs_root,
    )
    assert attempt["ok"] is True

    collected = collect_run_results(run_id="run-1", runs_root=runs_root)
    assert collected["collected"][0]["tests_passed"] == 1
    result_path = runs_root / "run-1" / "attempts" / "codex-1_result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert "src/main.py" in payload["untracked_files"]
    assert payload["build_passed"] is True
    assert payload["scope_violations"] == []

    compared = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert compared["recommended_attempt_id"] == "codex-1"
    assert compared["blockers"] == []

    closed = record_harness_closeout(
        run_id="run-1",
        operator_decision="accepted",
        runs_root=runs_root,
    )
    assert closed["external_write_performed"] is False
    assert closed["closeout"]["operator_decision"] == "accepted"
    assert get_harness_status(run_id="run-1", runs_root=runs_root)["run"]["status"] == "closed"
    for key, expected in NO_SIDE_EFFECTS.items():
        assert closed["closeout"][key] is expected


def test_segment_safe_scope_matching(repo: Path, runs_root: Path) -> None:
    created = create_run(repo, runs_root, allowed_paths=["src/foo"])
    (repo / "src").mkdir()
    (repo / "src" / "foobar.py").write_text("x = 1\n", encoding="utf-8")
    register_model_attempt(
        run_id=created["run_id"],
        model_provider="claude",
        model_name="sonnet",
        ide_host="Claude Code",
        worktree_path=repo,
        attempt_id="claude-1",
        runs_root=runs_root,
    )
    collect_run_results(run_id="run-1", runs_root=runs_root)
    payload = json.loads(
        (runs_root / "run-1" / "attempts" / "claude-1_result.json").read_text()
    )
    assert payload["scope_violations"] == ["src/foobar.py"]


def test_sensitive_paths_are_redacted_and_block_recommendation(
    repo: Path, runs_root: Path
) -> None:
    created = create_run(repo, runs_root)
    (repo / ".env").write_text("SECRET=do-not-record\n", encoding="utf-8")
    register_model_attempt(
        run_id=created["run_id"],
        model_provider="cursor",
        model_name="composer",
        ide_host="Cursor",
        worktree_path=repo,
        attempt_id="cursor-1",
        runs_root=runs_root,
    )
    collect_run_results(run_id="run-1", runs_root=runs_root)
    payload = json.loads(
        (runs_root / "run-1" / "attempts" / "cursor-1_result.json").read_text()
    )
    assert payload["sensitive_paths_found"][0].startswith("<sensitive-path:")
    serialized = json.dumps(payload)
    assert "SECRET=do-not-record" not in serialized
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_attempt_id"] is None
    assert "sensitive_paths_in_diff" in comparison["blockers"]


def test_failed_test_blocks_recommendation(repo: Path, runs_root: Path) -> None:
    created = create_run(
        repo,
        runs_root,
        required_tests=[["python", "-c", "raise SystemExit(2)"]],
    )
    register_model_attempt(
        run_id=created["run_id"],
        model_provider="gemini",
        model_name="model",
        ide_host="CLI",
        worktree_path=repo,
        attempt_id="gemini-1",
        runs_root=runs_root,
    )
    collect_run_results(run_id="run-1", runs_root=runs_root)
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_provider"] is None
    assert "required_tests_failed" in comparison["blockers"]


def test_closeout_rejects_invalid_decision(repo: Path, runs_root: Path) -> None:
    create_run(repo, runs_root)
    with pytest.raises(CloseoutError, match="invalid_operator_decision"):
        record_harness_closeout(
            run_id="run-1",
            operator_decision="ship_it",
            runs_root=runs_root,
        )
