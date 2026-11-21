"""Regressions for the false no-side-effects attestation and host execution."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from crucible import (
    collect_run_results,
    compare_model_results,
    create_harness_run,
    record_harness_closeout,
    register_model_attempt,
)
from crucible.sandbox import BubblewrapCommandRunner, SandboxUnavailable
from crucible.schemas import ATTESTATION_KEYS, CommandResult


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for args in (
        ["init"],
        ["config", "user.email", "test@example.com"],
        ["config", "user.name", "Test"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
    return root


@pytest.fixture
def runs_root(tmp_path: Path) -> Path:
    return tmp_path / "runs"


def run_attempt(repo: Path, runs_root: Path, command: list[str], **collect_kwargs):
    create_harness_run(
        task_summary="Isolation regression",
        baseline_ref="HEAD",
        repo_root=repo,
        runs_root=runs_root,
        run_id="run-1",
        required_tests=[command],
    )
    register_model_attempt(
        run_id="run-1",
        model_provider="local",
        model_name="probe",
        ide_host="pytest",
        worktree_path=repo,
        attempt_id="probe-1",
        runs_root=runs_root,
    )
    collected = collect_run_results(run_id="run-1", runs_root=runs_root, **collect_kwargs)
    payload = json.loads(
        (runs_root / "run-1" / "attempts" / "probe-1_result.json").read_text(encoding="utf-8")
    )
    return collected, payload


def commit_count(repo: Path) -> int:
    output = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=repo, text=True)
    return int(output)


def python_check(source: str) -> list[str]:
    return ["python", "-c", source]


def test_required_test_cannot_commit_to_real_repository(repo: Path, runs_root: Path) -> None:
    command = [
        "git",
        "-c",
        "user.name=probe",
        "-c",
        "user.email=probe@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "made-by-required-test",
    ]
    collected, payload = run_attempt(repo, runs_root, command)
    assert commit_count(repo) == 1
    assert payload["tests_passed"] == 0
    assert payload["repository_mutations"] == []
    assert collected["attestations"]["git_commit_performed"]["status"] == "verified_absent"


def test_required_test_cannot_modify_real_worktree(repo: Path, runs_root: Path) -> None:
    source = "from pathlib import Path; Path('README.md').write_text('tampered')"
    _collected, payload = run_attempt(repo, runs_root, python_check(source))
    assert payload["tests_passed"] == 1
    assert (repo / "README.md").read_text(encoding="utf-8") == "baseline\n"
    assert payload["repository_mutations"] == []


def test_required_test_has_no_network(repo: Path, runs_root: Path) -> None:
    source = (
        "import socket\n"
        "s = socket.socket(); s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 53))\n"
        "except OSError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(9)\n"
    )
    _collected, payload = run_attempt(repo, runs_root, python_check(source))
    assert payload["tests_passed"] == 1


def test_required_test_cannot_reach_home_or_escalate(repo: Path, runs_root: Path) -> None:
    host_home = str(Path.home())
    source = (
        "import os, pathlib\n"
        f"assert not os.path.exists({host_home!r})\n"
        "assert os.environ['HOME'] == '/tmp/home'\n"
        "status = pathlib.Path('/proc/self/status').read_text()\n"
        "assert any(l.split() == ['NoNewPrivs:', '1'] for l in status.splitlines())\n"
    )
    _collected, payload = run_attempt(repo, runs_root, python_check(source))
    assert payload["tests_passed"] == 1, payload["test_results"][0]["summary"]


def test_sensitive_files_are_not_copied_into_sandbox(repo: Path, runs_root: Path) -> None:
    (repo / ".env").write_text("SECRET=do-not-read\n", encoding="utf-8")
    source = "import os; raise SystemExit(0 if not os.path.exists('.env') else 9)"
    _collected, payload = run_attempt(repo, runs_root, python_check(source))
    assert payload["tests_passed"] == 1
    assert "do-not-read" not in json.dumps(payload)


def test_hardlinked_file_is_refused(repo: Path, runs_root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-secret"
    outside.write_text("do-not-read\n", encoding="utf-8")
    (repo / "notes.txt").hardlink_to(outside)
    collected, payload = run_attempt(repo, runs_root, ["cat", "notes.txt"])
    assert payload["tests_passed"] == 0
    assert "do-not-read" not in json.dumps(payload)
    assert collected["attestations"]["secrets_written"]["status"] == "unverified"


@pytest.mark.parametrize("vector", ["fsmonitor", "clean_filter"])
def test_malicious_git_config_does_not_run_on_host(
    repo: Path, runs_root: Path, tmp_path: Path, vector: str
) -> None:
    marker = tmp_path / "executed"
    script = tmp_path / "payload.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n", encoding="utf-8")
    script.chmod(0o755)
    if vector == "fsmonitor":
        subprocess.run(["git", "config", "core.fsmonitor", str(script)], cwd=repo, check=True)
    else:
        subprocess.run(["git", "config", "filter.evil.clean", str(script)], cwd=repo, check=True)
        (repo / ".gitattributes").write_text("*.md filter=evil\n", encoding="utf-8")
        (repo / "README.md").write_text("changed\n", encoding="utf-8")
    run_attempt(repo, runs_root, python_check("pass"))
    assert not marker.exists()


def test_missing_sandbox_fails_closed(
    repo: Path, runs_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran-on-host"
    monkeypatch.setattr("crucible.sandbox.shutil.which", lambda _name: None)
    collected, payload = run_attempt(repo, runs_root, ["touch", str(marker)])
    assert not marker.exists()
    assert payload["test_results"][0]["returncode"] == 126
    assert payload["test_results"][0]["sandboxed"] is False
    assert all(
        collected["attestations"][key]["status"] == "unverified" for key in ATTESTATION_KEYS
    )
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_attempt_id"] is None
    assert "boundary_attestation_unverified" in comparison["blockers"]


def test_failed_preflight_never_runs_command(
    repo: Path, runs_root: Path, tmp_path: Path
) -> None:
    class BrokenSandbox(BubblewrapCommandRunner):
        def preflight(self) -> None:
            raise SandboxUnavailable("simulated")

        def run(self, argv, cwd):  # pragma: no cover
            raise AssertionError("command must not run")

    _collected, payload = run_attempt(
        repo, runs_root, ["true"], command_runner=BrokenSandbox()
    )
    assert payload["test_results"][0]["returncode"] == 126
    assert any("sandbox_unavailable" in error for error in payload["collection_errors"])


def test_repository_commit_during_validation_is_observed_and_blocks(
    repo: Path, runs_root: Path
) -> None:
    class EscapingRunner:
        isolated = True

        def run(self, argv, cwd):
            subprocess.run(
                ["git", "commit", "--allow-empty", "-qm", "escaped"], cwd=repo, check=True
            )
            return CommandResult(list(argv), True, 0, 0.0, "", sandboxed=True)

    collected, payload = run_attempt(repo, runs_root, ["true"], command_runner=EscapingRunner())
    assert {"head_changed", "refs_changed"} <= set(payload["repository_mutations"])
    assert collected["attestations"]["git_commit_performed"]["status"] == "observed"
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_attempt_id"] is None
    assert "repository_mutated_during_validation" in comparison["blockers"]
    closed = record_harness_closeout(run_id="run-1", runs_root=runs_root)
    assert closed["closeout"]["validation"]["boundary_checks_passed"] is False
    assert closed["attestations"]["git_commit_performed"]["status"] == "observed"


def test_unisolated_runner_is_never_verified(repo: Path, runs_root: Path) -> None:
    class HostRunner:
        def run(self, argv, cwd):
            return CommandResult(list(argv), True, 0, 0.0, "")

    collected, _payload = run_attempt(repo, runs_root, ["true"], command_runner=HostRunner())
    assert all(
        collected["attestations"][key]["status"] == "unverified" for key in ATTESTATION_KEYS
    )


def test_clean_attempt_is_verified_only_for_validation_scope(
    repo: Path, runs_root: Path
) -> None:
    collected, _payload = run_attempt(repo, runs_root, python_check("print('ok')"))
    assert collected["attestation_scope"] == "validation_commands"
    assert collected["agent_session_covered"] is False
    assert all(
        collected["attestations"][key]["status"] == "verified_absent"
        for key in ATTESTATION_KEYS
    )
    assert "git_commit_performed" not in collected
