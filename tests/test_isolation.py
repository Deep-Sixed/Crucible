"""Regressions for the false no-side-effects attestation and host execution."""

from __future__ import annotations

import ast
import json
import os
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
from crucible.run_manager import RunManagerError
from crucible.sandbox import (
    BubblewrapCommandRunner,
    ResourceLimits,
    SandboxUnavailable,
    _redact_summary,
    read_scope_limits,
)
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


def setup_attempt(
    repo: Path, runs_root: Path, command: list[str], baseline_ref: str = "HEAD"
) -> None:
    create_harness_run(
        task_summary="Isolation regression",
        baseline_ref=baseline_ref,
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


def run_attempt(
    repo: Path,
    runs_root: Path,
    command: list[str],
    baseline_ref: str = "HEAD",
    **collect_kwargs,
):
    setup_attempt(repo, runs_root, command, baseline_ref)
    return collect_attempt(runs_root, **collect_kwargs)


def collect_attempt(runs_root: Path, **collect_kwargs):
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
    setup_attempt(repo, runs_root, ["touch", str(marker)])
    monkeypatch.setattr("crucible.sandbox.shutil.which", lambda _name: None)
    collected, payload = collect_attempt(runs_root)
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


def make_repo(path: Path, content: str) -> str:
    path.mkdir()
    for args in (
        ["init"],
        ["config", "user.email", "test@example.com"],
        ["config", "user.name", "Test"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    (path / "file.txt").write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "commit"], cwd=path, check=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def make_promisor_repo(path: Path, tmp_path: Path, marker: Path) -> None:
    make_repo(path, "attacker\n")
    remote = tmp_path / f"{path.name}-remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    payload = tmp_path / f"{path.name}-payload.sh"
    payload.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
    payload.chmod(0o755)
    for key, value in (
        ("core.repositoryformatversion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.url", str(remote)),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("remote.origin.uploadpack", str(payload)),
    ):
        subprocess.run(["git", "config", key, value], cwd=path, check=True)


def test_promisor_repo_cannot_execute_during_register(
    repo: Path, runs_root: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "executed-at-register"
    evil = tmp_path / "evil-register"
    make_promisor_repo(evil, tmp_path, marker)
    created = create_harness_run(
        task_summary="Malicious worktree",
        baseline_ref="HEAD",
        repo_root=repo,
        runs_root=runs_root,
        run_id="run-1",
    )
    with pytest.raises(RunManagerError):
        register_model_attempt(
            run_id=created["run_id"],
            model_provider="local",
            model_name="probe",
            ide_host="pytest",
            worktree_path=evil,
            attempt_id="probe-1",
            runs_root=runs_root,
        )
    assert not marker.exists()


def test_promisor_repo_cannot_execute_during_create(
    repo: Path, runs_root: Path, tmp_path: Path
) -> None:
    marker = tmp_path / "executed-at-create"
    evil = tmp_path / "evil-create"
    make_promisor_repo(evil, tmp_path, marker)
    missing = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    with pytest.raises(RunManagerError):
        create_harness_run(
            task_summary="Malicious repo",
            baseline_ref=missing,
            repo_root=evil,
            runs_root=runs_root,
            run_id="run-1",
        )
    assert not marker.exists()


def test_no_module_invokes_git_directly() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "crucible"
    offenders = []
    for path in source_root.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.List)
                and node.elts
                and isinstance(node.elts[0], ast.Constant)
                and node.elts[0].value == "git"
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_replace_refs_cannot_hide_changes(repo: Path, runs_root: Path) -> None:
    baseline = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "change"], cwd=repo, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    subprocess.run(["git", "replace", baseline, head], cwd=repo, check=True)
    _collected, payload = run_attempt(
        repo, runs_root, python_check("pass"), baseline_ref=baseline
    )
    assert "README.md" in payload["files_changed"]


def test_sensitive_path_is_a_signal_not_a_confirmed_secret(
    repo: Path, runs_root: Path
) -> None:
    (repo / "docs").mkdir()
    (repo / "docs" / "setup.environment.md").write_text("plain docs\n", encoding="utf-8")
    collected, _payload = run_attempt(repo, runs_root, python_check("pass"))
    assert collected["attestations"]["secrets_written"]["status"] == "unverified"
    assert collected["boundary_signals"]["sensitive_path_changed"] is True
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_attempt_id"] is None
    assert "sensitive_paths_in_diff" in comparison["blockers"]


def test_ref_deletion_is_history_change_not_commit(repo: Path, runs_root: Path) -> None:
    subprocess.run(["git", "branch", "stale"], cwd=repo, check=True)

    class RefDeletingRunner:
        isolated = True

        def run(self, argv, cwd):
            subprocess.run(["git", "branch", "-qD", "stale"], cwd=repo, check=True)
            return CommandResult(list(argv), True, 0, 0.0, "", sandboxed=True)

    collected, _payload = run_attempt(
        repo, runs_root, ["true"], command_runner=RefDeletingRunner()
    )
    assert collected["attestations"]["git_commit_performed"]["status"] == "unverified"
    assert collected["boundary_signals"]["repository_history_changed"] is True
    comparison = compare_model_results(run_id="run-1", runs_root=runs_root)
    assert comparison["recommended_attempt_id"] is None
    assert "repository_mutated_during_validation" in comparison["blockers"]


def test_merge_during_validation_is_observed(repo: Path, runs_root: Path) -> None:
    default = subprocess.check_output(
        ["git", "branch", "--show-current"], cwd=repo, text=True
    ).strip()

    class MergingRunner:
        isolated = True

        def run(self, argv, cwd):
            for args in (
                ["switch", "-qc", "side"],
                ["commit", "--allow-empty", "-qm", "side"],
                ["switch", "-q", default],
                ["commit", "--allow-empty", "-qm", "main"],
                ["merge", "-q", "--no-edit", "side"],
            ):
                subprocess.run(["git", *args], cwd=repo, check=True)
            return CommandResult(list(argv), True, 0, 0.0, "", sandboxed=True)

    collected, _payload = run_attempt(repo, runs_root, ["true"], command_runner=MergingRunner())
    assert collected["attestations"]["git_commit_performed"]["status"] == "observed"
    assert collected["attestations"]["git_merge_performed"]["status"] == "observed"


def test_cgroup_limits_are_applied_by_kernel() -> None:
    limits = ResourceLimits(memory_bytes=256 * 1024**2, tasks=64, cpu_percent=50)
    actual = read_scope_limits(limits)
    assert actual["memory"] == str(limits.memory_bytes)
    assert actual["tasks"] == "64"
    assert actual["cpu"] == "50000 100000"
    assert actual["swap"] in {"0", "absent"}


def test_process_limit_is_enforced(repo: Path, runs_root: Path) -> None:
    source = (
        "import threading\n"
        "stop = threading.Event()\n"
        "try:\n"
        "    for _ in range(200):\n"
        "        threading.Thread(target=stop.wait, daemon=True).start()\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(9)\n"
    )
    runner = BubblewrapCommandRunner(limits=ResourceLimits(tasks=32))
    _collected, payload = run_attempt(
        repo, runs_root, python_check(source), command_runner=runner
    )
    assert payload["tests_passed"] == 1, payload["test_results"][0]["summary"]


def test_memory_limit_is_enforced(repo: Path, runs_root: Path) -> None:
    source = "data = bytearray(b'x') * (768 * 1024 * 1024); print(len(data))"
    runner = BubblewrapCommandRunner(limits=ResourceLimits(memory_bytes=128 * 1024**2))
    _collected, payload = run_attempt(
        repo, runs_root, python_check(source), command_runner=runner
    )
    assert payload["tests_passed"] == 0


@pytest.mark.parametrize("target", ["/tmp/fill", "/workspace/fill"])
def test_tmpfs_limits_are_enforced(repo: Path, runs_root: Path, target: str) -> None:
    source = (
        "try:\n"
        f"    open({target!r}, 'wb').write(b'x' * (8 * 1024 * 1024))\n"
        "except OSError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(9)\n"
    )
    limits = ResourceLimits(tmp_bytes=2 * 1024**2, workspace_bytes=2 * 1024**2)
    _collected, payload = run_attempt(
        repo,
        runs_root,
        python_check(source),
        command_runner=BubblewrapCommandRunner(limits=limits),
    )
    assert payload["tests_passed"] == 1, payload["test_results"][0]["summary"]


def test_missing_cgroup_support_fails_closed(
    repo: Path, runs_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran-without-limits"
    setup_attempt(repo, runs_root, ["touch", str(marker)])
    real_which = __import__("shutil").which
    monkeypatch.setattr(
        "crucible.sandbox.shutil.which",
        lambda name: None if name == "systemd-run" else real_which(name),
    )
    _collected, payload = collect_attempt(runs_root)
    assert not marker.exists()
    assert payload["test_results"][0]["returncode"] == 126


def run_prohibited(repo: Path, runs_root: Path):
    create_harness_run(
        task_summary="Boundary evasion",
        baseline_ref="baseline",
        repo_root=repo,
        runs_root=runs_root,
        run_id="run-1",
        prohibited_paths=["deploy"],
        required_tests=[["true"]],
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
    _collected, payload = collect_attempt(runs_root)
    return payload, compare_model_results(run_id="run-1", runs_root=runs_root)


@pytest.fixture
def boundary_repo(repo: Path) -> Path:
    (repo / "deploy").mkdir()
    (repo / "deploy" / "prod.conf").write_text("safe\n", encoding="utf-8")
    (repo / ".gitignore").write_text("build/\n*.log\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "boundary"], cwd=repo, check=True)
    subprocess.run(["git", "tag", "baseline"], cwd=repo, check=True)
    return repo


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True)


@pytest.mark.parametrize(
    "vector",
    [
        "assume_unchanged",
        "skip_worktree",
        "lying_clean_filter",
        "info_exclude",
        "core_excludes_file",
        "nested_gitignore",
        "edited_root_gitignore",
    ],
)
def test_git_metadata_cannot_hide_prohibited_changes(
    boundary_repo: Path, runs_root: Path, vector: str
) -> None:
    repo = boundary_repo
    conf = repo / "deploy" / "prod.conf"
    backdoor = repo / "deploy" / "backdoor.sh"
    if vector == "assume_unchanged":
        git(repo, "update-index", "--assume-unchanged", "deploy/prod.conf")
        conf.write_text("tampered\n", encoding="utf-8")
    elif vector == "skip_worktree":
        git(repo, "update-index", "--skip-worktree", "deploy/prod.conf")
        conf.write_text("tampered\n", encoding="utf-8")
    elif vector == "lying_clean_filter":
        git(repo, "config", "filter.hide.clean", "printf 'safe\\n'")
        (repo / ".git" / "info" / "attributes").write_text(
            "deploy/prod.conf filter=hide\n", encoding="utf-8"
        )
        conf.write_text("tampered\n", encoding="utf-8")
    elif vector == "info_exclude":
        with (repo / ".git" / "info" / "exclude").open("a", encoding="utf-8") as handle:
            handle.write("deploy/backdoor.sh\n")
        backdoor.write_text("x\n", encoding="utf-8")
    elif vector == "core_excludes_file":
        hidden = repo / ".git" / "hidden-excludes"
        hidden.write_text("deploy/backdoor.sh\n", encoding="utf-8")
        git(repo, "config", "core.excludesFile", str(hidden))
        backdoor.write_text("x\n", encoding="utf-8")
    elif vector == "nested_gitignore":
        (repo / "deploy" / ".gitignore").write_text("*\n", encoding="utf-8")
        backdoor.write_text("x\n", encoding="utf-8")
    else:
        (repo / ".gitignore").write_text("build/\n*.log\ndeploy/\n", encoding="utf-8")
        backdoor.write_text("x\n", encoding="utf-8")

    payload, comparison = run_prohibited(repo, runs_root)
    assert payload["prohibited_violations"], vector
    assert comparison["recommended_attempt_id"] is None
    assert "prohibited_path_violations" in comparison["blockers"]


def test_hidden_deletion_is_detected(boundary_repo: Path, runs_root: Path) -> None:
    git(boundary_repo, "update-index", "--skip-worktree", "deploy/prod.conf")
    (boundary_repo / "deploy" / "prod.conf").unlink()
    payload, comparison = run_prohibited(boundary_repo, runs_root)
    assert payload["prohibited_violations"] == ["deploy/prod.conf"]
    assert payload["lines_deleted"] == 1
    assert comparison["recommended_attempt_id"] is None


def test_baseline_ignored_output_is_not_a_change(boundary_repo: Path, runs_root: Path) -> None:
    (boundary_repo / "build").mkdir()
    (boundary_repo / "build" / "out.txt").write_text("generated\n", encoding="utf-8")
    (boundary_repo / "debug.log").write_text("log\n", encoding="utf-8")
    payload, comparison = run_prohibited(boundary_repo, runs_root)
    assert payload["files_changed"] == []
    assert comparison["recommended_attempt_id"] == "probe-1"


def test_baseline_ignored_file_under_prohibited_path_blocks(
    boundary_repo: Path, runs_root: Path
) -> None:
    (boundary_repo / "deploy" / "payload.log").write_text("x\n", encoding="utf-8")
    payload, comparison = run_prohibited(boundary_repo, runs_root)
    assert payload["prohibited_violations"] == ["deploy/payload.log"]
    assert comparison["recommended_attempt_id"] is None


def test_clean_attempt_with_real_edit_counts_lines(boundary_repo: Path, runs_root: Path) -> None:
    (boundary_repo / "README.md").write_text("baseline\nadded\n", encoding="utf-8")
    payload, comparison = run_prohibited(boundary_repo, runs_root)
    assert payload["files_changed"] == ["README.md"]
    assert (payload["lines_added"], payload["lines_deleted"]) == (1, 0)
    assert comparison["recommended_attempt_id"] == "probe-1"


def test_unusual_filenames_do_not_break_collection(boundary_repo: Path, runs_root: Path) -> None:
    raw = os.fsencode(boundary_repo) + b"/caf\xe9.txt"
    with open(raw, "wb") as handle:
        handle.write(b"x\n")
    (boundary_repo / "line\nbreak.txt").write_text("x\n", encoding="utf-8")
    payload, _comparison = run_prohibited(boundary_repo, runs_root)
    assert "caf\\xe9.txt" in payload["files_changed"]
    assert "line\nbreak.txt" in payload["files_changed"]


@pytest.mark.parametrize(
    "secret",
    [
        "gh" + "p_" + "a" * 36,
        "github_" + "pat_" + "b" * 40,
        "sk-" + "c" * 32,
        "AK" + "IA" + "D" * 16,
        "xo" + "xb-" + "1234567890-abcdef",
        "ey" + "J" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
    ],
)
def test_known_token_formats_are_redacted(secret: str) -> None:
    summary = _redact_summary(f"before {secret} after")
    assert secret not in summary
    assert summary == "before [REDACTED] after"


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("DB_PASSWORD=hunter2value", "hunter2value"),
        ('api_key: "quoted-value"', "quoted-value"),
        ("Authorization: Bearer opaque-value-123", "opaque-value-123"),
        ("https://user:url-password@example.invalid/repo", "url-password"),
        (
            "-----BEGIN " + "PRIVATE KEY-----\nkey-material\n-----END " + "PRIVATE KEY-----",
            "key-material",
        ),
        ("-----BEGIN " + "RSA PRIVATE KEY-----\nunterminated-material", "unterminated-material"),
    ],
)
def test_secret_assignments_are_redacted(text: str, value: str) -> None:
    assert value not in _redact_summary(text)


def test_ordinary_output_is_not_redacted() -> None:
    text = "tests passed: 12, failed: 0\nsrc/token_parser.py ok"
    assert _redact_summary(text) == text


def test_persisted_command_summary_is_redacted(repo: Path, runs_root: Path) -> None:
    secret = "gh" + "p_" + "z" * 36
    source = "print('leaked', 'gh' + 'p_' + 'z' * 36)"
    _collected, payload = run_attempt(repo, runs_root, python_check(source))
    assert secret not in json.dumps(payload)
    assert "[REDACTED]" in payload["test_results"][0]["summary"]
