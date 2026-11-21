"""Bubblewrap isolation for agent-controlled commands and Git reads.

Validation commands never run on the host. Each one gets a disposable copy of the
attempt's files, with no network, no host home, no credentials and no privilege
escalation. If that isolation cannot be established, callers must not execute the
command: there is deliberately no host-execution fallback.
"""

from __future__ import annotations

import os
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Sequence

from .schemas import CommandResult

SANDBOX_WORKSPACE = "/workspace"
SANDBOX_HOME = "/tmp/home"
SANDBOX_SEED = "/.crucible-seed"
SANDBOX_SCRATCH = "/.crucible-scratch"
MAX_WORKSPACE_BYTES = 1024**3
MAX_FILE_BYTES = 1024**3
OUTPUT_TAIL_BYTES = 64 * 1024
RO_PATHS_ENV = "CRUCIBLE_SANDBOX_RO_PATHS"
PERSIST_OUTPUT_ENV = "CRUCIBLE_PERSIST_REDACTED_OUTPUT"
_PROTECTED_ROOTS = ("/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys", "/var")
DEFAULT_TOOLCHAIN_PATHS = ("/opt/python",)
REDACTED = "[REDACTED]"
_SECRET_NAME = (
    r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential)[\w.-]*"
)
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
            re.DOTALL,
        ),
        REDACTED,
    ),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)[^\r\n]+"), rf"\1{REDACTED}"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^/\s@]+(@)"), rf"\1{REDACTED}\2"),
    (
        re.compile(rf"(?i)(\b{_SECRET_NAME}[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"),
        rf"\1{REDACTED}",
    ),
    (
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
            r"sk-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|"
            r"xox[abeoprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|"
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
        ),
        REDACTED,
    ),
)
_GIT_COMMAND = (
    "/usr/bin/git",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.sparseCheckout=false",
    "-c",
    "protocol.allow=never",
)
_FORBIDDEN_RO_SEGMENTS = {
    ".aws",
    ".azure",
    ".docker",
    ".git-credentials",
    ".gnupg",
    ".kube",
    ".netrc",
    ".password-store",
    ".ssh",
}


@dataclass(frozen=True)
class ResourceLimits:
    """Cgroup and tmpfs limits applied to everything agent-controlled."""

    memory_bytes: int = 4 * 1024**3
    tasks: int = 256
    cpu_percent: int = 200
    tmp_bytes: int = 1024**3
    workspace_bytes: int = 2 * 1024**3


DEFAULT_LIMITS = ResourceLimits()


class SandboxUnavailable(RuntimeError):
    """Isolation could not be established, so the command must not run."""


def toolchain_paths() -> list[str]:
    """Return read-only toolchain roots, rejecting anything that exposes the host home."""

    paths = [path for path in DEFAULT_TOOLCHAIN_PATHS if os.path.isdir(path)]
    configured = os.environ.get(RO_PATHS_ENV, "")
    home = Path.home().resolve()
    for raw in filter(None, configured.split(":")):
        path = Path(raw)
        if not path.is_absolute() or not path.exists():
            raise SandboxUnavailable(f"invalid_ro_path: {raw}")
        resolved = path.resolve()
        if resolved == Path("/") or home.is_relative_to(resolved):
            raise SandboxUnavailable(f"ro_path_exposes_home: {raw}")
        if _FORBIDDEN_RO_SEGMENTS.intersection(resolved.parts):
            raise SandboxUnavailable(f"ro_path_exposes_credentials: {raw}")
        if not _is_toolchain(resolved):
            raise SandboxUnavailable(f"invalid_ro_path: {raw}")
        paths.append(str(resolved))
    return sorted(set(paths))


def _is_toolchain(path: Path) -> bool:
    """Accept a virtualenv or an installed toolchain under /opt, never a system directory."""

    if any(path.is_relative_to(root) for root in _PROTECTED_ROOTS):
        return False
    if (path / "pyvenv.cfg").is_file():
        return True
    return path.is_relative_to("/opt") and len(path.parts) >= 3 and (path / "bin").is_dir()


def _sandbox_path(toolchains: Sequence[str]) -> str:
    entries: list[str] = []
    for entry in os.environ.get("PATH", "").split(":"):
        if any(entry == root or entry.startswith(f"{root}/") for root in toolchains):
            entries.append(entry)
    entries.extend(["/usr/local/bin", "/usr/bin", "/bin"])
    return ":".join(dict.fromkeys(entries))


def _base_args(bwrap: str, toolchains: Sequence[str], limits: ResourceLimits) -> list[str]:
    args = [
        bwrap,
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    for name in ("bin", "sbin", "lib", "lib32", "lib64"):
        host = f"/{name}"
        if os.path.islink(host):
            args.extend(["--symlink", os.readlink(host), host])
        elif os.path.isdir(host):
            args.extend(["--ro-bind", host, host])
    args.extend(
        [
            "--ro-bind-try",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--ro-bind-try",
            "/etc/alternatives",
            "/etc/alternatives",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(limits.tmp_bytes),
            "--tmpfs",
            "/tmp",
            "--dir",
            SANDBOX_HOME,
        ]
    )
    for path in toolchains:
        args.extend(["--ro-bind", path, path])
    env = {
        "PATH": _sandbox_path(toolchains),
        "HOME": SANDBOX_HOME,
        "USER": "sandbox",
        "LOGNAME": "sandbox",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    for key, value in env.items():
        args.extend(["--setenv", key, value])
    return args


def _limit_child() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))


def _find_bwrap() -> str:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise SandboxUnavailable("bubblewrap_not_installed")
    return bwrap


def _scope_env() -> dict[str, str]:
    """Return only what systemd-run needs; bubblewrap clears it before agent code runs."""

    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(Path.home()),
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        or f"unix:path={runtime}/bus",
    }


def _scoped(command: Sequence[str], limits: ResourceLimits) -> list[str]:
    systemd_run = shutil.which("systemd-run")
    if not systemd_run:
        raise SandboxUnavailable("systemd_run_not_installed")
    return [
        systemd_run,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        f"--property=MemoryMax={limits.memory_bytes}",
        "--property=MemorySwapMax=0",
        f"--property=TasksMax={limits.tasks}",
        f"--property=CPUQuota={limits.cpu_percent}%",
        "--",
        *command,
    ]


def read_scope_limits(limits: ResourceLimits = DEFAULT_LIMITS) -> dict[str, str]:
    """Read the limits the kernel actually applied to a scope."""

    script = (
        'c=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); '
        'cat "$c/memory.max" "$c/pids.max" "$c/cpu.max"; '
        'cat "$c/memory.swap.max" 2>/dev/null || echo absent'
    )
    try:
        completed = subprocess.run(
            _scoped(["/bin/sh", "-c", script], limits),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=_scope_env(),
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxUnavailable(f"cgroup_scope_failed: {exc}") from exc
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or len(lines) != 4:
        raise SandboxUnavailable(f"cgroup_scope_failed: {completed.stderr.strip()[:200]}")
    return {"memory": lines[0], "tasks": lines[1], "cpu": lines[2], "swap": lines[3]}


def _verify_scope(limits: ResourceLimits) -> None:
    actual = read_scope_limits(limits)
    expected = {
        "memory": str(limits.memory_bytes),
        "tasks": str(limits.tasks),
        "cpu": f"{limits.cpu_percent * 1000} 100000",
    }
    for key, value in expected.items():
        if actual[key] != value:
            raise SandboxUnavailable(f"cgroup_limit_not_applied: {key}")
    if actual["swap"] not in {"0", "absent"}:
        raise SandboxUnavailable("cgroup_limit_not_applied: swap")


class BubblewrapCommandRunner:
    """Run commands in a network-less, credential-less, no-new-privileges sandbox."""

    isolated = True

    def __init__(
        self,
        timeout_seconds: int = 300,
        limits: ResourceLimits = DEFAULT_LIMITS,
        persist_output: bool | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.limits = limits
        self.persist_output = (
            os.environ.get(PERSIST_OUTPUT_ENV) == "1"
            if persist_output is None
            else persist_output
        )

    def preflight(self) -> None:
        """Prove the isolation properties before any agent-controlled code runs."""

        bwrap = _find_bwrap()
        toolchains = toolchain_paths()
        _verify_scope(self.limits)
        script = (
            'grep -Eq "^NoNewPrivs:[[:space:]]*1$" /proc/self/status || exit 11; '
            'grep -Eq "^CapEff:[[:space:]]*0+$" /proc/self/status || exit 12; '
            '[ "$(grep -c : /proc/net/dev)" = 1 ] || exit 13; '
            '[ ! -e "$1" ] || exit 14; '
            "[ ! -e /etc/sudoers ] || exit 15; "
            "[ ! -e /run ] || exit 16; "
            'grep -Eq "^tmpfs /tmp tmpfs .*size=" /proc/mounts || exit 17; '
            'grep -Eq "^tmpfs /workspace tmpfs .*size=" /proc/mounts || exit 18'
        )
        argv = _scoped(
            [
                *_base_args(bwrap, toolchains, self.limits),
                "--size",
                str(self.limits.workspace_bytes),
                "--tmpfs",
                SANDBOX_WORKSPACE,
                "--",
                "/bin/sh",
                "-c",
                script,
                "crucible-preflight",
                str(Path.home()),
            ],
            self.limits,
        )
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                env=_scope_env(),
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailable(f"preflight_failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip()[:200]
            raise SandboxUnavailable(f"preflight_exit_{completed.returncode}: {detail}")

    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult:
        if not argv:
            raise ValueError("empty_command")
        command = _scoped(
            [
                *_base_args(_find_bwrap(), toolchain_paths(), self.limits),
                "--ro-bind",
                str(cwd),
                SANDBOX_SEED,
                "--size",
                str(self.limits.workspace_bytes),
                "--tmpfs",
                SANDBOX_WORKSPACE,
                "--chdir",
                SANDBOX_WORKSPACE,
                "--",
                "/bin/sh",
                "-c",
                'cp -a "$0"/. . && exec "$@"',
                SANDBOX_SEED,
                *argv,
            ],
            self.limits,
        )
        started = time.monotonic()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=_scope_env(),
                    timeout=self.timeout_seconds,
                    check=False,
                    preexec_fn=_limit_child,
                )
                returncode, timed_out = completed.returncode, False
            except subprocess.TimeoutExpired:
                returncode, timed_out = -1, True
            summary = _summarize(stdout, stderr, self.persist_output)
        return CommandResult(
            argv=list(argv),
            passed=returncode == 0 and not timed_out,
            returncode=returncode,
            duration_seconds=round(time.monotonic() - started, 3),
            summary=summary,
            timed_out=timed_out,
            sandboxed=True,
        )


def _summarize(stdout, stderr, persist_output: bool) -> str:
    """Store agent-controlled output only when the operator explicitly opts in."""

    if persist_output:
        return _tail(stdout) or _tail(stderr)
    stdout_bytes = stdout.seek(0, os.SEEK_END)
    stderr_bytes = stderr.seek(0, os.SEEK_END)
    return (
        f"output suppressed: stdout={stdout_bytes} bytes, stderr={stderr_bytes} bytes; "
        f"set {PERSIST_OUTPUT_ENV}=1 to store redacted output"
    )


def _tail(handle) -> str:
    size = handle.seek(0, os.SEEK_END)
    handle.seek(max(0, size - OUTPUT_TAIL_BYTES))
    value = handle.read().decode("utf-8", errors="replace").replace("\x00", "")
    return _redact_summary(value)[-2000:]


def _redact_summary(text: str) -> str:
    """Mask common secret formats before command output is persisted."""

    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _common_git_dir(worktree: Path) -> tuple[Path, bool]:
    """Return a checkout's Git common dir and whether it is a linked worktree."""

    dot_git = worktree / ".git"
    if dot_git.is_symlink():
        raise SandboxUnavailable("git_dir_is_symlink")
    if dot_git.is_dir():
        return dot_git.resolve(), False
    if not dot_git.is_file():
        raise SandboxUnavailable("git_dir_not_found")

    content = dot_git.read_text(encoding="utf-8", errors="replace").strip()
    if not content.startswith("gitdir:"):
        raise SandboxUnavailable("git_file_invalid")
    git_dir = (worktree / content.removeprefix("gitdir:").strip()).resolve()
    commondir_file = git_dir / "commondir"
    if not commondir_file.is_file():
        raise SandboxUnavailable("git_worktree_pointer_invalid")
    relative = commondir_file.read_text(encoding="utf-8", errors="replace").strip()
    common = (git_dir / relative).resolve()
    if not git_dir.is_relative_to(common / "worktrees"):
        raise SandboxUnavailable("git_worktree_pointer_invalid")
    return common, True


def resolve_git_paths(worktree: Path, repo_root: Path | None = None) -> Path:
    """Return the Git common dir, refusing a `.git` pointer aimed outside the run's repo."""

    common, linked = _common_git_dir(worktree)
    if linked and (repo_root is None or _common_git_dir(repo_root)[0] != common):
        raise SandboxUnavailable("git_dir_outside_run_repository")
    return common


def _execute_git(
    command: Sequence[str],
    input_bytes: bytes | None,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        _scoped(command, DEFAULT_LIMITS),
        input=input_bytes if input_bytes is not None else b"",
        capture_output=True,
        env=_scope_env(),
        timeout=timeout,
        check=False,
    )


def run_git_bytes(
    worktree: Path,
    repo_root: Path | None,
    args: Sequence[str],
    *,
    timeout: int,
    scratch: Path | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run Git read-only and isolated, since repo config and filters can execute code."""

    common = resolve_git_paths(worktree, repo_root)
    command = _base_args(_find_bwrap(), toolchain_paths(), DEFAULT_LIMITS)
    for path in sorted({str(worktree), str(common)}, key=len):
        command.extend(["--ro-bind", path, path])
    if scratch is not None:
        command.extend(["--bind", str(scratch), SANDBOX_SCRATCH])
    settings = {
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        **(env or {}),
    }
    for key, value in settings.items():
        command.extend(["--setenv", key, value])
    command.extend(["--chdir", str(worktree), "--", *_GIT_COMMAND, *args])
    return _execute_git(command, input_bytes, timeout)


def run_sandboxed_git(
    worktree: Path,
    repo_root: Path | None,
    args: Sequence[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run a sandboxed Git command and decode its output for display."""

    completed = run_git_bytes(worktree, repo_root, args, timeout=timeout)
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


def run_scratch_git(
    scratch: Path,
    args: Sequence[str],
    *,
    timeout: int,
    directory: str = ".",
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run Git in a repository Crucible created, with no access to the attempt."""

    command = _base_args(_find_bwrap(), toolchain_paths(), DEFAULT_LIMITS)
    command.extend(
        [
            "--bind",
            str(scratch),
            SANDBOX_SCRATCH,
            "--chdir",
            f"{SANDBOX_SCRATCH}/{directory}",
            "--",
            *_GIT_COMMAND,
            *args,
        ]
    )
    return _execute_git(command, input_bytes, timeout)


def scratch_index_env(worktree: Path, repo_root: Path | None) -> dict[str, str]:
    """Point Git at a disposable index and object store instead of the attempt's."""

    common = resolve_git_paths(worktree, repo_root)
    return {
        "GIT_INDEX_FILE": f"{SANDBOX_SCRATCH}/index",
        "GIT_OBJECT_DIRECTORY": f"{SANDBOX_SCRATCH}/objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(common / "objects"),
    }


def prepare_workspace(
    worktree: Path,
    files: Sequence[str],
    is_excluded: Callable[[str], bool],
) -> Path:
    """Copy attempt files to a disposable directory without following links."""

    workspace = Path(tempfile.mkdtemp(prefix="crucible-workspace-"))
    total = 0
    try:
        for relative in files:
            pure = PurePosixPath(relative)
            if pure.is_absolute() or ".." in pure.parts or ".git" in pure.parts:
                continue
            if is_excluded(relative) or _has_symlink_parent(worktree, pure):
                continue
            source = worktree / relative
            try:
                info = source.lstat()
            except FileNotFoundError:
                continue
            target = workspace / relative
            if stat.S_ISLNK(info.st_mode):
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.readlink(source), target)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink > 1:
                    raise SandboxUnavailable("workspace_hardlink_refused")
                total += info.st_size
                if total > MAX_WORKSPACE_BYTES:
                    raise SandboxUnavailable("workspace_too_large")
                target.parent.mkdir(parents=True, exist_ok=True)
                _copy_regular(source, target, info.st_mode)
    except BaseException:
        remove_workspace(workspace)
        raise
    return workspace


def _has_symlink_parent(worktree: Path, relative: PurePosixPath) -> bool:
    current = worktree
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _copy_regular(source: Path, target: Path, mode: int) -> None:
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as reader:
        info = os.fstat(reader.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise SandboxUnavailable("workspace_source_changed")
        with target.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
    target.chmod(stat.S_IMODE(mode) & 0o755 | stat.S_IRUSR | stat.S_IWUSR)


def remove_workspace(workspace: Path) -> None:
    """Delete a workspace even if a command removed write permission from its directories."""

    for root, directories, _files in os.walk(workspace):
        for name in directories:
            path = Path(root) / name
            if not path.is_symlink():
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
    shutil.rmtree(workspace, ignore_errors=True)
