"""Versioned data schemas for EVECOR AI Harness artifacts."""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Self

SCHEMA_VERSION = 2


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


class RunStatus(StrEnum):
    ACTIVE = "active"
    EVALUATED = "evaluated"
    CLOSED = "closed"


class OperatorDecision(StrEnum):
    PENDING_REVIEW = "pending_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NEEDS_CHANGES = "needs_changes"


class ModelProvider(StrEnum):
    CURSOR = "cursor"
    CODEX = "codex"
    CLAUDE = "claude"
    COMPOSER = "composer"
    GEMINI = "gemini"
    LOCAL = "local"
    OTHER = "other"


NO_SIDE_EFFECTS: dict[str, bool] = {
    "outbound_email_sent": False,
    "mailbox_mutated": False,
    "application_status_mutated": False,
    "browser_submit_executed": False,
    "secrets_written": False,
    "database_mutated": False,
    "git_commit_performed": False,
    "git_merge_performed": False,
    "git_push_performed": False,
}

SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.",
    "keepass",
    ".kdbx",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".token",
    "credentials.json",
    "secrets/",
    "_secrets/",
    "id_rsa",
    "id_ed25519",
)


@dataclass(slots=True)
class HarnessRun:
    run_id: str
    workspace: str
    task_summary: str
    repo_root: str
    baseline_commit: str
    baseline_ref: str
    allowed_paths: list[str]
    prohibited_paths: list[str]
    required_tests: list[list[str]]
    required_builds: list[list[str]]
    status: str = RunStatus.ACTIVE.value
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        normalized = dict(data)
        normalized.setdefault("required_builds", [])
        normalized.setdefault("repo_root", "")
        normalized.setdefault("updated_at", normalized.get("created_at", ""))
        normalized.setdefault("schema_version", 1)
        normalized["required_tests"] = _normalize_commands(normalized.get("required_tests", []))
        normalized["required_builds"] = _normalize_commands(normalized.get("required_builds", []))
        return cls(**_only_fields(cls, normalized))


@dataclass(slots=True)
class ModelAttempt:
    attempt_id: str
    run_id: str
    model_provider: str
    model_name: str
    ide_host: str
    worktree_path: str
    baseline_commit: str
    registered_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        normalized = dict(data)
        normalized.setdefault("schema_version", 1)
        return cls(**_only_fields(cls, normalized))


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    passed: bool
    returncode: int
    duration_seconds: float
    summary: str
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(**_only_fields(cls, data))


@dataclass(slots=True)
class AttemptResult:
    attempt_id: str
    run_id: str
    model_provider: str
    model_name: str
    files_changed: list[str]
    lines_added: int
    lines_deleted: int
    untracked_files: list[str]
    scope_violations: list[str]
    prohibited_violations: list[str]
    sensitive_paths_found: list[str]
    test_results: list[dict[str, Any]]
    build_results: list[dict[str, Any]]
    tests_passed: int
    tests_total: int
    builds_passed: int
    builds_total: int
    build_passed: bool | None
    collection_errors: list[str]
    collected_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        normalized = dict(data)
        normalized.setdefault("untracked_files", [])
        normalized.setdefault("test_results", [])
        normalized.setdefault("build_results", [])
        normalized.setdefault("builds_passed", 0)
        normalized.setdefault("builds_total", 0)
        normalized.setdefault("collection_errors", [])
        normalized.setdefault("schema_version", 1)
        return cls(**_only_fields(cls, normalized))


@dataclass(slots=True)
class ComparisonResult:
    run_id: str
    comparison_id: str
    attempt_ids: list[str]
    recommended_attempt_id: str | None
    recommended_provider: str | None
    scores: list[dict[str, Any]]
    blockers: list[str]
    operator_approval_required: bool = True
    generated_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        normalized = dict(data)
        normalized.setdefault("recommended_attempt_id", None)
        normalized.setdefault("schema_version", 1)
        return cls(**_only_fields(cls, normalized))


@dataclass(slots=True)
class HarnessCloseout:
    entity_type: str
    run_id: str
    workspace: str
    baseline_commit: str
    task_summary: str
    models_observed: list[str]
    artifacts: list[str]
    validation: dict[str, bool]
    operator_decision: str
    closed_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), **NO_SIDE_EFFECTS}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        normalized = dict(data)
        normalized.setdefault("closed_at", utc_now())
        normalized.setdefault("schema_version", 1)
        return cls(**_only_fields(cls, normalized))


def _only_fields(cls: type[Any], data: dict[str, Any]) -> dict[str, Any]:
    return {name: data[name] for name in cls.__dataclass_fields__ if name in data}


def _normalize_commands(commands: Any) -> list[list[str]]:
    normalized: list[list[str]] = []
    for command in commands or []:
        if isinstance(command, str):
            import shlex

            normalized.append(shlex.split(command))
        else:
            normalized.append([str(part) for part in command])
    return normalized
