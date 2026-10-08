"""Command-line interface for EVECOR AI Harness."""

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any, Sequence

from .closeout import record_harness_closeout
from .comparison_engine import compare_model_results
from .evaluation_engine import collect_run_results
from .run_manager import (
    create_harness_run,
    get_harness_status,
    register_model_attempt,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crucible")
    parser.add_argument(
        "--runs-root",
        type=Path,
        help="Override the component-local var/runs directory",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("--repo", type=Path, required=True)
    create.add_argument("--baseline", required=True)
    create.add_argument("--task", required=True)
    create.add_argument("--workspace", default="EVECOR")
    create.add_argument("--run-id")
    create.add_argument("--allow", action="append", default=[])
    create.add_argument("--prohibit", action="append", default=[])
    create.add_argument("--test", action="append", default=[])
    create.add_argument("--build", action="append", default=[])
    create.add_argument("--dry-run", action="store_true")

    register = sub.add_parser("register")
    register.add_argument("run_id")
    register.add_argument("--provider", required=True)
    register.add_argument("--model", required=True)
    register.add_argument("--host", required=True)
    register.add_argument("--worktree", type=Path, required=True)
    register.add_argument("--attempt-id")

    collect = sub.add_parser("collect")
    collect.add_argument("run_id")

    compare = sub.add_parser("compare")
    compare.add_argument("run_id")
    compare.add_argument("--attempt", action="append", default=None)

    closeout = sub.add_parser("closeout")
    closeout.add_argument("run_id")
    closeout.add_argument(
        "--decision",
        default="pending_review",
        choices=["pending_review", "accepted", "rejected", "needs_changes"],
    )
    closeout.add_argument("--dry-run", action="store_true")

    status = sub.add_parser("status")
    status.add_argument("run_id", nargs="?")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    common: dict[str, Any] = {}
    if args.runs_root:
        common["runs_root"] = args.runs_root

    if args.command == "create":
        result = create_harness_run(
            task_summary=args.task,
            baseline_ref=args.baseline,
            repo_root=args.repo,
            workspace=args.workspace,
            allowed_paths=args.allow,
            prohibited_paths=args.prohibit,
            required_tests=[shlex.split(value) for value in args.test],
            required_builds=[shlex.split(value) for value in args.build],
            run_id=args.run_id,
            dry_run=args.dry_run,
            **common,
        )
    elif args.command == "register":
        result = register_model_attempt(
            run_id=args.run_id,
            model_provider=args.provider,
            model_name=args.model,
            ide_host=args.host,
            worktree_path=args.worktree,
            attempt_id=args.attempt_id,
            **common,
        )
    elif args.command == "collect":
        result = collect_run_results(run_id=args.run_id, **common)
    elif args.command == "compare":
        result = compare_model_results(
            run_id=args.run_id,
            attempt_ids=args.attempt,
            **common,
        )
    elif args.command == "closeout":
        result = record_harness_closeout(
            run_id=args.run_id,
            operator_decision=args.decision,
            dry_run=args.dry_run,
            **common,
        )
    else:
        result = get_harness_status(run_id=args.run_id, **common)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
