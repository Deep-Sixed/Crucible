"""Local-only closeout records; no Datacore or Nexus bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifact_store import (
    default_runs_root,
    list_attempt_results,
    list_attempts,
    load_latest_comparison,
    load_manifest,
    run_dir,
    run_lock,
    write_closeout,
    write_manifest,
)
from .schemas import (
    HarnessCloseout,
    NO_SIDE_EFFECTS,
    OperatorDecision,
    RunStatus,
    utc_now,
)


class CloseoutError(ValueError):
    pass


def record_harness_closeout(
    *,
    run_id: str,
    operator_decision: str = OperatorDecision.PENDING_REVIEW.value,
    runs_root: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    root = (runs_root or default_runs_root()).resolve()
    run = load_manifest(root, run_id)
    attempts = list_attempts(root, run_id)
    results = list_attempt_results(root, run_id)
    comparison = load_latest_comparison(root, run_id)

    try:
        decision = OperatorDecision(operator_decision)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in OperatorDecision)
        raise CloseoutError(
            f"invalid_operator_decision: {operator_decision!r}; allowed: {allowed}"
        ) from exc

    validation = {
        "results_collected": len(results) == len(attempts) and bool(attempts),
        "tests_passed": all(
            result.tests_passed == result.tests_total for result in results
        ),
        "builds_passed": all(
            result.builds_passed == result.builds_total for result in results
        ),
        "boundary_checks_passed": bool(comparison)
        and not comparison.blockers,
        "comparison_generated": comparison is not None,
    }

    artifacts = [str(run_dir(root, run_id) / "manifest.json")]
    artifacts.extend(
        str(
            run_dir(root, run_id)
            / "attempts"
            / f"{result.attempt_id}_result.json"
        )
        for result in results
    )
    if comparison:
        artifacts.append(
            str(
                run_dir(root, run_id)
                / "comparisons"
                / f"{comparison.comparison_id}.json"
            )
        )

    closeout = HarnessCloseout(
        entity_type="crucible_run",
        run_id=run_id,
        workspace=run.workspace,
        baseline_commit=run.baseline_commit,
        task_summary=run.task_summary[:500],
        models_observed=sorted({attempt.model_provider for attempt in attempts}),
        artifacts=artifacts,
        validation=validation,
        operator_decision=decision.value,
    )

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "run_id": run_id,
            "closeout": closeout.to_dict(),
            "external_write_performed": False,
            **NO_SIDE_EFFECTS,
        }

    with run_lock(root, run_id):
        closeout_path = write_closeout(closeout, root)
        run.status = RunStatus.CLOSED.value
        run.updated_at = utc_now()
        write_manifest(run, root)

    return {
        "ok": True,
        "run_id": run_id,
        "closeout_path": str(closeout_path),
        "closeout": closeout.to_dict(),
        "external_write_performed": False,
        **NO_SIDE_EFFECTS,
    }
