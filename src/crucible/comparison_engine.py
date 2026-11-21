"""Deterministic cross-attempt comparison."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .artifact_store import (
    default_runs_root,
    list_attempt_results,
    load_latest_comparison as _load_latest,
    load_manifest,
    run_lock,
    write_comparison,
)
from .schemas import (
    AttemptResult,
    AttestationStatus,
    ComparisonResult,
    aggregate_attestations,
    attestation_block,
    unverified_attestations,
)


class ComparisonEngineError(ValueError):
    pass


def compare_model_results(
    *,
    run_id: str,
    attempt_ids: list[str] | None = None,
    runs_root: Path | None = None,
) -> dict[str, Any]:
    root = (runs_root or default_runs_root()).resolve()
    run = load_manifest(root, run_id)
    available = list_attempt_results(root, run_id)
    if attempt_ids is not None:
        requested = set(attempt_ids)
        results = [result for result in available if result.attempt_id in requested]
        missing = sorted(requested - {result.attempt_id for result in results})
        if missing:
            raise ComparisonEngineError(
                f"attempt_results_missing: {','.join(missing)}"
            )
    else:
        results = available

    if not results:
        raise ComparisonEngineError("no_attempt_results_found")

    scores = [_score_result(result) for result in results]
    blockers = _derive_blockers(results)
    recommended_attempt_id, recommended_provider = _pick_recommended(
        scores, blockers
    )

    comparison = ComparisonResult(
        run_id=run_id,
        comparison_id=f"cmp-{uuid.uuid4().hex[:10]}",
        attempt_ids=[result.attempt_id for result in results],
        recommended_attempt_id=recommended_attempt_id,
        recommended_provider=recommended_provider,
        scores=scores,
        blockers=blockers,
    )
    with run_lock(root, run_id):
        path = write_comparison(comparison, root)

    return {
        "ok": True,
        "run_id": run_id,
        "comparison_id": comparison.comparison_id,
        "recommended_attempt_id": recommended_attempt_id,
        "recommended_provider": recommended_provider,
        "comparison_path": str(path),
        "scores": scores,
        "blockers": blockers,
        "task_summary": run.task_summary,
        **attestation_block(_attestations(results)),
    }


def get_latest_comparison(
    *,
    run_id: str,
    runs_root: Path | None = None,
) -> dict[str, Any]:
    root = (runs_root or default_runs_root()).resolve()
    comparison = _load_latest(root, run_id)
    if comparison is None:
        return {"ok": False, "error": "no_comparison_found", **unverified_attestations()}
    results = [
        result
        for result in list_attempt_results(root, run_id)
        if result.attempt_id in comparison.attempt_ids
    ]
    return {
        "ok": True,
        "comparison": comparison.to_dict(),
        **attestation_block(_attestations(results)),
    }


def _attestations(results: list[AttemptResult]) -> dict[str, dict[str, str]]:
    return aggregate_attestations([result.attestations for result in results])


def _has_status(result: AttemptResult, status: AttestationStatus) -> bool:
    return any(item.get("status") == status.value for item in result.attestations.values())


def _score_result(result: AttemptResult) -> dict[str, Any]:
    correctness = (
        result.tests_passed / result.tests_total if result.tests_total else 1.0
    )
    build = (
        result.builds_passed / result.builds_total if result.builds_total else 1.0
    )
    scope_control = max(0.0, 1.0 - 0.2 * len(result.scope_violations))
    safety = 1.0
    if (
        result.prohibited_violations
        or result.sensitive_paths_found
        or result.repository_mutations
        or _has_status(result, AttestationStatus.OBSERVED)
        or _has_status(result, AttestationStatus.UNVERIFIED)
    ):
        safety = 0.0
    collection = 0.0 if result.collection_errors else 1.0
    churn = result.lines_added + result.lines_deleted
    maintainability = max(0.0, 1.0 - min(churn, 1000) / 1000)

    overall = round(
        correctness * 0.35
        + build * 0.10
        + scope_control * 0.15
        + safety * 0.25
        + collection * 0.05
        + maintainability * 0.10,
        4,
    )
    notes: list[str] = []
    if result.scope_violations:
        notes.append(f"scope_violations={len(result.scope_violations)}")
    if result.prohibited_violations:
        notes.append(
            f"prohibited_violations={len(result.prohibited_violations)}"
        )
    if result.sensitive_paths_found:
        notes.append("sensitive_paths_detected")
    if result.repository_mutations:
        notes.append("repository_mutated_during_validation")
    if _has_status(result, AttestationStatus.OBSERVED):
        notes.append("boundary_violation_observed")
    if _has_status(result, AttestationStatus.UNVERIFIED):
        notes.append("boundary_attestation_unverified")
    if result.collection_errors:
        notes.append("collection_errors")
    if result.tests_total and result.tests_passed < result.tests_total:
        notes.append("required_tests_failed")
    if result.builds_total and result.builds_passed < result.builds_total:
        notes.append("required_builds_failed")

    return {
        "attempt_id": result.attempt_id,
        "model_provider": result.model_provider,
        "model_name": result.model_name,
        "correctness": round(correctness, 4),
        "build": round(build, 4),
        "scope_control": round(scope_control, 4),
        "safety_boundaries": round(safety, 4),
        "collection_integrity": round(collection, 4),
        "maintainability": round(maintainability, 4),
        "overall": overall,
        "notes": notes,
    }


def _derive_blockers(results: list[AttemptResult]) -> list[str]:
    blockers: list[str] = []
    if any(result.collection_errors for result in results):
        blockers.append("collection_errors")
    if any(result.prohibited_violations for result in results):
        blockers.append("prohibited_path_violations")
    if any(result.sensitive_paths_found for result in results):
        blockers.append("sensitive_paths_in_diff")
    if any(result.repository_mutations for result in results):
        blockers.append("repository_mutated_during_validation")
    if any(_has_status(result, AttestationStatus.OBSERVED) for result in results):
        blockers.append("boundary_violation_observed")
    if any(_has_status(result, AttestationStatus.UNVERIFIED) for result in results):
        blockers.append("boundary_attestation_unverified")
    if any(
        result.tests_total and result.tests_passed < result.tests_total
        for result in results
    ):
        blockers.append("required_tests_failed")
    if any(
        result.builds_total and result.builds_passed < result.builds_total
        for result in results
    ):
        blockers.append("required_builds_failed")
    return blockers


def _pick_recommended(
    scores: list[dict[str, Any]],
    blockers: list[str],
) -> tuple[str | None, str | None]:
    if blockers or not scores:
        return None, None
    winner = sorted(
        scores,
        key=lambda score: (
            -float(score["overall"]),
            str(score["attempt_id"]),
        ),
    )[0]
    return str(winner["attempt_id"]), str(winner["model_provider"])
