"""EVECOR AI Harness public API."""

from .closeout import CloseoutError, record_harness_closeout
from .comparison_engine import (
    ComparisonEngineError,
    compare_model_results,
    get_latest_comparison,
)
from .evaluation_engine import EvaluationEngineError, collect_run_results
from .run_manager import (
    RunManagerError,
    create_harness_run,
    get_harness_status,
    register_model_attempt,
)

__all__ = [
    "CloseoutError",
    "ComparisonEngineError",
    "EvaluationEngineError",
    "RunManagerError",
    "collect_run_results",
    "compare_model_results",
    "create_harness_run",
    "get_harness_status",
    "get_latest_comparison",
    "record_harness_closeout",
    "register_model_attempt",
]
