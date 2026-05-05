"""
Game-Theoretic Threat Estimator Package
========================================

Computes a dynamic Threat Score (T_S) and routes each drone/RPA
ingestion submission to the appropriate inspection depth (Signature
only / + AI-ML / + Sandbox) using a Stackelberg game plus a Bayesian
cold-start prior and an adaptive-threshold feedback loop.

Pipeline Position:
    Ingestion Interceptor → **Game-Theoretic Threat Estimator**
        → Multi-Layer Malware Detection Engine → Metadata Sanitizer
        → Threat Intelligence Correlator → Response & Quarantine Manager

Main entry points:
    - GameTheoreticThreatEstimator: class-based API with full configuration
    - estimate_from_ingest_result(): accepts IngestResult dict directly

Usage:
    from threat_estimator import (
        GameTheoreticThreatEstimator,
        EstimatorConfig,
        DetectionOutcome,
    )

    estimator = GameTheoreticThreatEstimator(EstimatorConfig())
    estimate = estimator.estimate_from_ingest_result(ingest_result)
    print(estimate.threat_score, estimate.inspection.level)

    # Close the feedback loop once the detection engine returns a verdict
    estimator.record_outcome(DetectionOutcome(
        drone_id=estimate.drone_id,
        verdict="malicious",
        source="sandbox",
        estimate_id=estimate.estimate_id,
    ))
    # Periodically re-tune thresholds from accumulated feedback
    estimator.update_thresholds_from_feedback()
"""

from .adaptive import AdaptiveThresholdManager
from .bayesian import (
    BayesianReputationEstimator,
    DEFAULT_FILE_LIKELIHOOD,
    DEFAULT_ZONE_LIKELIHOOD,
    update_reputation,
)
from .config import EstimatorConfig
from .estimator import GameTheoreticThreatEstimator
from .feedback import FeedbackLoop
from .models import (
    BatchThreatEstimate,
    BayesianTrace,
    DetectionOutcome,
    DetectionVerdict,
    EquilibriumResult,
    FeedbackMetrics,
    InspectionDecision,
    InspectionLevel,
    PayoffMatrix,
    ReputationProfile,
    ReputationSource,
    ThreatEstimate,
    new_estimate_id,
)
from .reputation_store import InMemoryReputationStore
from .stackelberg import (
    build_payoff_matrices,
    compute_DSR_primes,
    compute_I_prime,
    compute_threat_score,
    sigmoid,
    solve_stackelberg_pure,
)

__all__ = [
    # Core
    "GameTheoreticThreatEstimator",
    "EstimatorConfig",
    # Sub-components (swappable via DI)
    "BayesianReputationEstimator",
    "AdaptiveThresholdManager",
    "InMemoryReputationStore",
    "FeedbackLoop",
    # Models
    "ThreatEstimate",
    "BatchThreatEstimate",
    "BayesianTrace",
    "PayoffMatrix",
    "EquilibriumResult",
    "InspectionDecision",
    "InspectionLevel",
    "ReputationProfile",
    "ReputationSource",
    "DetectionOutcome",
    "DetectionVerdict",
    "FeedbackMetrics",
    # Helpers
    "update_reputation",
    "build_payoff_matrices",
    "compute_DSR_primes",
    "compute_I_prime",
    "compute_threat_score",
    "solve_stackelberg_pure",
    "sigmoid",
    "new_estimate_id",
    # Default CPTs (exposed for host-side tuning)
    "DEFAULT_ZONE_LIKELIHOOD",
    "DEFAULT_FILE_LIKELIHOOD",
]
