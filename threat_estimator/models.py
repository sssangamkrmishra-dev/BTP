"""
Data models for the Game-Theoretic Threat Estimator pipeline.
Uses dataclasses for structured, typed representations of all entities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_id(prefix: str, length: int = 12) -> str:
    return f"{prefix}{uuid.uuid4().hex[:length]}"


class InspectionLevel(Enum):
    """Depth of inspection selected by the estimator."""
    LOW = "Low"            # signature scan only
    MEDIUM = "Medium"      # signature + AI/ML classifier
    HIGH = "High"          # signature + AI/ML + sandbox execution


class ReputationSource(Enum):
    """Origin of the reputation value used for an estimate."""
    HISTORY = "history"                 # retrieved from ReputationStore
    BAYESIAN_PRIOR = "bayesian_prior"   # computed via BBN on (zone, file_type)
    DEFAULT = "default"                 # fallback from EstimatorConfig
    PROVIDED = "provided"               # carried through IngestMetadata


class DetectionVerdict(Enum):
    """Verdict returned by the downstream malware-detection engine."""
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"


@dataclass
class BayesianTrace:
    """Per-request breakdown of the Bayesian posterior computation."""
    zone: str
    file_type: str
    P_N: float
    P_A: float
    P_Z_given_N: float
    P_Z_given_A: float
    P_F_given_N: float
    P_F_given_A: float
    numerator: float
    denominator: float
    R: float
    used_fallback_zone: bool = False
    used_fallback_file: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "file_type": self.file_type,
            "P_N": self.P_N,
            "P_A": self.P_A,
            "P_Z_given_N": self.P_Z_given_N,
            "P_Z_given_A": self.P_Z_given_A,
            "P_F_given_N": self.P_F_given_N,
            "P_F_given_A": self.P_F_given_A,
            "numerator": round(self.numerator, 6),
            "denominator": round(self.denominator, 6),
            "R": round(self.R, 6),
            "used_fallback_zone": self.used_fallback_zone,
            "used_fallback_file": self.used_fallback_file,
        }


@dataclass
class ReputationProfile:
    """Stored reputation record for a drone."""
    drone_id: str
    value: float
    source: str                   # ReputationSource value
    updated_at: str = field(default_factory=_utc_now_iso)
    sample_count: int = 0         # number of detection outcomes observed
    last_verdict: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drone_id": self.drone_id,
            "value": round(self.value, 6),
            "source": self.source,
            "updated_at": self.updated_at,
            "sample_count": self.sample_count,
            "last_verdict": self.last_verdict,
        }


@dataclass
class PayoffMatrix:
    """Defender and attacker payoff matrices for the Stackelberg game."""
    defender_strategies: List[str]
    attacker_actions: List[str]
    U_d: List[List[float]]
    U_a: List[List[float]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "defender_strategies": list(self.defender_strategies),
            "attacker_actions": list(self.attacker_actions),
            "U_d": self.U_d,
            "U_a": self.U_a,
        }


@dataclass
class EquilibriumResult:
    """Pure-strategy Stackelberg equilibrium chosen by the solver."""
    defender_strategy: str
    attacker_action: str
    defender_index: int
    attacker_index: int
    U_d_eq: float
    U_a_eq: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "defender_strategy": self.defender_strategy,
            "attacker_action": self.attacker_action,
            "defender_index": self.defender_index,
            "attacker_index": self.attacker_index,
            "U_d_eq": round(self.U_d_eq, 6),
            "U_a_eq": round(self.U_a_eq, 6),
        }


@dataclass
class InspectionDecision:
    """Inspection-depth decision derived from T_S."""
    level: str                    # InspectionLevel value
    route: List[str]              # e.g. ["signature", "ml", "sandbox"]
    threshold_low: float
    threshold_high: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "route": list(self.route),
            "threshold_low": round(self.threshold_low, 6),
            "threshold_high": round(self.threshold_high, 6),
        }


@dataclass
class ThreatEstimate:
    """
    Output of estimating a single ingest submission.

    Consumers downstream (Multi-Layer Malware Detection Engine, Metadata
    Sanitizer, Response Manager) use `threat_score` and
    `inspection.level` to route the submission and pick sanitization
    aggressiveness.
    """

    # Identity ----------------------------------------------------------
    estimate_id: str
    drone_id: str
    ingest_id: Optional[str] = None
    mission_zone: Optional[str] = None
    file_type: Optional[str] = None

    # Reputation --------------------------------------------------------
    reputation: float = 0.0
    reputation_source: str = ReputationSource.DEFAULT.value
    bayesian_trace: Optional[BayesianTrace] = None

    # Intermediate game-theoretic values --------------------------------
    I_base: float = 0.0
    I_prime: float = 0.0
    DSR_prime: Dict[str, float] = field(default_factory=dict)
    payoffs: Optional[PayoffMatrix] = None
    equilibrium: Optional[EquilibriumResult] = None

    # Final outputs -----------------------------------------------------
    raw_attacker_advantage: float = 0.0     # U_a_eq - U_d_eq
    T_raw: float = 0.0                      # sigmoid-normalized raw
    threat_score: float = 0.0               # T_S ∈ [0, 1]
    inspection: Optional[InspectionDecision] = None

    # Audit -------------------------------------------------------------
    created_at: str = field(default_factory=_utc_now_iso)
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self, include_matrices: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "estimate_id": self.estimate_id,
            "drone_id": self.drone_id,
            "ingest_id": self.ingest_id,
            "mission_zone": self.mission_zone,
            "file_type": self.file_type,
            "reputation": round(self.reputation, 6),
            "reputation_source": self.reputation_source,
            "I_base": round(self.I_base, 6),
            "I_prime": round(self.I_prime, 6),
            "raw_attacker_advantage": round(self.raw_attacker_advantage, 6),
            "T_raw": round(self.T_raw, 6),
            "threat_score": round(self.threat_score, 6),
            "created_at": self.created_at,
            "warnings": list(self.warnings),
        }
        if self.bayesian_trace is not None:
            d["bayesian_trace"] = self.bayesian_trace.to_dict()
        if self.equilibrium is not None:
            d["equilibrium"] = self.equilibrium.to_dict()
        if self.inspection is not None:
            d["inspection"] = self.inspection.to_dict()
        if include_matrices:
            d["DSR_prime"] = {k: round(v, 6) for k, v in self.DSR_prime.items()}
            if self.payoffs is not None:
                d["payoffs"] = self.payoffs.to_dict()
            if self.config_snapshot:
                d["config_snapshot"] = self.config_snapshot
        return d


@dataclass
class BatchThreatEstimate:
    """Aggregated output for a batch of ingest submissions."""
    estimates: List[ThreatEstimate] = field(default_factory=list)
    total_processed: int = 0
    total_errors: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_processing_time_ms: float = 0.0

    def to_dict(self, include_matrices: bool = False) -> Dict[str, Any]:
        return {
            "summary": {
                "total_processed": self.total_processed,
                "total_errors": self.total_errors,
                "total_high": self.total_high,
                "total_medium": self.total_medium,
                "total_low": self.total_low,
                "total_processing_time_ms": round(self.total_processing_time_ms, 2),
            },
            "estimates": [e.to_dict(include_matrices=include_matrices) for e in self.estimates],
        }


@dataclass
class DetectionOutcome:
    """
    Post-inspection feedback returned by the Malware Detection Engine.

    Consumed by `GameTheoreticThreatEstimator.record_outcome()` to update
    the drone's reputation and aggregate statistics for the feedback loop.
    """
    drone_id: str
    verdict: str                       # DetectionVerdict value
    source: str = "unknown"            # "signature" | "ml" | "sandbox" | "triage"
    estimate_id: Optional[str] = None
    artifact_id: Optional[str] = None
    observed_at: str = field(default_factory=_utc_now_iso)
    confidence: Optional[float] = None  # detector's self-reported confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drone_id": self.drone_id,
            "verdict": self.verdict,
            "source": self.source,
            "estimate_id": self.estimate_id,
            "artifact_id": self.artifact_id,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
        }


@dataclass
class FeedbackMetrics:
    """Detection metrics aggregated over a monitoring window."""
    fpr: float = 0.0
    fnr: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    window_size: int = 0
    computed_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fpr": round(self.fpr, 6),
            "fnr": round(self.fnr, 6),
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "window_size": self.window_size,
            "computed_at": self.computed_at,
        }


def new_estimate_id() -> str:
    return _generate_id("est_", 12)
