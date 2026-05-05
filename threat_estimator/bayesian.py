"""
Bayesian Belief Network for cold-start reputation calculation.

Implements the posterior R = P(Benign | Zone, FileType) described in
the 8 April plan and reproduced in Game_theoretic_threat_estimator_v3.ipynb §7.
Used when a drone has no history in the ReputationStore.
"""

import logging
from dataclasses import dataclass
from typing import Dict, Optional

from .models import BayesianTrace

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Default Conditional Probability Tables (CPTs)
#
# These are seed values. In production, the Security Feedback Loop
# should replace them with values learned from detection outcomes.
# Values are P(evidence | attack_status); each row is independent, so
# they do not need to sum to 1 across zones or file types — the BBN
# posterior normalises via its denominator.
# ──────────────────────────────────────────────────────────────────────

DEFAULT_ZONE_LIKELIHOOD: Dict[str, Dict[str, float]] = {
    # numeric zones (from the plan's worked example)
    "zone-1": {"N": 0.35, "A": 0.10},
    "zone-2": {"N": 0.28, "A": 0.15},
    "zone-3": {"N": 0.12, "A": 0.35},   # worked-example zone
    "zone-4": {"N": 0.15, "A": 0.25},
    "zone-x": {"N": 0.10, "A": 0.15},
    # named zones (used by the ingestion-interceptor sample fixtures)
    "zone-a": {"N": 0.35, "A": 0.10},
    "zone-b": {"N": 0.28, "A": 0.15},
    "zone-c": {"N": 0.12, "A": 0.35},
}

DEFAULT_FILE_LIKELIHOOD: Dict[str, Dict[str, float]] = {
    "video":     {"N": 0.40, "A": 0.10},
    "image":     {"N": 0.30, "A": 0.10},
    "telemetry": {"N": 0.15, "A": 0.05},
    "text":      {"N": 0.07, "A": 0.30},
    "zip":       {"N": 0.08, "A": 0.45},   # worked-example file type
    "archive":   {"N": 0.08, "A": 0.45},
    "pdf":       {"N": 0.10, "A": 0.20},
    "audio":     {"N": 0.25, "A": 0.10},
}

# Pessimistic fallbacks for labels not present in the CPT.
UNKNOWN_ZONE_LIKELIHOOD: Dict[str, float] = {"N": 0.10, "A": 0.20}
UNKNOWN_FILE_LIKELIHOOD: Dict[str, float] = {"N": 0.15, "A": 0.25}


class BayesianReputationEstimator:
    """
    Computes an initial reputation R = P(Benign | Zone, FileType) for
    drones with no prior history (cold start).

    The CPTs passed in at construction time are used as-is. In production
    the host should periodically refresh them from the Security Feedback
    Loop. The `update_cpts()` helper offers a simple in-place refresh.
    """

    def __init__(
        self,
        prior_benign: float = 0.85,
        zone_likelihood: Optional[Dict[str, Dict[str, float]]] = None,
        file_likelihood: Optional[Dict[str, Dict[str, float]]] = None,
    ):
        if not 0.0 < prior_benign < 1.0:
            raise ValueError(f"prior_benign must be in (0, 1); got {prior_benign}")

        self.P_N = prior_benign
        self.P_A = 1.0 - prior_benign
        self.zone_likelihood: Dict[str, Dict[str, float]] = (
            dict(zone_likelihood) if zone_likelihood is not None
            else dict(DEFAULT_ZONE_LIKELIHOOD)
        )
        self.file_likelihood: Dict[str, Dict[str, float]] = (
            dict(file_likelihood) if file_likelihood is not None
            else dict(DEFAULT_FILE_LIKELIHOOD)
        )

    # ── CPT accessors ─────────────────────────────────────────────────
    def _get_zone(self, zone: str):
        key = (zone or "").lower()
        if key in self.zone_likelihood:
            return self.zone_likelihood[key], False
        return dict(UNKNOWN_ZONE_LIKELIHOOD), True

    def _get_file(self, file_type: str):
        key = (file_type or "").lower()
        if key in self.file_likelihood:
            return self.file_likelihood[key], False
        return dict(UNKNOWN_FILE_LIKELIHOOD), True

    # ── Public API ────────────────────────────────────────────────────
    def compute_initial_reputation(self, zone: str, file_type: str) -> BayesianTrace:
        """
        Evaluate P(Benign | zone, file_type) via Bayes' rule.

        The posterior formula is:

            R = [P(N)·P(Z|N)·P(F|N)] /
                {[P(N)·P(Z|N)·P(F|N)] + [P(A)·P(Z|A)·P(F|A)]}

        Returns a `BayesianTrace` containing every intermediate value for
        full auditability.
        """
        z, zone_fb = self._get_zone(zone)
        f, file_fb = self._get_file(file_type)

        num = self.P_N * z["N"] * f["N"]
        den = num + (self.P_A * z["A"] * f["A"])
        R = (num / den) if den > 0.0 else self.P_N

        return BayesianTrace(
            zone=zone or "",
            file_type=file_type or "",
            P_N=self.P_N, P_A=self.P_A,
            P_Z_given_N=z["N"], P_Z_given_A=z["A"],
            P_F_given_N=f["N"], P_F_given_A=f["A"],
            numerator=num, denominator=den,
            R=R,
            used_fallback_zone=zone_fb,
            used_fallback_file=file_fb,
        )

    # ── CPT management (feedback-loop hooks) ──────────────────────────
    def update_cpts(
        self,
        zone_likelihood: Optional[Dict[str, Dict[str, float]]] = None,
        file_likelihood: Optional[Dict[str, Dict[str, float]]] = None,
        prior_benign: Optional[float] = None,
    ) -> None:
        """Refresh the CPTs in-place. Typically invoked by the feedback loop."""
        if zone_likelihood is not None:
            self.zone_likelihood = dict(zone_likelihood)
        if file_likelihood is not None:
            self.file_likelihood = dict(file_likelihood)
        if prior_benign is not None:
            if not 0.0 < prior_benign < 1.0:
                raise ValueError(f"prior_benign must be in (0, 1); got {prior_benign}")
            self.P_N = prior_benign
            self.P_A = 1.0 - prior_benign


def update_reputation(
    current: float,
    verdict: str,
    reward_rate: float = 0.05,
    penalty_rate: float = 0.50,
) -> float:
    """
    Asymmetric reputation update driven by detection-engine verdicts.

        R_new = clip(R + η_+ (1 - R), 0, 1)    if verdict == "benign"
              = clip(R - η_- R,       0, 1)    if verdict == "malicious"
              = R                              otherwise

    Defaults: reward 0.05, penalty 0.50 — a single infection costs as
    much as ten clean deliveries.
    """
    if verdict == "benign":
        new = current + reward_rate * (1.0 - current)
    elif verdict == "malicious":
        new = current - penalty_rate * current
    else:
        new = current
    return max(0.0, min(1.0, new))
