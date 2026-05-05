"""
Adaptive threshold manager for T_S inspection-level routing.

Implements the soft-update rule from the 8 April plan (see
Game_theoretic_threat_estimator_v3.ipynb §8). Live FPR / FNR feedback
drives θ_low and θ_high toward the operating point that meets target
detection objectives without oscillation.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Tuple

from .config import EstimatorConfig
from .models import InspectionDecision, InspectionLevel

logger = logging.getLogger(__name__)


class AdaptiveThresholdManager:
    """
    Live-tunable θ_low / θ_high for inspection-level routing.

    Update rule (per §8.3):

        θ_high_new = θ_high_old + η(FPR - FPR_target) - η(FNR - FNR_target)
        θ_low_new  = θ_low_old  + η(FPR - FPR_target) - η(FNR - FNR_target)

    and then the values are clamped to the safe bounds defined in
    `EstimatorConfig`. A non-zero `min_gap` keeps θ_high - θ_low from
    collapsing to zero under aggressive updates.

    When `adaptive_thresholds` is disabled in config, `update()` becomes
    a no-op and thresholds remain at their configured defaults.
    """

    # Inspection routes per level (shared across all estimates)
    ROUTES = {
        InspectionLevel.LOW.value:    ["signature"],
        InspectionLevel.MEDIUM.value: ["signature", "ml"],
        InspectionLevel.HIGH.value:   ["signature", "ml", "sandbox"],
    }

    def __init__(self, config: EstimatorConfig):
        self.config = config
        self.th_low: float = config.th_low
        self.th_high: float = config.th_high
        self.history: List[dict] = []
        self._update_count = 0

    # ── Public API ────────────────────────────────────────────────────
    def update(self, fpr: float, fnr: float) -> Tuple[float, float]:
        """Soft-update θ_low and θ_high from observed FPR / FNR."""
        if not self.config.adaptive_thresholds:
            logger.debug("adaptive_thresholds=False; update is a no-op")
            return self.th_low, self.th_high

        eta = self.config.eta
        fpr_err = fpr - self.config.FPR_target
        fnr_err = fnr - self.config.FNR_target

        self.th_high = self.th_high + eta * fpr_err - eta * fnr_err
        self.th_low  = self.th_low  + eta * fpr_err - eta * fnr_err

        self._clamp()
        self._update_count += 1
        self.history.append({
            "fpr": fpr, "fnr": fnr,
            "th_low": self.th_low, "th_high": self.th_high,
        })
        logger.info(
            "thresholds updated: FPR=%.4f FNR=%.4f -> th_low=%.4f th_high=%.4f",
            fpr, fnr, self.th_low, self.th_high,
        )
        return self.th_low, self.th_high

    def classify(self, T_S: float) -> InspectionDecision:
        """Map a threat score to an inspection decision using live thresholds."""
        if T_S < self.th_low:
            level = InspectionLevel.LOW.value
        elif T_S < self.th_high:
            level = InspectionLevel.MEDIUM.value
        else:
            level = InspectionLevel.HIGH.value
        return InspectionDecision(
            level=level,
            route=list(self.ROUTES[level]),
            threshold_low=self.th_low,
            threshold_high=self.th_high,
        )

    def reset(self) -> None:
        """Reset to configured defaults. Preserves history for audit."""
        self.th_low = self.config.th_low
        self.th_high = self.config.th_high

    @property
    def stats(self) -> dict:
        return {
            "th_low": round(self.th_low, 6),
            "th_high": round(self.th_high, 6),
            "update_count": self._update_count,
            "adaptive_enabled": self.config.adaptive_thresholds,
            "FPR_target": self.config.FPR_target,
            "FNR_target": self.config.FNR_target,
        }

    # ── Internal ──────────────────────────────────────────────────────
    def _clamp(self) -> None:
        c = self.config
        self.th_low  = max(c.threshold_low_min,  min(c.threshold_low_max,  self.th_low))
        self.th_high = max(c.threshold_high_min, min(c.threshold_high_max, self.th_high))
        if (self.th_high - self.th_low) < c.threshold_min_gap:
            self.th_high = min(c.threshold_high_max, self.th_low + c.threshold_min_gap)
