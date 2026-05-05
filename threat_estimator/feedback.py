"""
Feedback-loop aggregator for the threat estimator.

Collects `DetectionOutcome` records from the Multi-Layer Malware
Detection Engine (via the Response & Quarantine Manager), pairs them
with the originating `ThreatEstimate`, and exposes rolling FPR / FNR
metrics that the `AdaptiveThresholdManager` consumes.

Kept intentionally simple: no persistence, no external bus. The host
process is responsible for wiring real feedback sources — see
`GameTheoreticThreatEstimator.record_outcome()` for the integration
hook and the design doc's "Integration Points" section.
"""

import logging
import threading
from collections import deque
from typing import Deque, Dict, List, Optional

from .models import DetectionOutcome, DetectionVerdict, FeedbackMetrics, _utc_now_iso

logger = logging.getLogger(__name__)


class FeedbackLoop:
    """
    Rolling-window aggregator for detection outcomes.

    Tracks the last `window_size` (estimated_level, verdict) pairs so
    FPR / FNR can be computed over a recent window rather than over all
    time. The current inspection level decides whether a given
    outcome counts as a positive (High / Medium inspection was chosen)
    or negative (Low inspection was chosen).

    Caveat: this is a *coarse* approximation — production systems
    typically rely on ground-truth labels from an analyst-review
    pipeline. Plug such a pipeline in by overriding `observe()` in a
    subclass or by calling `update_metrics()` directly with analyst
    numbers from an external source.
    """

    def __init__(self, window_size: int = 500):
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        self._lock = threading.RLock()
        self._window: Deque[Dict] = deque(maxlen=window_size)
        self._cached_metrics: Optional[FeedbackMetrics] = None

    # ── Event ingestion ───────────────────────────────────────────────
    def observe(self, outcome: DetectionOutcome, inspection_level: str) -> None:
        """
        Record a (level, verdict) pair from the detection engine.
        Called by `GameTheoreticThreatEstimator.record_outcome()`.
        """
        with self._lock:
            self._window.append({
                "drone_id": outcome.drone_id,
                "estimate_id": outcome.estimate_id,
                "verdict": outcome.verdict,
                "source": outcome.source,
                "inspection_level": inspection_level,
                "observed_at": outcome.observed_at,
            })
            self._cached_metrics = None  # invalidate cache

    # ── Metrics ───────────────────────────────────────────────────────
    def compute_metrics(self) -> FeedbackMetrics:
        """
        Derive FPR / FNR / precision / recall over the current window.

        Convention (high/medium = positive prediction, low = negative):
          - TP: level ∈ {High, Medium}, verdict = malicious
          - FP: level ∈ {High, Medium}, verdict = benign
          - FN: level = Low,            verdict = malicious
          - TN: level = Low,            verdict = benign
        Outcomes with unknown/quarantined verdicts are ignored.
        """
        with self._lock:
            if self._cached_metrics is not None:
                return self._cached_metrics

            tp = fp = tn = fn = 0
            for rec in self._window:
                verdict = rec["verdict"]
                level = rec["inspection_level"]
                if verdict == DetectionVerdict.MALICIOUS.value:
                    if level in ("High", "Medium"):
                        tp += 1
                    else:
                        fn += 1
                elif verdict == DetectionVerdict.BENIGN.value:
                    if level in ("High", "Medium"):
                        fp += 1
                    else:
                        tn += 1
                # unknown / quarantined verdicts are skipped

            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            metrics = FeedbackMetrics(
                fpr=fpr, fnr=fnr,
                precision=precision, recall=recall,
                true_positives=tp, false_positives=fp,
                true_negatives=tn, false_negatives=fn,
                window_size=len(self._window),
                computed_at=_utc_now_iso(),
            )
            self._cached_metrics = metrics
            return metrics

    # ── Introspection ─────────────────────────────────────────────────
    def __len__(self) -> int:
        with self._lock:
            return len(self._window)

    def clear(self) -> None:
        with self._lock:
            self._window.clear()
            self._cached_metrics = None

    def snapshot(self) -> List[Dict]:
        with self._lock:
            return list(self._window)
