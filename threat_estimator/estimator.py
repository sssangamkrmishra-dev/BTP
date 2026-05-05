"""
Main Game-Theoretic Threat Estimator orchestrator.

Ties together Bayesian cold-start reputation, Stackelberg payoff
construction & solving, threat-score computation, and adaptive
inspection-level routing. Consumes the output of the Ingestion
Interceptor and emits a `ThreatEstimate` used by every downstream
module (Multi-Layer Malware Detection Engine, Metadata Sanitizer,
Threat Intelligence Correlator, Response & Quarantine Manager).
"""

import logging
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from .adaptive import AdaptiveThresholdManager
from .bayesian import BayesianReputationEstimator, update_reputation
from .config import EstimatorConfig
from .feedback import FeedbackLoop
from .models import (
    BatchThreatEstimate,
    BayesianTrace,
    DetectionOutcome,
    InspectionDecision,
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
    solve_stackelberg_pure,
)

logger = logging.getLogger(__name__)


# Priority order used when a submission contains multiple artifact types.
_FILE_TYPE_PRIORITY = ("zip", "archive", "video", "image", "pdf", "audio", "telemetry", "text")


class GameTheoreticThreatEstimator:
    """
    Core threat estimator for drone/RPA ingestion records.

    Pipeline position:
        Ingestion Interceptor → **Game-Theoretic Threat Estimator**
            → Multi-Layer Malware Detection Engine → Metadata Sanitizer
            → Threat Intelligence Correlator → Response & Quarantine Manager

    Inputs:
        ingest_metadata : dict
            `IngestMetadata.to_dict()` payload from the Ingestion
            Interceptor (contains drone_id, mission_zone, insecure_flags,
            auth_result, optionally reputation / zone_risk).
        artifact_records : list[dict]
            `ArtifactRecord.to_dict()` payloads.

    Outputs:
        ThreatEstimate — per-submission decision carrying the threat
        score, inspection level, and full audit trail.

    Integration points (see design doc §3 for detail):
      - reputation_store   : dict-backed by default; swap for Redis/Postgres.
      - feedback_loop      : in-process; host can subclass to bridge to
                             an analyst-review pipeline or SIEM.
      - bayesian_estimator : CPTs are seed values; update via
                             `BayesianReputationEstimator.update_cpts()` from
                             the Security Feedback Loop.
      - threshold_manager  : theta_low / theta_high auto-adapt from
                             `update_thresholds_from_feedback()`.

    Thread-safety:
      The injected `reputation_store` and `feedback_loop` implementations
      are thread-safe. The orchestrator's own counters and LRU cache are
      not protected by a lock — a single `GameTheoreticThreatEstimator`
      instance is expected to be invoked from one request-handling thread
      at a time, matching the pattern of the sibling modules. Host
      processes that fan out across threads should instantiate one
      estimator per worker and share only the underlying stores.
    """

    # ── Construction ──────────────────────────────────────────────────
    def __init__(
        self,
        config: Optional[EstimatorConfig] = None,
        reputation_store: Optional[InMemoryReputationStore] = None,
        bayesian_estimator: Optional[BayesianReputationEstimator] = None,
        threshold_manager: Optional[AdaptiveThresholdManager] = None,
        feedback_loop: Optional[FeedbackLoop] = None,
    ):
        self.config = config or EstimatorConfig()
        self._setup_logging()

        self.reputation_store = reputation_store or InMemoryReputationStore()
        self.bayesian = bayesian_estimator or BayesianReputationEstimator(
            prior_benign=self.config.prior_benign
        )
        self.thresholds = threshold_manager or AdaptiveThresholdManager(self.config)
        self.feedback = feedback_loop or FeedbackLoop()

        self._stats = {
            "total_processed": 0,
            "total_errors": 0,
            "total_low": 0,
            "total_medium": 0,
            "total_high": 0,
            "total_cold_start": 0,
            "total_history_hit": 0,
            "total_outcomes_recorded": 0,
            "last_estimate_id": None,
        }

        # Bounded-LRU cache of the last ThreatEstimate per drone so
        # record_outcome() can (a) back-fill the inspection level used
        # when the estimate was made, and (b) seed the reputation update
        # from the Bayesian prior for cold-start drones.
        self._last_estimate_by_drone: "OrderedDict[str, ThreatEstimate]" = OrderedDict()

    def _setup_logging(self) -> None:
        """Configure the package logger level only; do not install handlers."""
        package_logger = logging.getLogger("threat_estimator")
        level = getattr(logging, self.config.log_level, logging.INFO)
        package_logger.setLevel(level)

    # ── Public API ────────────────────────────────────────────────────
    def estimate(
        self,
        ingest_metadata: Dict[str, Any],
        artifact_records: List[Dict[str, Any]],
        history: float = 0.0,
        threat_intel: float = 0.0,
    ) -> ThreatEstimate:
        """
        Score a single ingestion submission.

        Args:
            ingest_metadata: `IngestMetadata.to_dict()` payload from the
                Ingestion Interceptor.
            artifact_records: `ArtifactRecord.to_dict()` payloads for this
                submission.
            history: recent infection frequency H ∈ [0, 1] for this drone
                or zone. In production, pull from the Security Feedback
                Loop; 0.0 is a safe default.
            threat_intel: threat-intel corroboration strength TI ∈ [0, 1].
                Zero until a Threat Intelligence Correlator feed is wired.

        Returns:
            ThreatEstimate with full audit trail (Bayesian trace, payoff
            matrices, equilibrium, T_S, inspection decision).
        """
        cfg = self.config
        warnings: List[str] = []

        drone_id = ingest_metadata.get("drone_id", "UNKNOWN")
        ingest_id = ingest_metadata.get("ingest_id")
        mission_zone = ingest_metadata.get("mission_zone") or "unknown"
        file_type = self._dominant_file_type(artifact_records)

        # 1) Resolve reputation R ---------------------------------------
        R, R_source, bayes_trace = self._resolve_reputation(
            drone_id=drone_id,
            zone=mission_zone,
            file_type=file_type,
            ingest_metadata=ingest_metadata,
        )

        # 2) Resolve zone risk Z ----------------------------------------
        Z = self._resolve_zone_risk(mission_zone, ingest_metadata)

        # 3) Base impact (heuristic) + flag bumps -----------------------
        I_base = self._compute_I_base(artifact_records, ingest_metadata, warnings)
        I_base = self._apply_flag_bumps(I_base, ingest_metadata)
        I_base = max(cfg.I_base_min, min(cfg.I_base_max, I_base))

        # 4) Adjusted impact & DSR' -------------------------------------
        I_prime = compute_I_prime(
            I_base=I_base, reputation=R, zone_risk=Z,
            alpha=cfg.alpha, beta=cfg.beta,
        )
        DSR_prime = compute_DSR_primes(
            DSR_base=cfg.DSR_base,
            history=history,
            threat_intel=threat_intel,
            gamma=cfg.gamma, delta=cfg.delta, eps=cfg.eps,
        )

        # 5) Payoffs + Stackelberg equilibrium -------------------------
        payoffs = build_payoff_matrices(
            I_prime=I_prime, DSR_prime=DSR_prime,
            C_d=cfg.C_d, C_a=cfg.C_a,
            defender_strategies=cfg.defender_strategies,
            attacker_actions=cfg.attacker_actions,
        )
        equilibrium = solve_stackelberg_pure(payoffs, C_d=cfg.C_d)

        # 6) Threat score T_S -------------------------------------------
        raw, T_raw, T_S = compute_threat_score(
            U_a_eq=equilibrium.U_a_eq,
            U_d_eq=equilibrium.U_d_eq,
            reputation=R,
            kappa=cfg.kappa,
            lambda_blend=cfg.lambda_blend,
        )

        # 7) Inspection level via adaptive thresholds -------------------
        inspection = self.thresholds.classify(T_S)

        # 8) Assemble result -------------------------------------------
        estimate = ThreatEstimate(
            estimate_id=new_estimate_id(),
            drone_id=drone_id,
            ingest_id=ingest_id,
            mission_zone=mission_zone,
            file_type=file_type,
            reputation=R,
            reputation_source=R_source,
            bayesian_trace=bayes_trace,
            I_base=I_base,
            I_prime=I_prime,
            DSR_prime=DSR_prime,
            payoffs=payoffs,
            equilibrium=equilibrium,
            raw_attacker_advantage=raw,
            T_raw=T_raw,
            threat_score=T_S,
            inspection=inspection,
            config_snapshot=self._config_snapshot(),
            warnings=warnings,
        )

        self._update_stats(estimate, R_source)
        self._cache_last_estimate(drone_id, estimate)
        return estimate

    def estimate_from_ingest_result(
        self,
        ingest_result: Dict[str, Any],
        **kwargs: Any,
    ) -> ThreatEstimate:
        """
        Convenience wrapper that accepts an `IngestResult.to_dict()` dict
        directly from the Ingestion Interceptor.
        """
        if not isinstance(ingest_result, dict):
            raise TypeError("ingest_result must be a dict")
        if ingest_result.get("error"):
            raise ValueError("cannot estimate on an errored IngestResult")
        return self.estimate(
            ingest_metadata=ingest_result.get("ingest_metadata", {}),
            artifact_records=ingest_result.get("artifact_records", []),
            **kwargs,
        )

    def estimate_batch(
        self,
        submissions: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
    ) -> BatchThreatEstimate:
        """Score many submissions and aggregate per-level counts."""
        batch = BatchThreatEstimate()
        start = time.time()
        for md, artifacts in submissions:
            try:
                est = self.estimate(md, artifacts)
                batch.estimates.append(est)
                batch.total_processed += 1
                lvl = est.inspection.level if est.inspection else "Low"
                if lvl == "High":
                    batch.total_high += 1
                elif lvl == "Medium":
                    batch.total_medium += 1
                else:
                    batch.total_low += 1
            except Exception:
                logger.exception("batch item failed: drone=%s", md.get("drone_id"))
                batch.total_errors += 1
        batch.total_processing_time_ms = (time.time() - start) * 1000.0
        return batch

    # ── Feedback-loop API ─────────────────────────────────────────────
    def record_outcome(self, outcome: DetectionOutcome) -> ReputationProfile:
        """
        Consume a `DetectionOutcome` from the Malware Detection Engine.

        Applies the asymmetric reward/penalty update to reputation and
        feeds the pair `(inspection_level, verdict)` into the
        `FeedbackLoop` so rolling FPR / FNR stay current.

        Returns the updated `ReputationProfile`.
        """
        drone_id = outcome.drone_id
        existing = self.reputation_store.get(drone_id)
        last = self._last_estimate_by_drone.get(drone_id)

        # Seed the update from (in priority order):
        #   1. a previously-stored reputation (history)
        #   2. the Bayesian / provided R from the most recent estimate,
        #      so a cold-start drone's first verdict moves *from the prior*,
        #      not from the generic config default
        #   3. the config default (true first-contact case)
        if existing is not None:
            current = existing.value
        elif last is not None:
            current = last.reputation
        else:
            current = self.config.default_reputation

        new_value = update_reputation(
            current=current,
            verdict=outcome.verdict,
            reward_rate=self.config.reward_rate,
            penalty_rate=self.config.penalty_rate,
        )

        profile = ReputationProfile(
            drone_id=drone_id,
            value=new_value,
            source=ReputationSource.HISTORY.value,
            sample_count=(existing.sample_count + 1) if existing else 1,
            last_verdict=outcome.verdict,
        )
        self.reputation_store.put(profile)

        # Pair the outcome with the last estimate's inspection level so
        # the feedback loop can classify it for FPR/FNR accounting.
        last = self._last_estimate_by_drone.get(drone_id)
        level = last.inspection.level if (last and last.inspection) else "Low"
        self.feedback.observe(outcome, inspection_level=level)

        self._stats["total_outcomes_recorded"] += 1
        logger.info(
            "outcome recorded: drone=%s verdict=%s level=%s R %.4f -> %.4f",
            drone_id, outcome.verdict, level, current, new_value,
        )
        return profile

    def update_thresholds_from_feedback(self) -> Tuple[float, float]:
        """
        Pull fresh FPR / FNR from the feedback loop and soft-update the
        adaptive thresholds. Intended to be invoked periodically by the
        host's monitoring loop.
        """
        metrics = self.feedback.compute_metrics()
        return self.thresholds.update(metrics.fpr, metrics.fnr)

    def update_thresholds(self, fpr: float, fnr: float) -> Tuple[float, float]:
        """Direct pass-through for hosts that compute metrics externally."""
        return self.thresholds.update(fpr, fnr)

    # ── Introspection ────────────────────────────────────────────────
    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "thresholds": self.thresholds.stats,
            "reputation_store_size": len(self.reputation_store),
            "feedback_window_size": len(self.feedback),
        }

    # ── Internal helpers ──────────────────────────────────────────────
    def _resolve_reputation(
        self,
        drone_id: str,
        zone: str,
        file_type: str,
        ingest_metadata: Dict[str, Any],
    ) -> Tuple[float, str, Optional[BayesianTrace]]:
        """
        Priority:
          1. Reputation already carried in IngestMetadata (if present).
          2. Stored reputation (history).
          3. Bayesian cold-start prior on (zone, file_type).
          4. Config-level default (last resort).
        """
        upstream_rep = ingest_metadata.get("reputation")
        if upstream_rep is not None:
            try:
                value = float(upstream_rep)
                if 0.0 <= value <= 1.0:
                    return value, ReputationSource.PROVIDED.value, None
            except (TypeError, ValueError):
                pass  # fall through

        existing = self.reputation_store.get(drone_id)
        if existing is not None:
            return existing.value, ReputationSource.HISTORY.value, None

        # Cold start — Bayesian posterior.
        try:
            trace = self.bayesian.compute_initial_reputation(zone, file_type)
            return trace.R, ReputationSource.BAYESIAN_PRIOR.value, trace
        except Exception:
            logger.exception("bayesian prior failed; falling back to config default")
            return (
                self.config.default_reputation,
                ReputationSource.DEFAULT.value,
                None,
            )

    def _resolve_zone_risk(self, mission_zone: str, ingest_metadata: Dict[str, Any]) -> float:
        upstream = ingest_metadata.get("zone_risk")
        if upstream is not None:
            try:
                value = float(upstream)
                if 0.0 <= value <= 1.0:
                    return value
            except (TypeError, ValueError):
                pass
        cfg_lookup = self.config.zone_risk_lookup
        if mission_zone in cfg_lookup:
            return float(cfg_lookup[mission_zone])
        return self.config.default_zone_risk

    def _compute_I_base(
        self,
        artifact_records: List[Dict[str, Any]],
        ingest_metadata: Dict[str, Any],
        warnings: List[str],
    ) -> float:
        if not artifact_records:
            warnings.append("no_artifact_records")
            return 3.0  # neutral starting point

        sizes = [int(a.get("size_bytes", 0)) for a in artifact_records]
        avg_size_mb = (sum(sizes) / len(sizes)) / 1_000_000.0 if sizes else 0.0

        risks = [
            self.config.type_risk.get((a.get("type") or "other").lower(), 0.4)
            for a in artifact_records
        ]
        type_risk = max(risks) if risks else 0.2

        mission_sens = self._mission_sensitivity_bump(ingest_metadata)
        return 3.0 + (avg_size_mb * 3.0) + (type_risk * 3.0) + mission_sens

    @staticmethod
    def _mission_sensitivity_bump(ingest_metadata: Dict[str, Any]) -> float:
        md = ingest_metadata.get("additional_metadata") or {}
        candidate = (
            md.get("mission_sensitivity")
            or md.get("mission_sensitivity_level")
            or ingest_metadata.get("notes", "")
        )
        if not candidate:
            return 0.0
        text = str(candidate).lower()
        if "crit" in text:
            return 2.0
        if "high" in text:
            return 1.5
        if "med" in text:
            return 1.0
        return 0.0

    def _apply_flag_bumps(self, I_base: float, ingest_metadata: Dict[str, Any]) -> float:
        bumps = self.config.flag_impact_bumps
        flags = ingest_metadata.get("insecure_flags") or []
        auth_result = ingest_metadata.get("auth_result")

        for flag in flags:
            I_base += bumps.get(flag, 0.0)
        if auth_result in self.config.unsafe_auth_results:
            I_base += bumps.get("auth_failed", 0.0)
        return I_base

    @staticmethod
    def _dominant_file_type(artifact_records: List[Dict[str, Any]]) -> str:
        if not artifact_records:
            return "other"
        present = {(a.get("type") or "other").lower() for a in artifact_records}
        for t in _FILE_TYPE_PRIORITY:
            if t in present:
                return t
        return next(iter(present))

    def _cache_last_estimate(self, drone_id: str, estimate: ThreatEstimate) -> None:
        """Insert into the LRU and evict the oldest entry if over-capacity."""
        cache = self._last_estimate_by_drone
        if drone_id in cache:
            cache.move_to_end(drone_id)
        cache[drone_id] = estimate
        max_size = self.config.estimate_cache_max_size
        while len(cache) > max_size:
            cache.popitem(last=False)

    def _update_stats(self, estimate: ThreatEstimate, R_source: str) -> None:
        self._stats["total_processed"] += 1
        self._stats["last_estimate_id"] = estimate.estimate_id
        level = estimate.inspection.level if estimate.inspection else "Low"
        if level == "High":
            self._stats["total_high"] += 1
        elif level == "Medium":
            self._stats["total_medium"] += 1
        else:
            self._stats["total_low"] += 1
        if R_source == ReputationSource.BAYESIAN_PRIOR.value:
            self._stats["total_cold_start"] += 1
        elif R_source == ReputationSource.HISTORY.value:
            self._stats["total_history_hit"] += 1

    def _config_snapshot(self) -> Dict[str, Any]:
        """Compact snapshot of the tunables used — for forensic replay."""
        c = self.config
        return {
            "alpha": c.alpha, "beta": c.beta, "gamma": c.gamma, "delta": c.delta,
            "kappa": c.kappa, "lambda_blend": c.lambda_blend,
            "prior_benign": c.prior_benign,
            "th_low_live": self.thresholds.th_low,
            "th_high_live": self.thresholds.th_high,
            "adaptive_thresholds": c.adaptive_thresholds,
        }
