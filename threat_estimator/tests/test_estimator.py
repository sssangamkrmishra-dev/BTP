"""
Tests for the Game-Theoretic Threat Estimator.

Run with:
    python -m unittest threat_estimator.tests.test_estimator -v
or:
    python -m pytest threat_estimator/tests/ -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from threat_estimator import (
    AdaptiveThresholdManager,
    BayesianReputationEstimator,
    DetectionOutcome,
    EstimatorConfig,
    FeedbackLoop,
    GameTheoreticThreatEstimator,
    InMemoryReputationStore,
    InspectionLevel,
    ReputationProfile,
    ReputationSource,
    build_payoff_matrices,
    compute_DSR_primes,
    compute_I_prime,
    compute_threat_score,
    solve_stackelberg_pure,
    update_reputation,
)


# ── Fixtures ────────────────────────────────────────────────────────

def _sample_ingest_a():
    """Normal video+image feed, trusted zone."""
    return {
        "ingest_metadata": {
            "ingest_id": "ingest_9f1a2b3c4d",
            "drone_id": "DRN-001",
            "mission_zone": "zone-a",
            "insecure_flags": [],
            "auth_result": "ok",
        },
        "artifact_records": [
            {"artifact_id": "artifact://a3f8", "filename": "v.mp4",
             "type": "video", "mime": "video/mp4", "size_bytes": 4_500_000,
             "encryption": False, "container": False, "security_flags": []},
            {"artifact_id": "artifact://b4c5", "filename": "i.jpg",
             "type": "image", "mime": "image/jpeg", "size_bytes": 320_000,
             "encryption": False, "container": False, "security_flags": []},
        ],
    }


def _sample_ingest_b():
    """Encrypted nested archive, suspicious-looking."""
    return {
        "ingest_metadata": {
            "ingest_id": "ingest_c7d6e5f4a3",
            "drone_id": "DRN-002",
            "mission_zone": "zone-c",
            "insecure_flags": ["encrypted_payload", "nested_archive"],
            "auth_result": "unknown",
        },
        "artifact_records": [
            {"artifact_id": "artifact://c1d2", "filename": "p.zip",
             "type": "archive", "mime": "application/zip", "size_bytes": 4_200_000,
             "encryption": True, "container": True, "security_flags": []},
        ],
    }


def _sample_ingest_highrisk():
    """Encrypted ZIP in risky zone with failed auth — should route High."""
    return {
        "ingest_metadata": {
            "ingest_id": "ingest_high_999",
            "drone_id": "DRN-999",
            "mission_zone": "zone-3",
            "insecure_flags": ["encrypted_payload", "nested_archive", "large_binary"],
            "auth_result": "fail",
            "notes": "critical mission, unverified source, encrypted nested archive payload",
        },
        "artifact_records": [
            {"artifact_id": "artifact://risk1", "filename": "bundle.zip",
             "type": "archive", "mime": "application/zip", "size_bytes": 18_000_000,
             "encryption": True, "container": True, "security_flags": []},
        ],
    }


# ── 1. Config ───────────────────────────────────────────────────────

class TestEstimatorConfig(unittest.TestCase):

    def test_defaults(self):
        cfg = EstimatorConfig()
        self.assertEqual(cfg.alpha, 0.5)
        self.assertEqual(cfg.beta, 0.3)
        self.assertEqual(cfg.th_low, 0.40)
        self.assertEqual(cfg.th_high, 0.70)
        self.assertTrue(cfg.adaptive_thresholds)
        self.assertEqual(cfg.prior_benign, 0.85)

    def test_DSR_costs_sandbox_most_expensive(self):
        cfg = EstimatorConfig()
        self.assertLess(cfg.C_d["signature"], cfg.C_d["ml"])
        self.assertLess(cfg.C_d["ml"], cfg.C_d["sandbox"])
        self.assertLess(cfg.DSR_base["signature"], cfg.DSR_base["ml"])
        self.assertLess(cfg.DSR_base["ml"], cfg.DSR_base["sandbox"])

    def test_override(self):
        cfg = EstimatorConfig(alpha=0.9, adaptive_thresholds=False)
        self.assertEqual(cfg.alpha, 0.9)
        self.assertFalse(cfg.adaptive_thresholds)

    def test_post_init_rejects_inconsistent_dsr(self):
        with self.assertRaises(ValueError):
            EstimatorConfig(defender_strategies=("signature", "ml", "sandbox", "deep"))

    def test_post_init_rejects_inverted_thresholds(self):
        with self.assertRaises(ValueError):
            EstimatorConfig(th_low=0.8, th_high=0.5)

    def test_post_init_rejects_bad_prior(self):
        with self.assertRaises(ValueError):
            EstimatorConfig(prior_benign=0.0)
        with self.assertRaises(ValueError):
            EstimatorConfig(prior_benign=1.0)

    def test_post_init_rejects_out_of_range_rates(self):
        with self.assertRaises(ValueError):
            EstimatorConfig(reward_rate=1.5)
        with self.assertRaises(ValueError):
            EstimatorConfig(penalty_rate=-0.1)
        with self.assertRaises(ValueError):
            EstimatorConfig(eta=-0.1)

    def test_post_init_rejects_zero_cache_size(self):
        with self.assertRaises(ValueError):
            EstimatorConfig(estimate_cache_max_size=0)


# ── 2. Bayesian ─────────────────────────────────────────────────────

class TestBayesianReputation(unittest.TestCase):

    def test_plan_worked_example(self):
        """Plan example: prior=0.85, zone-3, ZIP -> R ≈ 0.257."""
        est = BayesianReputationEstimator(prior_benign=0.85)
        trace = est.compute_initial_reputation("zone-3", "zip")
        self.assertAlmostEqual(trace.R, 0.257, places=3)
        self.assertAlmostEqual(trace.numerator, 0.00816, places=5)
        self.assertAlmostEqual(trace.denominator, 0.031785, places=5)
        self.assertFalse(trace.used_fallback_zone)
        self.assertFalse(trace.used_fallback_file)

    def test_posterior_in_unit_interval(self):
        est = BayesianReputationEstimator()
        for zone in ("zone-1", "zone-2", "zone-3", "zone-4"):
            for ftype in ("video", "image", "zip", "telemetry"):
                trace = est.compute_initial_reputation(zone, ftype)
                self.assertGreaterEqual(trace.R, 0.0)
                self.assertLessEqual(trace.R, 1.0)

    def test_unknown_labels_use_fallback(self):
        est = BayesianReputationEstimator()
        trace = est.compute_initial_reputation("zone-unmapped", "unknown-type")
        self.assertTrue(trace.used_fallback_zone)
        self.assertTrue(trace.used_fallback_file)
        self.assertGreater(trace.R, 0.0)

    def test_invalid_prior_rejected(self):
        with self.assertRaises(ValueError):
            BayesianReputationEstimator(prior_benign=0.0)
        with self.assertRaises(ValueError):
            BayesianReputationEstimator(prior_benign=1.0)

    def test_benign_zone_raises_R(self):
        """Same file type, safer zone ⇒ higher reputation."""
        est = BayesianReputationEstimator()
        safe = est.compute_initial_reputation("zone-1", "image")
        risky = est.compute_initial_reputation("zone-3", "image")
        self.assertGreater(safe.R, risky.R)

    def test_update_cpts(self):
        est = BayesianReputationEstimator(prior_benign=0.85)
        est.update_cpts(prior_benign=0.5)
        self.assertEqual(est.P_N, 0.5)
        self.assertEqual(est.P_A, 0.5)


class TestReputationUpdate(unittest.TestCase):

    def test_benign_reward_monotone(self):
        r = 0.3
        for _ in range(50):
            r2 = update_reputation(r, "benign")
            self.assertGreater(r2, r)
            r = r2
        self.assertLess(r, 1.0)

    def test_malicious_penalty_monotone(self):
        r = 0.8
        for _ in range(10):
            r2 = update_reputation(r, "malicious")
            self.assertLess(r2, r)
            r = r2
        self.assertGreaterEqual(r, 0.0)

    def test_unknown_verdict_no_change(self):
        self.assertEqual(update_reputation(0.5, "unknown"), 0.5)
        self.assertEqual(update_reputation(0.5, "quarantined"), 0.5)

    def test_asymmetry(self):
        """Default penalty (0.5) is much larger than default reward (0.05)."""
        r_after_reward  = update_reputation(0.5, "benign")
        r_after_penalty = update_reputation(0.5, "malicious")
        reward_delta  = r_after_reward - 0.5
        penalty_delta = 0.5 - r_after_penalty
        self.assertGreater(penalty_delta, reward_delta * 5)


# ── 3. Stackelberg primitives ──────────────────────────────────────

class TestStackelbergPrimitives(unittest.TestCase):

    def test_I_prime_worked_example(self):
        # v3 notebook §2.1 example: I_base=8, R=0.4, Z=0.6 → I' ≈ 12.272
        I_prime = compute_I_prime(I_base=8.0, reputation=0.4, zone_risk=0.6)
        self.assertAlmostEqual(I_prime, 12.272, places=3)

    def test_DSR_prime_degrades_with_history(self):
        base = {"signature": 0.7, "ml": 0.85, "sandbox": 0.95}
        low = compute_DSR_primes(base, history=0.0)
        high = compute_DSR_primes(base, history=0.5)
        for s in base:
            self.assertGreaterEqual(low[s], high[s])
            self.assertGreater(low[s], 0.0)
            self.assertLess(low[s], 1.0)

    def test_payoffs_shape_and_signs(self):
        DSR_prime = {"signature": 0.672, "ml": 0.833, "sandbox": 0.938}
        pm = build_payoff_matrices(
            I_prime=12.272,
            DSR_prime=DSR_prime,
            C_d={"signature": 1.0, "ml": 3.0, "sandbox": 6.0},
            C_a={"inject": 2.0, "no_inject": 0.0},
            defender_strategies=("signature", "ml", "sandbox"),
            attacker_actions=("inject", "no_inject"),
        )
        self.assertEqual(len(pm.U_d), 3)
        self.assertEqual(len(pm.U_a), 3)
        # conservative rule: no_inject → U_d = -C_d, U_a = 0
        self.assertEqual(pm.U_a[0][1], 0.0)
        self.assertEqual(pm.U_d[0][1], -1.0)
        self.assertEqual(pm.U_d[2][1], -6.0)

    def test_stackelberg_picks_sandbox_for_high_impact(self):
        """When I' is huge, defender should pick sandbox (highest DSR)."""
        cfg = EstimatorConfig()
        DSR_prime = compute_DSR_primes(cfg.DSR_base, history=0.0)
        pm = build_payoff_matrices(
            I_prime=100.0, DSR_prime=DSR_prime,
            C_d=cfg.C_d, C_a=cfg.C_a,
            defender_strategies=cfg.defender_strategies,
            attacker_actions=cfg.attacker_actions,
        )
        eq = solve_stackelberg_pure(pm, C_d=cfg.C_d)
        self.assertEqual(eq.defender_strategy, "sandbox")
        # Attacker will still inject — the very high impact makes it worth it
        self.assertEqual(eq.attacker_action, "inject")

    def test_threat_score_bounded(self):
        """T_S must stay in [0, 1] for any inputs."""
        for u_a, u_d, R in [(5, -5, 0.0), (-5, 5, 1.0), (0, 0, 0.5), (100, -100, 0.0)]:
            raw, T_raw, T_S = compute_threat_score(u_a, u_d, R)
            self.assertGreaterEqual(T_S, 0.0)
            self.assertLessEqual(T_S, 1.0)


# ── 4. Adaptive thresholds ─────────────────────────────────────────

class TestAdaptiveThresholds(unittest.TestCase):

    def test_high_fpr_raises_thresholds(self):
        mgr = AdaptiveThresholdManager(EstimatorConfig())
        low0, high0 = mgr.th_low, mgr.th_high
        mgr.update(fpr=0.20, fnr=0.03)
        self.assertGreater(mgr.th_high, high0)
        self.assertGreater(mgr.th_low, low0)

    def test_high_fnr_lowers_thresholds(self):
        mgr = AdaptiveThresholdManager(EstimatorConfig())
        low0, high0 = mgr.th_low, mgr.th_high
        mgr.update(fpr=0.05, fnr=0.20)
        self.assertLess(mgr.th_high, high0)
        self.assertLess(mgr.th_low, low0)

    def test_clamped_to_safe_bounds(self):
        mgr = AdaptiveThresholdManager(EstimatorConfig())
        for _ in range(200):
            mgr.update(fpr=0.99, fnr=0.0)
        self.assertLessEqual(mgr.th_high, 0.85)
        self.assertLessEqual(mgr.th_low, 0.50)
        self.assertGreaterEqual(mgr.th_high - mgr.th_low, 0.10 - 1e-9)

    def test_disabled_when_adaptive_false(self):
        cfg = EstimatorConfig(adaptive_thresholds=False)
        mgr = AdaptiveThresholdManager(cfg)
        low0, high0 = mgr.th_low, mgr.th_high
        mgr.update(fpr=0.99, fnr=0.99)
        self.assertEqual(mgr.th_low, low0)
        self.assertEqual(mgr.th_high, high0)

    def test_classify_boundaries(self):
        mgr = AdaptiveThresholdManager(EstimatorConfig())
        self.assertEqual(mgr.classify(0.0).level, "Low")
        self.assertEqual(mgr.classify(0.5).level, "Medium")
        self.assertEqual(mgr.classify(0.9).level, "High")
        # High route must include sandbox
        self.assertIn("sandbox", mgr.classify(0.9).route)


# ── 5. Reputation store ─────────────────────────────────────────────

class TestReputationStore(unittest.TestCase):

    def test_put_get_delete(self):
        store = InMemoryReputationStore()
        profile = ReputationProfile(
            drone_id="DRN-X", value=0.7,
            source=ReputationSource.HISTORY.value,
        )
        store.put(profile)
        self.assertIn("DRN-X", store)
        self.assertEqual(store.get("DRN-X").value, 0.7)
        self.assertTrue(store.delete("DRN-X"))
        self.assertNotIn("DRN-X", store)
        self.assertFalse(store.delete("DRN-X"))

    def test_initial_dict_seed(self):
        store = InMemoryReputationStore(initial={"DRN-1": 0.9, "DRN-2": 0.3})
        self.assertEqual(store.get("DRN-1").value, 0.9)
        self.assertEqual(store.get("DRN-2").value, 0.3)
        self.assertEqual(len(store), 2)

    def test_get_returns_copy_not_reference(self):
        store = InMemoryReputationStore(initial={"DRN-1": 0.9})
        p = store.get("DRN-1")
        p.value = 0.01
        self.assertEqual(store.get("DRN-1").value, 0.9)

    def test_out_of_range_rejected(self):
        store = InMemoryReputationStore()
        with self.assertRaises(ValueError):
            store.put(ReputationProfile(drone_id="x", value=1.5, source="history"))


# ── 6. End-to-end estimator ────────────────────────────────────────

class TestEndToEnd(unittest.TestCase):

    def test_normal_submission_is_low(self):
        est = GameTheoreticThreatEstimator(EstimatorConfig())
        sample = _sample_ingest_a()
        out = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        self.assertEqual(out.drone_id, "DRN-001")
        self.assertEqual(out.reputation_source, ReputationSource.BAYESIAN_PRIOR.value)
        self.assertEqual(out.inspection.level, "Low")
        self.assertGreaterEqual(out.threat_score, 0.0)
        self.assertLessEqual(out.threat_score, 1.0)

    def test_estimate_from_ingest_result_dict(self):
        est = GameTheoreticThreatEstimator(EstimatorConfig())
        ir = {
            "ingest_metadata": _sample_ingest_a()["ingest_metadata"],
            "artifact_records": _sample_ingest_a()["artifact_records"],
        }
        out = est.estimate_from_ingest_result(ir)
        self.assertIsNotNone(out.equilibrium)
        self.assertIsNotNone(out.inspection)

    def test_errored_ingest_rejected(self):
        est = GameTheoreticThreatEstimator(EstimatorConfig())
        with self.assertRaises(ValueError):
            est.estimate_from_ingest_result({"error": True, "errors": ["bad"]})

    def test_reputation_upstream_overrides_bayes(self):
        est = GameTheoreticThreatEstimator(EstimatorConfig())
        sample = _sample_ingest_a()
        sample["ingest_metadata"]["reputation"] = 0.25
        out = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        self.assertEqual(out.reputation_source, ReputationSource.PROVIDED.value)
        self.assertEqual(out.reputation, 0.25)
        self.assertIsNone(out.bayesian_trace)

    def test_history_wins_over_bayes(self):
        store = InMemoryReputationStore(initial={"DRN-002": 0.95})
        est = GameTheoreticThreatEstimator(reputation_store=store)
        sample = _sample_ingest_b()
        out = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        self.assertEqual(out.reputation_source, ReputationSource.HISTORY.value)
        self.assertEqual(out.reputation, 0.95)

    def test_cold_start_uses_bayesian_prior(self):
        est = GameTheoreticThreatEstimator()
        sample = _sample_ingest_b()  # zone-c + archive
        out = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        self.assertEqual(out.reputation_source, ReputationSource.BAYESIAN_PRIOR.value)
        self.assertIsNotNone(out.bayesian_trace)
        # zone-c mirrors zone-3; archive mirrors zip → R ≈ 0.257
        self.assertAlmostEqual(out.reputation, 0.257, places=3)

    def test_flag_bumps_increase_impact(self):
        est = GameTheoreticThreatEstimator()
        # Use a small telemetry artifact so we do not hit the I_base ceiling.
        small = {
            "ingest_metadata": {
                "ingest_id": "ig1", "drone_id": "DRN-X",
                "mission_zone": "zone-a",
                "insecure_flags": [], "auth_result": "ok",
            },
            "artifact_records": [{"artifact_id": "x", "filename": "t.json",
                "type": "telemetry", "mime": "application/json",
                "size_bytes": 1500, "encryption": False, "container": False,
                "security_flags": []}],
        }
        out_clean = est.estimate(small["ingest_metadata"], small["artifact_records"])
        bumped = {
            "ingest_metadata": {**small["ingest_metadata"],
                                "auth_result": "fail",
                                "insecure_flags": ["encrypted_payload"]},
            "artifact_records": small["artifact_records"],
        }
        out_bumped = est.estimate(bumped["ingest_metadata"], bumped["artifact_records"])
        self.assertGreater(out_bumped.I_base, out_clean.I_base)

    def test_record_outcome_moves_reputation(self):
        est = GameTheoreticThreatEstimator()
        sample = _sample_ingest_a()
        first = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        prior_R = first.reputation

        out = DetectionOutcome(drone_id="DRN-001", verdict="malicious", source="sandbox",
                               estimate_id=first.estimate_id)
        updated = est.record_outcome(out)
        self.assertLess(updated.value, prior_R)
        self.assertEqual(updated.sample_count, 1)

        # Second estimate should now pull from history
        second = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        self.assertEqual(second.reputation_source, ReputationSource.HISTORY.value)
        self.assertAlmostEqual(second.reputation, updated.value, places=6)

    def test_feedback_loop_drives_threshold_update(self):
        est = GameTheoreticThreatEstimator()

        # Seed enough outcomes for non-trivial metrics.
        sample = _sample_ingest_highrisk()
        for i in range(20):
            md = dict(sample["ingest_metadata"])
            md["drone_id"] = f"DRN-{i:03d}"
            est.estimate(md, sample["artifact_records"])
            verdict = "benign" if i % 4 else "malicious"
            est.record_outcome(DetectionOutcome(
                drone_id=md["drone_id"], verdict=verdict, source="sandbox",
            ))

        low0, high0 = est.thresholds.th_low, est.thresholds.th_high
        est.update_thresholds_from_feedback()
        # After feedback we may drift in either direction, but thresholds
        # must remain within their clamped bounds.
        self.assertGreaterEqual(est.thresholds.th_low,  0.20)
        self.assertLessEqual(   est.thresholds.th_low,  0.50)
        self.assertGreaterEqual(est.thresholds.th_high, 0.55)
        self.assertLessEqual(   est.thresholds.th_high, 0.85)

    def test_stats_tracks_counts(self):
        est = GameTheoreticThreatEstimator()
        for sample in (_sample_ingest_a(), _sample_ingest_b(), _sample_ingest_highrisk()):
            est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        s = est.stats
        self.assertEqual(s["total_processed"], 3)
        self.assertIsNotNone(s["last_estimate_id"])

    def test_to_dict_is_serializable(self):
        import json
        est = GameTheoreticThreatEstimator()
        sample = _sample_ingest_b()
        out = est.estimate(sample["ingest_metadata"], sample["artifact_records"])
        payload = out.to_dict(include_matrices=True)
        # Round-trip through json to catch unserializable types.
        json.dumps(payload)
        self.assertIn("bayesian_trace", payload)
        self.assertIn("payoffs", payload)

    def test_last_estimate_cache_is_bounded(self):
        """Long-running deployments must not leak per-drone estimate state."""
        cfg = EstimatorConfig(estimate_cache_max_size=4)
        est = GameTheoreticThreatEstimator(cfg)
        sample = _sample_ingest_a()
        for i in range(20):
            md = dict(sample["ingest_metadata"])
            md["drone_id"] = f"DRN-{i:03d}"
            est.estimate(md, sample["artifact_records"])
        self.assertLessEqual(len(est._last_estimate_by_drone), 4)

    def test_batch(self):
        est = GameTheoreticThreatEstimator()
        subs = [
            (_sample_ingest_a()["ingest_metadata"], _sample_ingest_a()["artifact_records"]),
            (_sample_ingest_b()["ingest_metadata"], _sample_ingest_b()["artifact_records"]),
            (_sample_ingest_highrisk()["ingest_metadata"],
             _sample_ingest_highrisk()["artifact_records"]),
        ]
        batch = est.estimate_batch(subs)
        self.assertEqual(batch.total_processed, 3)
        self.assertEqual(len(batch.estimates), 3)


# ── 7. Feedback loop ───────────────────────────────────────────────

class TestFeedbackLoop(unittest.TestCase):

    def test_metrics_on_empty_is_zero(self):
        fb = FeedbackLoop()
        m = fb.compute_metrics()
        self.assertEqual(m.fpr, 0.0)
        self.assertEqual(m.fnr, 0.0)

    def test_tp_fp_tn_fn_accounting(self):
        fb = FeedbackLoop()
        # 2 TP (High + malicious) ; 1 FP (High + benign)
        fb.observe(DetectionOutcome(drone_id="a", verdict="malicious", source="sandbox"), "High")
        fb.observe(DetectionOutcome(drone_id="a", verdict="malicious", source="sandbox"), "Medium")
        fb.observe(DetectionOutcome(drone_id="a", verdict="benign",    source="sandbox"), "High")
        # 1 TN (Low + benign) ; 1 FN (Low + malicious)
        fb.observe(DetectionOutcome(drone_id="a", verdict="benign",    source="signature"), "Low")
        fb.observe(DetectionOutcome(drone_id="a", verdict="malicious", source="signature"), "Low")
        m = fb.compute_metrics()
        self.assertEqual(m.true_positives,  2)
        self.assertEqual(m.false_positives, 1)
        self.assertEqual(m.true_negatives,  1)
        self.assertEqual(m.false_negatives, 1)
        self.assertAlmostEqual(m.fpr, 1 / (1 + 1), places=6)
        self.assertAlmostEqual(m.fnr, 1 / (1 + 2), places=6)

    def test_window_respected(self):
        fb = FeedbackLoop(window_size=3)
        for _ in range(5):
            fb.observe(DetectionOutcome(drone_id="a", verdict="benign", source="x"), "Low")
        self.assertEqual(len(fb), 3)


if __name__ == "__main__":
    unittest.main()
