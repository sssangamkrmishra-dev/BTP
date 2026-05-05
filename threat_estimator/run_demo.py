"""
Standalone demo for the Game-Theoretic Threat Estimator.

Shows:
    1. Cold-start Bayesian reputation (the 8 April plan example).
    2. End-to-end estimation on five ingestion-interceptor-style payloads.
    3. Feedback loop: detection verdicts update reputation and thresholds.
    4. Threshold drift under live FPR / FNR.

Run:
    python -m threat_estimator.run_demo
"""

import json
import logging
import random
from pprint import pprint

from threat_estimator import (
    BayesianReputationEstimator,
    DetectionOutcome,
    EstimatorConfig,
    GameTheoreticThreatEstimator,
    InMemoryReputationStore,
)


# ── Fixtures — mirror the ingestion_interceptor output shape ───────

SAMPLE_A = {
    "ingest_metadata": {
        "ingest_id": "ingest_9f1a2b3c4d",
        "drone_id": "DRN-001",
        "timestamp": "2025-10-13T03:00:12Z",
        "mission_zone": "zone-a",
        "insecure_flags": [],
        "auth_result": "ok",
        "notes": "normal video+image feed",
    },
    "artifact_records": [
        {"artifact_id": "artifact://a3f8", "filename": "drn001_fpv_001.mp4",
         "type": "video", "mime": "video/mp4", "size_bytes": 4_500_000,
         "encryption": False, "container": False, "security_flags": []},
        {"artifact_id": "artifact://b4c5", "filename": "drn001_cam_001.jpg",
         "type": "image", "mime": "image/jpeg", "size_bytes": 320_000,
         "encryption": False, "container": False, "security_flags": []},
    ],
}

SAMPLE_B = {
    "ingest_metadata": {
        "ingest_id": "ingest_c7d6e5f4a3",
        "drone_id": "DRN-002",
        "timestamp": "2025-10-13T03:05:45Z",
        "mission_zone": "zone-c",
        "insecure_flags": ["encrypted_payload", "nested_archive"],
        "auth_result": "unknown",
        "notes": "encrypted ZIP with nested contents",
    },
    "artifact_records": [
        {"artifact_id": "artifact://c1d2", "filename": "payload_bundle.zip",
         "type": "archive", "mime": "application/zip", "size_bytes": 4_200_000,
         "encryption": True, "container": True, "security_flags": []},
        {"artifact_id": "artifact://d7e8", "filename": "notes.txt",
         "type": "text", "mime": "text/plain", "size_bytes": 2048,
         "encryption": False, "container": False, "security_flags": []},
    ],
}

SAMPLE_C = {
    "ingest_metadata": {
        "ingest_id": "ingest_e8f7g6h5i4",
        "drone_id": "DRN-003",
        "timestamp": "2025-10-13T03:10:03Z",
        "mission_zone": "zone-b",
        "insecure_flags": [],
        "auth_result": "ok",
        "notes": "telemetry-only — low risk",
    },
    "artifact_records": [
        {"artifact_id": "artifact://e9f0", "filename": "telemetry_snapshot.json",
         "type": "telemetry", "mime": "application/json", "size_bytes": 1500,
         "encryption": False, "container": False, "security_flags": []},
    ],
}

SAMPLE_D = {
    "ingest_metadata": {
        "ingest_id": "ingest_f1e2d3c4b5",
        "drone_id": "DRN-004",
        "timestamp": "2025-10-13T03:15:22Z",
        "mission_zone": "zone-a",
        "insecure_flags": [],
        "auth_result": "ok",
        "additional_metadata": {"mission_sensitivity": "critical"},
        "notes": "large survey video — mission sensitivity: critical",
    },
    "artifact_records": [
        {"artifact_id": "artifact://f2e3", "filename": "survey.mp4",
         "type": "video", "mime": "video/mp4", "size_bytes": 12_500_000,
         "encryption": False, "container": False, "security_flags": []},
        {"artifact_id": "artifact://g3h4", "filename": "frame.jpg",
         "type": "image", "mime": "image/jpeg", "size_bytes": 550_000,
         "encryption": False, "container": False, "security_flags": []},
    ],
}

SAMPLE_HIGH_RISK = {
    "ingest_metadata": {
        "ingest_id": "ingest_high_999",
        "drone_id": "DRN-999",
        "timestamp": "2025-10-14T04:45:00Z",
        "mission_zone": "zone-3",
        "insecure_flags": ["encrypted_payload", "nested_archive", "large_binary"],
        "auth_result": "fail",
        "notes": "critical mission, unverified source, encrypted nested archive payload",
    },
    "artifact_records": [
        {"artifact_id": "artifact://risk001", "filename": "payload_secure_bundle.zip",
         "type": "archive", "mime": "application/zip", "size_bytes": 18_000_000,
         "encryption": True, "container": True, "security_flags": []},
    ],
}


ALL_SAMPLES = [SAMPLE_A, SAMPLE_B, SAMPLE_C, SAMPLE_D, SAMPLE_HIGH_RISK]


# ── Demo stages ─────────────────────────────────────────────────────

def _hr(title: str) -> None:
    print(f"\n{'─' * 78}\n{title}\n{'─' * 78}")


def stage_bayesian_example() -> None:
    _hr("Stage 1 — Bayesian cold-start posterior (8 April plan example)")
    bayes = BayesianReputationEstimator(prior_benign=0.85)
    trace = bayes.compute_initial_reputation("zone-3", "zip")
    print(f"  P(N)      = {trace.P_N}")
    print(f"  P(Z|N/A)  = {trace.P_Z_given_N} / {trace.P_Z_given_A}")
    print(f"  P(F|N/A)  = {trace.P_F_given_N} / {trace.P_F_given_A}")
    print(f"  numerator = {trace.numerator:.5f}")
    print(f"  denom     = {trace.denominator:.5f}")
    print(f"  → R = {trace.R:.6f}   (expected ≈ 0.257)")


def stage_end_to_end() -> None:
    _hr("Stage 2 — End-to-end estimation on five sample ingestions")
    est = GameTheoreticThreatEstimator(EstimatorConfig())
    header = f"{'drone':8s} {'zone':7s} {'type':10s} {'R':>6s} {'source':>16s} {'T_S':>6s}  inspection"
    print(header)
    print("-" * len(header))
    for s in ALL_SAMPLES:
        result = est.estimate(s["ingest_metadata"], s["artifact_records"])
        print(
            f"{result.drone_id:8s} {result.mission_zone:7s} {result.file_type:10s} "
            f"{result.reputation:>6.3f} {result.reputation_source:>16s} "
            f"{result.threat_score:>6.3f}  {result.inspection.level}"
        )
    print("\nEstimator stats:")
    pprint(est.stats, width=100)


def stage_feedback_loop() -> None:
    _hr("Stage 3 — Feedback loop: verdicts update reputation + thresholds")
    est = GameTheoreticThreatEstimator()

    first = est.estimate(SAMPLE_B["ingest_metadata"], SAMPLE_B["artifact_records"])
    print(f"cold-start estimate for {first.drone_id}:")
    print(f"  R = {first.reputation:.3f}  ({first.reputation_source})")
    print(f"  T_S = {first.threat_score:.3f}  -> {first.inspection.level}")

    verdict = "malicious"
    profile = est.record_outcome(DetectionOutcome(
        drone_id=first.drone_id, verdict=verdict, source="sandbox",
        estimate_id=first.estimate_id,
    ))
    print(f"\nafter '{verdict}' verdict: stored R = {profile.value:.3f} "
          f"(sample_count={profile.sample_count})")

    # Re-estimate — now comes from history.
    second = est.estimate(SAMPLE_B["ingest_metadata"], SAMPLE_B["artifact_records"])
    print(f"\nre-estimate pulls from history:")
    print(f"  R = {second.reputation:.3f}  ({second.reputation_source})")
    print(f"  T_S = {second.threat_score:.3f}  -> {second.inspection.level}")


def stage_threshold_drift() -> None:
    _hr("Stage 4 — Threshold drift under synthetic FPR / FNR windows")
    est = GameTheoreticThreatEstimator()
    random.seed(0)
    print(f"{'window':>6s} {'FPR':>6s} {'FNR':>6s}  ->  th_low   th_high")
    for i in range(1, 8):
        fpr = max(0.02, 0.12 - 0.01 * i + random.uniform(-0.01, 0.01))
        fnr = max(0.01, 0.04 + random.uniform(-0.01, 0.01))
        lo, hi = est.update_thresholds(fpr, fnr)
        print(f"{i:>6d} {fpr:>6.3f} {fnr:>6.3f}  -> {lo:>7.4f}  {hi:>7.4f}")


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    stage_bayesian_example()
    stage_end_to_end()
    stage_feedback_loop()
    stage_threshold_drift()


if __name__ == "__main__":
    main()
