# Game-Theoretic Threat Estimator

Scores each drone/RPA ingestion submission with a dynamic **Threat
Score** $T_S \in [0, 1]$ and routes it to **Low / Medium / High**
inspection depth. Combines a Stackelberg defender-vs-attacker game
with a Bayesian cold-start prior and an adaptive-threshold feedback
loop.

Pipeline position:

```
Ingestion Interceptor  →  **Threat Estimator**  →  Malware Detection Engine
                                               ↘  Metadata Sanitizer
                                               ↘  Response & Quarantine Manager
```

## Requirements

- Python ≥ 3.10 (uses `|` type unions, `dataclass` defaults).
- No third-party dependencies — stdlib only.

## Quick Start

### 1. As a library

```python
from threat_estimator import GameTheoreticThreatEstimator, EstimatorConfig

estimator = GameTheoreticThreatEstimator(EstimatorConfig())

# IngestResult from the Ingestion Interceptor:
ingest_result = interceptor.process(drone_json).to_dict()

estimate = estimator.estimate_from_ingest_result(ingest_result)
print(estimate.threat_score, estimate.inspection.level)  # e.g. 0.074, "Low"
```

### 2. With an explicit reputation store & feedback

```python
from threat_estimator import (
    GameTheoreticThreatEstimator, EstimatorConfig,
    InMemoryReputationStore, DetectionOutcome,
)

store = InMemoryReputationStore(initial={"DRN-001": 0.9})
estimator = GameTheoreticThreatEstimator(
    config=EstimatorConfig(),
    reputation_store=store,   # swap for a Redis/Postgres-backed subclass
)

estimate = estimator.estimate(ingest_metadata, artifact_records)

# After the Malware Detection Engine returns a verdict:
estimator.record_outcome(DetectionOutcome(
    drone_id=estimate.drone_id,
    verdict="malicious",
    source="sandbox",
    estimate_id=estimate.estimate_id,
))

# Periodically, from a monitoring loop:
estimator.update_thresholds_from_feedback()
```

### 3. Standalone demo

```bash
python -m threat_estimator.run_demo
```

Runs four stages: the plan's Bayesian worked example (R ≈ 0.257),
end-to-end estimation on five sample ingestions, a full verdict →
reputation/threshold feedback cycle, and synthetic threshold drift
under FPR/FNR windows.

## Running the Test Suite

```bash
python -m unittest threat_estimator.tests.test_estimator -v
# or
python -m pytest threat_estimator/tests/ -v
```

48 tests covering:

- config defaults, overrides, and `__post_init__` validation rejections
- Bayesian posterior math (incl. the reference worked example)
- reward/penalty reputation update
- `I'` / `DSR'` / payoff-matrix / Stackelberg equilibrium properties
- adaptive-threshold clamping and FPR/FNR response
- reputation-store get/put/delete
- end-to-end estimation on sample ingestions
- feedback-loop FPR/FNR accounting
- bounded LRU cache for `record_outcome` seeding

## Module Layout

```
threat_estimator/
├── __init__.py             # public API re-exports
├── config.py               # EstimatorConfig dataclass (all tunables)
├── models.py               # dataclasses: ThreatEstimate, BayesianTrace, …
├── bayesian.py             # BayesianReputationEstimator + default CPTs
├── stackelberg.py          # I', DSR', payoffs, Stackelberg solver, T_S map
├── adaptive.py             # AdaptiveThresholdManager (soft-update rule)
├── reputation_store.py     # InMemoryReputationStore (swap for production backend)
├── feedback.py             # FeedbackLoop rolling-window FPR/FNR aggregator
├── estimator.py            # GameTheoreticThreatEstimator orchestrator
├── run_demo.py             # standalone demo
├── tests/
│   └── test_estimator.py   # 48 stdlib-unittest tests
└── README.md               # this file
```

## Key Configuration Knobs

| Knob | Default | Meaning |
| :--- | :---: | :--- |
| `alpha` | 0.5 | Reputation weight on adjusted impact $I'$ |
| `beta` | 0.3 | Zone-risk weight on $I'$ |
| `gamma` | 0.2 | History weight on detection success rate |
| `kappa` | 0.8 | Sigmoid scale on raw utility gap |
| `lambda_blend` | 0.9 | Model-vs-reputation blend in $T_S$ |
| `th_low` / `th_high` | 0.40 / 0.70 | Initial inspection-level cut-offs |
| `adaptive_thresholds` | True | Enable soft-update rule on θ |
| `FPR_target` / `FNR_target` | 0.05 / 0.03 | Detection objectives driving the update rule |
| `eta` | 0.10 | Learning rate for threshold soft-update |
| `prior_benign` | 0.85 | $P(N)$ in the Bayesian cold-start prior |
| `reward_rate` | 0.05 | Reputation reward per benign verdict |
| `penalty_rate` | 0.50 | Reputation penalty per malicious verdict (asymmetric) |
| `default_reputation` | 0.80 | Fallback when no history and Bayes fails |
| `DSR_base` | {sig 0.70, ml 0.85, sandbox 0.95} | Base detection success rates |
| `C_d` | {sig 1, ml 3, sandbox 6} | Defender inspection costs |
| `C_a` | {inject 2, no_inject 0} | Attacker action costs |

## Integration Seams

The module exposes four pluggable seams — production backends are
wired in by the host process via constructor DI:

| Seam | Reference implementation | Production backend |
| :--- | :--- | :--- |
| `reputation_store` | `InMemoryReputationStore` | Redis / Postgres / RocksDB subclass that overrides `get` / `put` / `delete` / `list_drones` |
| `feedback_loop` | `FeedbackLoop` (in-process rolling window) | Subclass that subscribes to the Response & Quarantine Manager / SIEM |
| `BayesianReputationEstimator.zone_likelihood` / `file_likelihood` | Seed CPTs matching the reference worked example | Periodic `update_cpts()` refresh driven by a learning job |
| History / Threat-Intel inputs to `estimate()` | `history=0.0`, `threat_intel=0.0` | Wired from a rolling infection tracker and a Threat Intelligence Correlator |

## Operational Stats

`GameTheoreticThreatEstimator.stats` is a live dict:

```python
{
  "total_processed": 327,
  "total_errors":    0,
  "total_low":       210,
  "total_medium":     82,
  "total_high":       35,
  "total_cold_start": 41,
  "total_history_hit": 286,
  "total_outcomes_recorded": 318,
  "last_estimate_id": "est_9a1b2c3d4e5f",
  "thresholds": {
    "th_low": 0.418, "th_high": 0.721,
    "update_count": 12,
    "adaptive_enabled": True,
    "FPR_target": 0.05, "FNR_target": 0.03,
  },
  "reputation_store_size": 102,
  "feedback_window_size": 500,
}
```

Monitor:
- `total_high / total_processed` — sandbox load.
- `thresholds.th_high` drift — evidence of regime change.
- `total_cold_start / total_processed` — how often the Bayesian prior
  is invoked (useful for reputation-DB sizing).

## Troubleshooting

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| All estimates come back `Low` | `I_base` maxing out below threshold is normal for benign feeds. If you see it on risky ones, check `flag_impact_bumps` and `zone_risk_lookup`. | Tune bumps in config; or supply `zone_risk` in IngestMetadata. |
| Every drone treated cold-start | `reputation_store` is empty and host never calls `record_outcome`. | Wire the Response & Quarantine Manager to call `record_outcome` after every verdict. |
| Thresholds drifted to their clamps | FPR or FNR chronically off-target. | Retrain CPTs and/or re-calibrate `FPR_target`/`FNR_target`; inspect `feedback.snapshot()`. |
| `ValueError: cannot estimate on an errored IngestResult` | Ingestion Interceptor rejected the submission. | Fix the upstream errors; do not bypass validation. |
| Reputation collapses too fast under noisy verdicts | `penalty_rate` too large for your detector accuracy. | Lower `penalty_rate` or require corroborating verdict sources before calling `record_outcome`. |

## See Also

- `docs/design_threat_estimator.md` — detailed design document.
- `Game_theoretic_threat_estimator_v3.ipynb` — the research notebook
  this module productionises (Steps 1–5 + §6–§9 Bayesian/adaptive
  extensions).
- `ingestion_interceptor/` — upstream module supplying `IngestResult`.
- `metadata_sanitizer/` — downstream module consuming `threat_score`
  for mode selection.
