# Design Document: Game-Theoretic Threat Estimator

| Field              | Value                                                                                            |
|--------------------|--------------------------------------------------------------------------------------------------|
| Module             | `threat_estimator/`                                                                              |
| Version            | 1.0                                                                                              |
| Status             | Production                                                                                       |
| Upstream           | `ingestion_interceptor` — produces `IngestResult`                                                |
| Downstream         | Multi-Layer Malware Detection Engine, `metadata_sanitizer`, Response & Quarantine Manager        |
| Research notebook  | `Game_theoretic_threat_estimator_v3.ipynb`                                                       |
| Python version     | 3.10+                                                                                            |
| External deps      | None (standard library only)                                                                     |

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [System Context](#3-system-context)
4. [Architecture Overview](#4-architecture-overview)
5. [Component Design](#5-component-design)
6. [Data Models](#6-data-models)
7. [API Specification](#7-api-specification)
8. [Input / Output Specification](#8-input--output-specification)
9. [Sequence Diagrams](#9-sequence-diagrams)
10. [Mathematical Core](#10-mathematical-core)
11. [Configuration Reference](#11-configuration-reference)
12. [Security & Threat Model](#12-security--threat-model)
13. [Performance Characteristics](#13-performance-characteristics)
14. [Testing Strategy](#14-testing-strategy)
15. [Operations](#15-operations)
16. [Risk Assessment](#16-risk-assessment)
17. [Glossary](#17-glossary)

---

## 1. Executive Summary

The Game-Theoretic Threat Estimator consumes the structured output of
the Ingestion Interceptor and emits a per-submission **Threat Score**
`T_S ∈ [0, 1]` plus a discrete **inspection level** (`Low` /
`Medium` / `High`) that routes the submission to an appropriate subset
of the multi-layer detection stack (Signature → AI/ML → Sandbox).

Three capabilities distinguish this module from a static threshold
classifier:

1. **Stackelberg game model.** The defender is modelled as the leader
   and the attacker as the follower. The module picks the inspection
   strategy that maximises defender utility under the attacker's
   best response, so low-risk feeds skip the sandbox and high-risk
   feeds trigger it automatically.
2. **Bayesian cold-start reputation.** When a drone has no history,
   reputation is computed from observable context (Zone × File Type)
   via a small Bayesian Belief Network, avoiding a dangerous static
   default.
3. **Adaptive thresholds driven by feedback.** `θ_low` and `θ_high`
   are soft-updated from live FPR / FNR metrics so the system
   self-calibrates as attack patterns evolve.

The module depends only on the Python standard library, is fully
deterministic given its inputs, and emits a serialisable audit trail
for every estimate.

## 2. Goals and Non-Goals

### 2.1 Goals

| ID    | Goal                                                                                                       |
|-------|------------------------------------------------------------------------------------------------------------|
| G-1   | Produce a bounded, calibratable Threat Score `T_S ∈ [0, 1]` from the upstream `IngestResult` payload       |
| G-2   | Route every submission to `Low` / `Medium` / `High` inspection with clear, auditable reasoning             |
| G-3   | Solve the cold-start problem using observable context without requiring labelled history                   |
| G-4   | Adapt routing thresholds in response to observed FPR / FNR drift using a bounded soft-update rule          |
| G-5   | Expose dependency seams (reputation store, feedback loop, CPTs) so production backends plug in cleanly     |
| G-6   | Run with only the Python standard library — no ML framework or network dependency                          |
| G-7   | Emit a forensically complete audit record for every estimate (Bayesian trace, payoffs, equilibrium, config)|
| G-8   | Fail closed on inconsistent configuration (validation in `EstimatorConfig.__post_init__`)                  |
| G-9   | Guarantee bounded memory: all internal caches are size-capped by configuration                             |
| G-10  | Maintain processing statistics for operational monitoring (`stats` property)                               |

### 2.2 Non-Goals

| ID     | Non-Goal                                                                                                        |
|--------|-----------------------------------------------------------------------------------------------------------------|
| NG-1   | File-content inspection, AV scanning, AI/ML classification, or sandbox execution — handled by downstream modules|
| NG-2   | Persistent storage of reputation or feedback state — the reference implementation is in-memory                  |
| NG-3   | Wire-level ingestion — assumes the Ingestion Interceptor has already produced an authenticated `IngestResult`   |
| NG-4   | Training of ML classifiers — the Bayesian network uses hand-tunable CPTs, not gradient-learned parameters       |
| NG-5   | Distributed coordination — one estimator instance per edge node; cross-node consistency is not addressed here   |
| NG-6   | Mixed-strategy Stackelberg equilibria — the solver enumerates pure strategies only                              |
| NG-7   | Cryptographic verification of drone identity — fully delegated to the Ingestion Interceptor                     |

---

## 3. System Context

### 3.1 Position in the edge malware detection pipeline

The Threat Estimator sits between ingestion and detection. It converts
metadata + artifact summaries into a routing decision.

```
┌─────────────────────────┐
│ RPA / Drone Data Source │
└───────────┬─────────────┘
            │  payload + metadata
            ▼
┌─────────────────────────┐
│  Ingestion Interceptor  │   authenticates source, validates
└───────────┬─────────────┘   structure, extracts metadata
            │  IngestResult (dict)
            ▼
┌─────────────────────────┐
│   Threat Estimator      │   <<< this module
│  (Stackelberg + Bayes)  │   emits ThreatEstimate
└───────────┬─────────────┘
            │  threat_score + inspection.level + inspection.route
            ▼
┌────────────────────────────────────────────────────────────┐
│         Multi-Layer Malware Detection Engine               │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                │
│  │Signature │   │  AI/ML   │   │ Sandbox  │                │
│  │ Scanner  │──▶│Classifier│──▶│ Executor │  (subset run   │
│  └──────────┘   └──────────┘   └──────────┘   per route)   │
└──────────────────────────┬─────────────────────────────────┘
                           │  verdict
     ┌─────────────────────┼────────────────────┐
     ▼                     ▼                    ▼
┌──────────┐        ┌──────────────┐     ┌──────────────┐
│ Metadata │        │  Threat      │     │ Response &   │
│Sanitizer │        │Intelligence  │     │ Quarantine   │
│          │        │ Correlator   │     │  Manager     │
└──────────┘        └──────────────┘     └──────┬───────┘
                                                │
                              verdict feedback  │
                                                ▼
                            estimator.record_outcome(outcome)
                            estimator.update_thresholds_from_feedback()
```

### 3.2 Integration seams

Four dependencies are injected into `GameTheoreticThreatEstimator` so
host processes can supply production backends without touching the
algorithms:

| Seam                                      | Reference implementation                     | Production backend                                                                   |
|-------------------------------------------|----------------------------------------------|--------------------------------------------------------------------------------------|
| `reputation_store`                        | `InMemoryReputationStore` (thread-safe dict) | Subclass backed by Redis / Postgres / RocksDB; implements the same four-method contract |
| `feedback_loop`                           | `FeedbackLoop` (rolling-window, in-process)  | Subclass that subscribes to Response & Quarantine Manager / SIEM events              |
| `bayesian_estimator.zone_likelihood`, `file_likelihood` | Seed CPTs matching the reference worked example | Periodic refresh via `BayesianReputationEstimator.update_cpts()` from a learning job |
| `estimate(history=, threat_intel=)`       | `0.0` / `0.0`                                | Rolling infection frequency from the Response Manager; IOC corroboration from the Threat Intelligence Correlator |

No network, filesystem, or subprocess calls happen inside this module
by default. All external integration is gated by the constructor.

---

## 4. Architecture Overview

### 4.1 Module layout

```
threat_estimator/
├── __init__.py             # public API re-exports
├── config.py               # EstimatorConfig dataclass + __post_init__ validation
├── models.py               # dataclasses: ThreatEstimate, BayesianTrace, ...
├── bayesian.py             # BayesianReputationEstimator + CPTs + reputation update
├── stackelberg.py          # I', DSR', payoff builder, solver, T_S mapping
├── adaptive.py             # AdaptiveThresholdManager (soft-update rule + clamps)
├── reputation_store.py     # InMemoryReputationStore (thread-safe dict; subclass for prod)
├── feedback.py             # FeedbackLoop (rolling FPR/FNR aggregator)
├── estimator.py            # GameTheoreticThreatEstimator orchestrator
├── run_demo.py             # standalone demo runner
├── tests/
│   └── test_estimator.py   # 48 stdlib-unittest tests
└── README.md
```

### 4.2 Component dependency diagram

```
                             ┌──────────────────────────────────────┐
                             │   GameTheoreticThreatEstimator       │
                             │           (estimator.py)             │
                             └──┬──────┬──────┬──────┬──────────────┘
                                │      │      │      │
               ┌────────────────┘      │      │      └──────────────────┐
               │                       │      │                         │
               ▼                       ▼      ▼                         ▼
   ┌───────────────────────┐  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐
   │ BayesianReputation    │  │  Stackelberg  │  │   Adaptive    │  │ FeedbackLoop │
   │     Estimator         │  │   helpers     │  │  Threshold    │  │ (feedback.py)│
   │    (bayesian.py)      │  │(stackelberg.py)│ │   Manager     │  │              │
   │                       │  │  (functions)  │  │ (adaptive.py) │  │              │
   └───────────────────────┘  └───────────────┘  └───────────────┘  └──────────────┘
                                                                           ▲
                                                                           │ observe()
                                                                           │
                             ┌──────────────────────────────────────┐      │
                             │     InMemoryReputationStore          │      │
                             │       (reputation_store.py)          │      │
                             └──────────────────────────────────────┘      │
                                     ▲                                     │
                                     │ get / put / delete                  │
                                     └─────── GameTheoreticThreatEstimator ┘

   reads EstimatorConfig (config.py)
   returns ThreatEstimate (models.py)
```

### 4.3 Data flow through the pipeline

1. Caller hands an `IngestResult` dict to
   `estimator.estimate_from_ingest_result()`.
2. `_resolve_reputation()` picks `R` from (in priority order) upstream
   metadata, reputation store, Bayesian prior, configured default.
3. `_resolve_zone_risk()` picks `Z` from upstream metadata, configured
   zone lookup, or the default.
4. `_compute_I_base()` folds artifact sizes + per-type risk + mission
   sensitivity, then `_apply_flag_bumps()` adds deltas for every
   insecure flag raised upstream.
5. `compute_I_prime(I_base, R, Z)` and
   `compute_DSR_primes(DSR_base, H, TI)` produce the game inputs.
6. `build_payoff_matrices()` constructs `U_d` and `U_a`;
   `solve_stackelberg_pure()` returns the pure-strategy equilibrium.
7. `compute_threat_score()` maps the equilibrium to `T_S`.
8. `AdaptiveThresholdManager.classify(T_S)` returns the inspection
   decision using the live thresholds.
9. A `ThreatEstimate` is assembled with the full audit trail and
   returned; the last estimate per drone is cached in a bounded LRU so
   `record_outcome()` can correctly classify follow-up verdicts.

---

## 5. Component Design

### 5.1 `EstimatorConfig` (`config.py`)

Single `@dataclass` holding every tunable: impact weights (`alpha`,
`beta`, `gamma`, `delta`), threat-score mapping (`kappa`,
`lambda_blend`), defender / attacker strategy sets, DSR base rates,
defender and attacker costs (`C_d` / `C_a`), adaptive-threshold bounds,
Bayesian prior, asymmetric reward / penalty rates, per-file-type risk
lookup, insecure-flag impact bumps, and the LRU cache bound.

`__post_init__` enforces internal consistency:

- every defender strategy has a matching entry in `DSR_base` and `C_d`,
- every attacker action has a matching entry in `C_a`,
- `0 ≤ th_low < th_high ≤ 1`,
- clamp bounds are ordered (`*_min ≤ *_max`),
- `prior_benign ∈ (0, 1)`, `reward_rate, penalty_rate ∈ [0, 1]`,
- `eta ≥ 0`, `estimate_cache_max_size ≥ 1`.

### 5.2 `BayesianReputationEstimator` (`bayesian.py`)

Implements the posterior `R = P(Benign | Zone, FileType)` with
conditional independence between Zone and File Type given Attack
Status. Ships with seed CPTs (`DEFAULT_ZONE_LIKELIHOOD`,
`DEFAULT_FILE_LIKELIHOOD`) and pessimistic fallbacks for unseen labels.
`update_cpts()` is the refresh hook for online learning.

A module-level `update_reputation(R, verdict, reward_rate, penalty_rate)`
function implements the asymmetric reward / penalty rule used by
`GameTheoreticThreatEstimator.record_outcome()`.

### 5.3 Stackelberg primitives (`stackelberg.py`)

Pure-function layer — no state, no I/O:

- `compute_I_prime(I_base, R, Z)`
- `compute_DSR_primes(DSR_base, H, TI)`
- `build_payoff_matrices(I', DSR', C_d, C_a, S_d, S_a)`
- `solve_stackelberg_pure(payoffs, C_d)` — defender-as-leader,
  pure-strategy enumerator. Attacker breaks ties in the direction that
  hurts the defender; defender breaks ties toward the cheaper strategy.
- `compute_threat_score(U_a_eq, U_d_eq, R)` — sigmoid normalisation +
  reputation blend.

### 5.4 `AdaptiveThresholdManager` (`adaptive.py`)

Owns the live `θ_low` and `θ_high`. `update(fpr, fnr)` applies the
soft-update rule and clamps to the safe bounds declared in the config;
a configurable `threshold_min_gap` stops `θ_high - θ_low` from
collapsing under aggressive updates. `classify(T_S)` returns an
`InspectionDecision` containing the level and an ordered route list
(e.g. `["signature", "ml", "sandbox"]`). Disabling
`adaptive_thresholds` makes `update()` a no-op, which is useful for
deterministic replays and canary comparisons.

### 5.5 `InMemoryReputationStore` (`reputation_store.py`)

Thread-safe dict wrapper over `ReputationProfile`. `get()` returns a
defensive copy so callers cannot mutate stored state. `snapshot()`
serialises the full store for persistence or audit. Production
deployments subclass it and override `get`, `put`, `delete`, and
`list_drones`.

### 5.6 `FeedbackLoop` (`feedback.py`)

Rolling-window (`deque(maxlen=window_size)`) aggregator.
`observe(outcome, inspection_level)` records a (level, verdict) pair.
`compute_metrics()` returns a cached `FeedbackMetrics` with TP / FP /
TN / FN / precision / recall / FPR / FNR over the current window.

Classification convention:

- `High` or `Medium` level × `malicious` verdict → True Positive
- `High` or `Medium` level × `benign` verdict   → False Positive
- `Low` level × `malicious` verdict             → False Negative
- `Low` level × `benign` verdict                → True Negative
- `unknown` / `quarantined` verdicts are skipped

### 5.7 `GameTheoreticThreatEstimator` (`estimator.py`)

Orchestrator; the public API is listed in §7. Internally:

- `_resolve_reputation()` picks `R` from the priority chain in §4.3.
- `_resolve_zone_risk()` does the same for `Z`.
- `_compute_I_base()` + `_apply_flag_bumps()` compute the pre-game
  impact from artifact records and insecure flags.
- `_cache_last_estimate()` writes into the bounded LRU so that
  `record_outcome()` can back-fill the inspection level used when the
  estimate was produced (the feedback loop needs it) and can seed the
  reputation-update step from the Bayesian prior when the store has no
  history for this drone.

Thread-safety: injected stores are thread-safe; the orchestrator
itself is intended to be invoked from one request-handling thread at a
time, matching the pattern of the sibling modules. Host processes that
fan out across threads should instantiate one estimator per worker and
share only the underlying stores.

---

## 6. Data Models

All models are `@dataclass`-based with `to_dict()` methods for
structured logging and wire transport.

### 6.1 `ThreatEstimate` (output)

Returned by every call to `estimate()`. Carries the final score, the
inspection decision, and the complete audit trail.

| Field                    | Type                          | Notes                                                         |
|--------------------------|-------------------------------|---------------------------------------------------------------|
| `estimate_id`            | str                           | Opaque ID, prefix `est_`                                      |
| `drone_id`               | str                           | Propagated from `ingest_metadata.drone_id`                    |
| `ingest_id`              | Optional[str]                 | For cross-module correlation                                  |
| `mission_zone`           | Optional[str]                 |                                                               |
| `file_type`              | Optional[str]                 | Dominant type across artifact records                         |
| `reputation`             | float                         | `R ∈ [0, 1]` actually used for scoring                        |
| `reputation_source`      | str                           | One of `history` / `bayesian_prior` / `provided` / `default`  |
| `bayesian_trace`         | Optional[BayesianTrace]       | Present only when source = `bayesian_prior`                   |
| `I_base`                 | float                         | Pre-game impact after flag bumps, clamped to `[0, 10]`        |
| `I_prime`                | float                         | Adjusted impact used by the game                              |
| `DSR_prime`              | Dict[str, float]              | Detection success rate per defender strategy                  |
| `payoffs`                | Optional[PayoffMatrix]        | `U_d` and `U_a` matrices with strategy labels                 |
| `equilibrium`            | Optional[EquilibriumResult]   | Defender strategy, attacker action, equilibrium utilities     |
| `raw_attacker_advantage` | float                         | `U_a_eq - U_d_eq`                                             |
| `T_raw`                  | float                         | `σ(κ · raw_attacker_advantage)`                               |
| `threat_score`           | float                         | `T_S ∈ [0, 1]`                                                |
| `inspection`             | Optional[InspectionDecision]  | Level + ordered route + live thresholds                       |
| `created_at`             | str (ISO-8601 UTC)            |                                                               |
| `config_snapshot`        | Dict[str, Any]                | Subset of config used for this estimate (for replay)          |
| `warnings`               | List[str]                     |                                                               |

### 6.2 Supporting models

| Model                  | Purpose                                                                               |
|------------------------|---------------------------------------------------------------------------------------|
| `BayesianTrace`        | Priors, per-evidence likelihoods, numerator / denominator, final `R`, fallback flags  |
| `PayoffMatrix`         | Strategy and action labels plus `U_d` / `U_a`                                         |
| `EquilibriumResult`    | Chosen defender strategy, attacker action, equilibrium utilities                      |
| `InspectionDecision`   | Level (`Low` / `Medium` / `High`), ordered route, live thresholds                     |
| `ReputationProfile`    | Stored reputation record: value, source, updated_at, sample count, last verdict       |
| `DetectionOutcome`     | Input to `record_outcome()`                                                           |
| `FeedbackMetrics`      | FPR / FNR / precision / recall + confusion counts                                     |
| `BatchThreatEstimate`  | Aggregate output of `estimate_batch()`                                                |
| `InspectionLevel`      | Enum — `Low`, `Medium`, `High`                                                        |
| `ReputationSource`     | Enum — `history`, `bayesian_prior`, `provided`, `default`                             |
| `DetectionVerdict`     | Enum — `benign`, `malicious`, `unknown`, `quarantined`                                |

---

## 7. API Specification

### 7.1 Construction

```python
GameTheoreticThreatEstimator(
    config:             Optional[EstimatorConfig]           = None,
    reputation_store:   Optional[InMemoryReputationStore]   = None,
    bayesian_estimator: Optional[BayesianReputationEstimator] = None,
    threshold_manager:  Optional[AdaptiveThresholdManager]  = None,
    feedback_loop:      Optional[FeedbackLoop]              = None,
)
```

Every argument has a sensible default, so the minimum viable
instantiation is `GameTheoreticThreatEstimator()`.

### 7.2 Public methods

| Method                                                                  | Purpose                                                                      |
|-------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `estimate(ingest_metadata, artifact_records, history=0.0, threat_intel=0.0) -> ThreatEstimate` | Score a single submission                                                    |
| `estimate_from_ingest_result(ingest_result, **kwargs) -> ThreatEstimate` | Convenience wrapper accepting an `IngestResult` dict directly                |
| `estimate_batch(list[(metadata, artifacts)]) -> BatchThreatEstimate`     | Score many submissions; aggregates per-level counts                          |
| `record_outcome(DetectionOutcome) -> ReputationProfile`                  | Consume a detection verdict; updates reputation and feeds the feedback loop  |
| `update_thresholds_from_feedback() -> Tuple[float, float]`               | Pull FPR / FNR from the feedback loop and soft-update the thresholds          |
| `update_thresholds(fpr, fnr) -> Tuple[float, float]`                     | Direct pass-through for hosts that compute metrics externally                |
| `stats` (property)                                                       | Live counters, threshold state, store / window sizes                          |

### 7.3 Integration example

```python
from ingestion_interceptor import IngestionInterceptor
from threat_estimator import (
    GameTheoreticThreatEstimator,
    EstimatorConfig,
    DetectionOutcome,
)

interceptor = IngestionInterceptor(...)
estimator   = GameTheoreticThreatEstimator(EstimatorConfig())

ingest_result = interceptor.process(drone_json).to_dict()
estimate = estimator.estimate_from_ingest_result(ingest_result)

# Run the engines listed in estimate.inspection.route
# e.g. ["signature", "ml", "sandbox"]
verdict = detection_engine.run(estimate.inspection.route, ingest_result)

estimator.record_outcome(DetectionOutcome(
    drone_id=estimate.drone_id,
    verdict=verdict,            # "benign" | "malicious" | ...
    source="sandbox",
    estimate_id=estimate.estimate_id,
))

# Periodically, from a monitoring loop
estimator.update_thresholds_from_feedback()
```

---

## 8. Input / Output Specification

### 8.1 Input contract

`estimate()` takes two dict arguments. Both shapes are produced
directly by the Ingestion Interceptor — the estimator does **not**
re-validate authenticity, signatures, or file format (those are the
interceptor's responsibility).

#### 8.1.1 `ingest_metadata` — accepted fields

| Field                 | Type                     | Required | Source / Notes                                              |
|-----------------------|--------------------------|----------|-------------------------------------------------------------|
| `drone_id`            | str                      | Yes      | Propagated into the estimate                                |
| `ingest_id`           | str                      | No       | Used only for cross-module correlation                      |
| `mission_zone`        | str                      | No       | Default: `"unknown"`. Used as Zone in Bayesian prior        |
| `insecure_flags`      | List[str]                | No       | Each known flag adds a delta to `I_base` (see §11)          |
| `auth_result`         | str                      | No       | `"fail"` / `"failed"` add `flag_impact_bumps["auth_failed"]`|
| `reputation`          | float in [0, 1]          | No       | If present, takes priority over history and Bayesian prior  |
| `zone_risk`           | float in [0, 1]          | No       | If present, overrides `zone_risk_lookup`                    |
| `additional_metadata` | Dict[str, Any]           | No       | `mission_sensitivity` substring of `critical`/`high`/`med` adds to `I_base` |
| `notes`               | str                      | No       | Same sensitivity-substring matching as a fallback           |

Unknown fields are ignored. Errored `IngestResult` dicts (those with
`{"error": True, ...}`) cause `estimate_from_ingest_result()` to raise
`ValueError`.

#### 8.1.2 `artifact_records` — accepted fields per record

| Field        | Type   | Required | Notes                                                         |
|--------------|--------|----------|---------------------------------------------------------------|
| `type`       | str    | Yes      | Lookup key in `config.type_risk`; unknown types fall back to `"other"` (0.4) |
| `size_bytes` | int    | Yes      | Averaged across all artifacts to compute size contribution    |
| `filename`   | str    | No       | Not used for scoring; preserved in logs                       |
| `mime`       | str    | No       | Not used for scoring (interceptor has already classified)     |
| `encryption` | bool   | No       | Signals via `insecure_flags`, not read directly               |
| `container`  | bool   | No       | Signals via `insecure_flags`, not read directly               |

Any extra keys produced by the interceptor are passed through unchanged
and ignored.

#### 8.1.3 Feedback inputs

`record_outcome(DetectionOutcome)` — fields:

| Field          | Type           | Required | Notes                                                         |
|----------------|----------------|----------|---------------------------------------------------------------|
| `drone_id`     | str            | Yes      |                                                               |
| `verdict`      | str            | Yes      | One of `benign`, `malicious`, `unknown`, `quarantined`        |
| `source`       | str            | No       | `"signature"` / `"ml"` / `"sandbox"` / `"triage"`              |
| `estimate_id`  | Optional[str]  | No       | For cross-correlation with the originating estimate           |
| `artifact_id`  | Optional[str]  | No       |                                                               |
| `observed_at`  | str (ISO-8601) | No       | Auto-filled by the dataclass                                  |
| `confidence`   | Optional[float]| No       | Detector's self-reported confidence                            |

### 8.2 Output contract

#### 8.2.1 `ThreatEstimate.to_dict(include_matrices=True)`

Lightweight mode (`include_matrices=False`) drops `DSR_prime`,
`payoffs`, and `config_snapshot`, keeping the estimate small enough for
high-volume logging. Full mode includes everything and is the default
for forensic storage.

Example (lightweight mode, irrelevant long fields trimmed):

```
{
  "estimate_id":            "est_f3a9c1d28e4b",
  "drone_id":               "DRN-002",
  "ingest_id":              "ingest_c7d6e5f4a3",
  "mission_zone":           "zone-c",
  "file_type":              "archive",
  "reputation":             0.256725,
  "reputation_source":      "bayesian_prior",
  "I_base":                 5.58,
  "I_prime":                7.88,
  "raw_attacker_advantage": -0.89,
  "T_raw":                  0.33,
  "threat_score":           0.374,
  "bayesian_trace":  { "zone": "zone-c", "file_type": "archive",
                       "P_N": 0.85, "P_A": 0.15,
                       "P_Z_given_N": 0.12, "P_Z_given_A": 0.35,
                       "P_F_given_N": 0.08, "P_F_given_A": 0.45,
                       "numerator": 0.00816, "denominator": 0.031785,
                       "R": 0.256725,
                       "used_fallback_zone": false,
                       "used_fallback_file": false },
  "equilibrium":     { "defender_strategy": "signature",
                       "attacker_action":   "inject",
                       "defender_index": 0, "attacker_index": 0,
                       "U_d_eq": 4.30, "U_a_eq": 3.41 },
  "inspection":      { "level": "Low",
                       "route": ["signature"],
                       "threshold_low":  0.4,
                       "threshold_high": 0.7 },
  "created_at":      "2025-10-13T03:05:45.123456+00:00",
  "warnings":        []
}
```

#### 8.2.2 Downstream consumption contract

Downstream modules should consume only the following stable fields:

| Consumer                              | Fields read                                              |
|---------------------------------------|----------------------------------------------------------|
| Multi-Layer Malware Detection Engine  | `inspection.route`, `inspection.level`                   |
| `metadata_sanitizer`                  | `threat_score` (maps to sanitization mode via its config)|
| Response & Quarantine Manager         | `threat_score`, `inspection.level`, `drone_id`, `estimate_id` |
| Security Dashboard / SIEM             | full `to_dict()` for forensic replay                     |

Fields outside this set (intermediate game values, Bayesian trace,
config snapshot) are considered audit-only and their schema may evolve.

---

## 9. Sequence Diagrams

### 9.1 Happy path — cold-start submission

```
Caller        Estimator     RepStore    Bayesian    Stackelberg   Adaptive
  │ estimate()   │              │          │            │            │
  │─────────────▶│  get(drone)  │          │            │            │
  │              │─────────────▶│ None     │            │            │
  │              │◀─────────────│          │            │            │
  │              │ compute_initial_reputation(Z, F)     │            │
  │              │─────────────────────────▶│           │            │
  │              │◀─────────────────────────│ BayesianTrace          │
  │              │ I_base + flag bumps                  │            │
  │              │ I_prime, DSR_prime ──────▶           │            │
  │              │◀─────────────────────────────────────│            │
  │              │ build_payoff_matrices ──────────────▶│            │
  │              │ solve_stackelberg_pure  ────────────▶│            │
  │              │◀────────────────────────────────────│ Equilibrium │
  │              │ compute_threat_score    ────────────▶│            │
  │              │◀────────────────────────────────────│ T_S         │
  │              │ classify(T_S) ───────────────────────────────────▶│
  │              │◀────────────────────────────────────────────────── InspectionDecision
  │◀─────────────│ ThreatEstimate                                    │
```

### 9.2 Feedback cycle

```
Host                 Estimator              RepStore           FeedbackLoop      Adaptive
  │ record_outcome() │                         │                   │                │
  │─────────────────▶│  get()                  │                   │                │
  │                  │────────────────────────▶│                   │                │
  │                  │◀────────────────────────│ existing/None     │                │
  │                  │ update_reputation(current, verdict)         │                │
  │                  │  put(new profile) ─────▶│                   │                │
  │                  │  observe(outcome, level) ─────────────────▶│                │
  │◀─────────────────│ ReputationProfile                           │                │
  │                                                                                  │
  │ update_thresholds_from_feedback()                                                │
  │─────────────────▶│  compute_metrics() ────────────────────────▶│                │
  │                  │◀───────────────────────────────────────────│ FeedbackMetrics │
  │                  │  update(fpr, fnr) ──────────────────────────────────────────▶│
  │                  │◀──────────────────────────────────────────────── (th_low, th_high)
  │◀─────────────────│ (th_low, th_high)                                             │
```

### 9.3 Rejection — errored `IngestResult`

```
Caller          Estimator
  │ estimate_from_ingest_result({"error": True, "errors": [...]})
  │──────────────────▶│
  │                   │  check shape
  │◀──────────────────│  raise ValueError("cannot estimate on an errored IngestResult")
```

---

## 10. Mathematical Core

### 10.1 Adjusted impact

```
I' = I_base · (1 + α·(1 − R)) · (1 + β·Z)

    I_base ∈ [0, 10]   derived from artifact types + sizes + mission sensitivity + flag bumps
    R      ∈ [0, 1]    reputation (higher is safer)
    Z      ∈ [0, 1]    zone risk
    α, β   ≥ 0         multiplicative weights from config
```

Lower reputation or higher zone risk inflates `I'` multiplicatively.

### 10.2 Adjusted detection success rate

```
DSR'(s) = clamp( DSR(s) · (1 − γ·H) · (1 + δ·TI),  ε,  1 − ε )

    DSR(s) ∈ (0, 1)    base detection rate for strategy s
    H      ∈ [0, 1]    recent infection frequency (evasion signal)
    TI     ∈ [0, 1]    threat-intel corroboration strength
    γ, δ   ≥ 0         multiplicative weights from config
    ε      > 0         clamp epsilon to keep DSR'(s) strictly inside (0, 1)
```

### 10.3 Payoffs (conservative rule)

```
U_d(s, inject)    = DSR'(s) · I'          − C_d(s)
U_d(s, no_inject) =                       − C_d(s)        (defender pays inspection cost only)
U_a(s, inject)    = (1 − DSR'(s)) · I'    − C_a(inject)
U_a(s, no_inject) = 0                                        (attacker does nothing, no cost)
```

### 10.4 Pure-strategy Stackelberg (defender as leader)

```
for each defender strategy s:
    a*(s) = argmax over a of U_a(s, a)            # attacker best response
    (on ties: prefer the action that minimises U_d)

s* = argmax over s of U_d(s, a*(s))                # defender picks best reply-aware strategy
(on ties among equal U_d values: prefer the strategy with the lower C_d(s))

equilibrium  = (s*, a*(s*)),  U_d_eq = U_d(s*, a*(s*)),  U_a_eq = U_a(s*, a*(s*))
```

Complexity: `O(|S_d| · |S_a|)` per submission; |S_d| = 3, |S_a| = 2.

### 10.5 Threat score and inspection level

```
raw   = U_a_eq − U_d_eq
T_raw = σ(κ · raw)              where σ(x) = 1 / (1 + e⁻ˣ)
T_S   = λ · T_raw + (1 − λ) · (1 − R)
T_S   = clip(T_S, 0, 1)

inspection level =
    Low     if T_S <  θ_low
    Medium  if θ_low ≤ T_S < θ_high
    High    if T_S ≥ θ_high
```

### 10.6 Adaptive threshold update

```
θ_high_new = θ_high_old + η·(FPR − FPR_target) − η·(FNR − FNR_target)
θ_low_new  = θ_low_old  + η·(FPR − FPR_target) − η·(FNR − FNR_target)

then clamp each θ to its [*_min, *_max] bounds,
     and enforce θ_high − θ_low ≥ threshold_min_gap
```

High FPR pushes `θ_high` up (fewer sandbox routings, fewer false
alarms). High FNR pulls `θ_high` down (more sandbox routings, better
recall). `θ_low` is nudged in parallel to keep the band coherent.

### 10.7 Bayesian cold-start posterior

```
                                        P(N) · P(Z|N) · P(F|N)
R = P(Benign | Zone, FileType) = ───────────────────────────────────────────────────
                                  P(N)·P(Z|N)·P(F|N)  +  P(A)·P(Z|A)·P(F|A)

    N = Benign (No Attack)
    A = Malicious (Attack)
    P(N) = prior_benign, P(A) = 1 − prior_benign
    P(Z|·), P(F|·) come from the CPTs (DEFAULT_ZONE_LIKELIHOOD, DEFAULT_FILE_LIKELIHOOD)
```

Worked reference example (Zone 3 × ZIP with `prior_benign = 0.85`):

```
numerator    = 0.85 × 0.12 × 0.08 = 0.00816
denominator  = 0.00816 + (0.15 × 0.35 × 0.45) = 0.031785
R            = 0.00816 / 0.031785 ≈ 0.257
```

### 10.8 Reputation update (asymmetric)

```
R_new =
    clip(R + η₊·(1 − R),  0, 1)     if verdict = "benign"    (reward)
    clip(R − η₋·R,        0, 1)     if verdict = "malicious" (penalty)
    R                                otherwise  (unknown / quarantined: no-op)

    Defaults: η₊ = 0.05  (reward_rate)
              η₋ = 0.50  (penalty_rate) — one infection costs ten clean deliveries
```

---

## 11. Configuration Reference

Every field of `EstimatorConfig`, with defaults:

| Group              | Field                          | Default                                         | Meaning                                                                 |
|--------------------|--------------------------------|-------------------------------------------------|-------------------------------------------------------------------------|
| Impact             | `alpha`                        | 0.5                                             | Reputation weight on `I'`                                               |
| Impact             | `beta`                         | 0.3                                             | Zone-risk weight on `I'`                                                |
| Impact             | `gamma`                        | 0.2                                             | History weight on `DSR'`                                                |
| Impact             | `delta`                        | 0.0                                             | Threat-intel weight on `DSR'`                                           |
| Impact             | `eps`                          | 1e-3                                            | Clamp epsilon for probabilities                                         |
| Score              | `kappa`                        | 0.8                                             | Sigmoid scale on raw utility gap                                        |
| Score              | `lambda_blend`                 | 0.9                                             | Model-vs-reputation blend in `T_S`                                      |
| Game               | `defender_strategies`          | `("signature", "ml", "sandbox")`                |                                                                         |
| Game               | `attacker_actions`             | `("inject", "no_inject")`                       |                                                                         |
| Game               | `DSR_base`                     | `{signature: 0.70, ml: 0.85, sandbox: 0.95}`    | Base detection success rates                                            |
| Game               | `C_d`                          | `{signature: 1, ml: 3, sandbox: 6}`             | Defender inspection costs                                               |
| Game               | `C_a`                          | `{inject: 2, no_inject: 0}`                     | Attacker action costs                                                   |
| Thresholds         | `th_low`, `th_high`            | 0.40, 0.70                                      | Initial inspection-level cut-offs                                       |
| Thresholds         | `adaptive_thresholds`          | `True`                                          | Disable to freeze θ                                                     |
| Thresholds         | `FPR_target`, `FNR_target`     | 0.05, 0.03                                      | Detection objectives driving the update rule                            |
| Thresholds         | `eta`                          | 0.10                                            | Learning rate for threshold soft-update                                 |
| Thresholds         | `threshold_low_min`, `_max`    | 0.20, 0.50                                      | Safe clamp on `θ_low`                                                   |
| Thresholds         | `threshold_high_min`, `_max`   | 0.55, 0.85                                      | Safe clamp on `θ_high`                                                  |
| Thresholds         | `threshold_min_gap`            | 0.10                                            | Minimum `θ_high − θ_low`                                                |
| Bayesian           | `prior_benign`                 | 0.85                                            | `P(N)` in the cold-start prior                                          |
| Reputation         | `reward_rate`                  | 0.05                                            | η₊ — benign-verdict reward                                              |
| Reputation         | `penalty_rate`                 | 0.50                                            | η₋ — malicious-verdict penalty (intentionally asymmetric)               |
| Reputation         | `default_reputation`           | 0.80                                            | Fallback only when both history and Bayesian prior are unavailable      |
| Impact heuristics  | `type_risk`                    | `{telemetry: .1, text: .2, image: .5, video: .9, archive: .8, zip: .8, pdf: .6, audio: .4, other: .4}` | Per-file-type risk contribution to `I_base` |
| Impact heuristics  | `I_base_min`, `_max`           | 0.0, 10.0                                       | Clamp on `I_base`                                                       |
| Impact heuristics  | `default_zone_risk`            | 0.5                                             | When `mission_zone` is not in `zone_risk_lookup`                        |
| Impact heuristics  | `zone_risk_lookup`             | `{}`                                            | Per-zone override for `Z`                                               |
| Impact heuristics  | `flag_impact_bumps`            | see `config.py`                                 | Delta to `I_base` per insecure flag raised upstream                     |
| Impact heuristics  | `unsafe_auth_results`          | `{"fail", "failed"}`                            | `auth_result` values that trigger the `auth_failed` bump                |
| Caches             | `estimate_cache_max_size`      | 1024                                            | LRU size for the `record_outcome` seeding cache                         |
| Logging            | `log_level`                    | `"INFO"`                                        | Host installs log handlers                                              |

---

## 12. Security & Threat Model

### 12.1 Adversary model

The attacker's goal is to maximise the probability of delivering a
malicious payload undetected. Known vectors and mitigations:

| Vector                                                                         | Mitigation in this module                                                                                                             |
|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| Submit encrypted / nested archives to evade signature scans                    | Flag bumps on `encrypted_payload` + `nested_archive` inflate `I_base`; Bayesian prior for `archive` / `zip` is low                    |
| Spoof drone identity to inherit a trusted reputation                           | Upstream interceptor authenticates; `auth_result = fail` triggers `flag_impact_bumps["auth_failed"]` (default +1.5)                   |
| Reputation laundering (many benign, then a single malicious)                   | Asymmetric rates: one malicious verdict halves reputation; recovery requires many benign verdicts                                      |
| Threshold poisoning (flooding benign traffic to drift `θ_high` up)             | Safe-bound clamps on θ; `FPR_target` is explicit; CPT refresh runs on a slower cadence than threshold updates                          |
| Exploit Bayesian cold-start by rotating drone IDs                              | Unknown zone/file-type fallbacks are pessimistic; cold-start `R` is explicitly tagged `bayesian_prior` so consumers can require extra corroboration |
| Force collisions by submitting many tied utilities                             | Deterministic tie-breakers: attacker hurts defender, defender prefers cheaper strategy                                                 |

### 12.2 Non-repudiation

Every `ThreatEstimate` carries `estimate_id`, `created_at`, the full
`BayesianTrace`, the payoff matrices, the equilibrium, and a snapshot
of the config knobs that produced the decision. Persisting
`estimate.to_dict(include_matrices=True)` is sufficient for forensic
replay.

### 12.3 Input trust boundary

The estimator trusts that the Ingestion Interceptor has:

- authenticated the drone,
- validated the submission structure,
- detected and flagged encryption / nesting / suspicious MIME / size
  anomalies,
- produced the `IngestResult` with canonicalised types.

The estimator does **not** re-validate cryptographic signatures or
re-parse file formats. Bypassing the interceptor and feeding unvetted
input to the estimator is out of scope and unsupported.

### 12.4 No external I/O

By default, the module performs no network, filesystem, or subprocess
calls. All external integration flows through the injected seams
(§3.2) or through methods the host explicitly invokes
(`record_outcome`, `update_thresholds_from_feedback`).

### 12.5 Fail-closed configuration

`EstimatorConfig.__post_init__` rejects inconsistent deployments at
construction time (missing DSR / C_d entries, inverted thresholds,
out-of-range priors, negative learning rate, etc.). There is no
"silent degrade" path.

---

## 13. Performance Characteristics

### 13.1 Latency

| Phase                                  | Complexity                | Observed (stdlib Python, single core)       |
|----------------------------------------|---------------------------|----------------------------------------------|
| `_compute_I_base` + flag bumps         | O(n) over artifact records| sub-microsecond for typical n ≤ 10           |
| Bayesian posterior                     | O(1) dict lookups         | sub-microsecond                              |
| Payoff-matrix construction             | O(|S_d| · |S_a|) = 6      | sub-microsecond                              |
| Stackelberg solver                     | O(|S_d| · |S_a|) = 6      | sub-microsecond                              |
| Full `estimate()` end-to-end           | O(n) dominant             | under 200 µs per submission on commodity CPU |

Empirical: the 48-test suite completes in ≈ 5 ms on a developer
laptop; stage 2 of `run_demo.py` (five end-to-end estimations) runs in
under 1 ms.

### 13.2 Memory

| Structure                          | Bound                                                        |
|------------------------------------|--------------------------------------------------------------|
| `InMemoryReputationStore`          | O(number of known drones); profile ≈ 200 bytes each          |
| `FeedbackLoop._window`             | O(window_size) outcomes; default 500 records                 |
| `AdaptiveThresholdManager.history` | O(update_count); one small dict per `update()`               |
| `_last_estimate_by_drone`          | Bounded LRU, max `config.estimate_cache_max_size` (1024)     |

No unbounded structures. Long-running edge processes have a
well-defined memory ceiling.

### 13.3 Throughput

At < 200 µs per `estimate()`, a single estimator instance sustains
≳ 5 000 submissions/second on one CPU core, well above the ingestion
rate for any realistic drone fleet. Scale horizontally (one estimator
per ingestion worker) rather than vertically.

---

## 14. Testing Strategy

48 tests live in `threat_estimator/tests/test_estimator.py`. Run with:

```bash
python -m unittest threat_estimator.tests.test_estimator -v
# or
python -m pytest threat_estimator/tests/ -v
```

Coverage groups:

| Group                        | Count | Highlights                                                                                   |
|------------------------------|:-----:|----------------------------------------------------------------------------------------------|
| `TestEstimatorConfig`        |  8    | Defaults, DSR / cost ordering, override, `__post_init__` rejects every invalid combination   |
| `TestBayesianReputation`     |  6    | Reference example `R ≈ 0.257`, unit-interval invariant, fallback flags, prior validation, monotonicity across zones |
| `TestReputationUpdate`       |  4    | Monotone reward / penalty, unknown-verdict no-op, asymmetry                                   |
| `TestStackelbergPrimitives`  |  5    | `I'` / `DSR'` math, payoff-matrix signs, sandbox selection for high impact, `T_S` bounded     |
| `TestAdaptiveThresholds`     |  5    | FPR / FNR response, clamp bounds, gap preservation, disabled mode, classify boundaries        |
| `TestReputationStore`        |  4    | Put / get / delete, initial seed, defensive copy on `get()`, range validation                 |
| `TestEndToEnd`               | 13    | Samples A–D + high-risk, priority of reputation sources, feedback cycle, batch, JSON round-trip, bounded LRU cache |
| `TestFeedbackLoop`           |  3    | TP / FP / TN / FN accounting, empty metrics, window size                                      |

Key invariants covered explicitly:

- `T_S ∈ [0, 1]` for any inputs (`test_threat_score_bounded`)
- Bounded LRU cache does not leak (`test_last_estimate_cache_is_bounded`)
- JSON round-trip is clean for the full audit payload (`test_to_dict_is_serializable`)
- Cold-start reputation exactly matches the reference Bayesian example
  (`test_plan_worked_example`, `test_cold_start_uses_bayesian_prior`)

---

## 15. Operations

### 15.1 Deployment

Single-process Python library, no daemons. Instantiate one estimator
per ingestion worker in the edge node's detection process. Because all
dependencies are in-memory by default, there are no startup
dependencies beyond the Python runtime. The host process is
responsible for:

1. Constructing the `EstimatorConfig` (or accepting the defaults).
2. Choosing a `reputation_store` backend and wiring persistence /
   replication if needed.
3. Bridging `FeedbackLoop` to the Response & Quarantine Manager so
   every verdict results in an `observe()` call.
4. Scheduling `update_thresholds_from_feedback()` (e.g. every few
   minutes).
5. Installing log handlers for the `threat_estimator` package logger.

### 15.2 Monitoring checklist

Scrape `GameTheoreticThreatEstimator.stats` periodically:

| Signal                                       | Alert when                                                                   |
|----------------------------------------------|------------------------------------------------------------------------------|
| `total_high / total_processed`               | Above operational sandbox capacity for more than 5 minutes                   |
| `thresholds.th_high`                         | Pinned at `threshold_high_max` (0.85) or `threshold_high_min` (0.55) for three updates in a row |
| `total_cold_start / total_processed`         | Above 20% — reputation store is losing coverage                              |
| `feedback_window_size`                       | Stays at 0 — the feedback loop is disconnected                               |
| `thresholds.update_count`                    | Zero over a multi-hour window — `update_thresholds_from_feedback()` not running |

### 15.3 Runbook snippets

- **Sandbox overloaded.** Temporarily raise `FPR_target` or
  `threshold_high_max` so `θ_high` can drift higher; then refresh CPTs
  to reflect the new attack mix.
- **Detection rate dropped.** Lower `FNR_target`. Confirm that the
  Response & Quarantine Manager is calling `record_outcome` (check
  `feedback_window_size`).
- **Reputation noise.** Lower `penalty_rate`. Require multiple
  corroborating verdict sources before calling `record_outcome` for a
  given submission.
- **Config rejected on startup.** `EstimatorConfig.__post_init__`
  fail-closes on inconsistency; read the `ValueError` message, fix the
  offending field, and redeploy.

---

## 16. Risk Assessment

| Risk                                                                     | Likelihood | Impact | Mitigation                                                                                                             |
|--------------------------------------------------------------------------|:----------:|:------:|------------------------------------------------------------------------------------------------------------------------|
| CPT seed values diverge from the observed distribution                   | High (day 0) | Medium | `update_cpts()` refresh hook; tests verify fallback invariants rather than absolute values outside the reference example |
| Feedback loop not wired — thresholds frozen at defaults                  | Medium     | Medium | Operational monitor on `feedback_window_size`; dashboards surface `thresholds.update_count`                             |
| Pure-strategy solver ignores mixed-strategy equilibria                   | Low        | Low    | Conservative by construction; `adaptive_thresholds` compensates for boundary oscillation                                 |
| Host forgets to persist `reputation_store` snapshot — cold start after every restart | Medium | High   | `InMemoryReputationStore.snapshot()` provided; persistence is an explicit host responsibility (§15.1)                    |
| `I_base` heuristic too coarse for a new artifact type                    | Medium     | Medium | `type_risk` and `flag_impact_bumps` are config knobs; new keys can be added without code changes                         |
| Reputation update over-penalises a noisy detection engine                | Medium     | Medium | `penalty_rate` is tunable; host can require multi-source corroboration before calling `record_outcome`                   |
| Adversary bypasses the interceptor and feeds unvetted input              | Low        | High   | Out of scope by contract (NG-7); the interceptor is the sole authentication point                                        |

---

## 17. Glossary

- **Stackelberg equilibrium** — Leader-follower game solution; here the
  defender moves first and the attacker best-responds.
- **Reputation (`R`)** — Drone trustworthiness in `[0, 1]`.
- **Threat Score (`T_S`)** — Bounded output in `[0, 1]` driving
  inspection-level routing.
- **Cold start** — Scoring a drone that has no entry in the reputation
  store.
- **Bayesian Belief Network (BBN)** — Here, a two-feature naive-Bayes
  network with Zone and File Type as evidence and Attack Status as the
  class variable.
- **Conditional Probability Table (CPT)** — Tabulated likelihoods
  `P(Z | ·)` and `P(F | ·)`.
- **Inspection level** — Discrete output in `{Low, Medium, High}`,
  mapping to the subset of detection engines to run.
- **Soft update** — Additive adjustment scaled by a small learning rate
  `η`, as opposed to a hard swap.
- **DSR** — Detection Success Rate of a defender strategy.
- **ASP** — Attacker Success Probability, `1 − DSR'`.
- **FPR / FNR** — False-Positive / False-Negative rate over the current
  monitoring window.
- **`I_base` / `I'`** — Base impact and reputation-and-zone-adjusted
  impact used by the game.
