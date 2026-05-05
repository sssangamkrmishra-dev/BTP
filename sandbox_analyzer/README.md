# Sandbox Analyzer

Dynamic behavioural analysis layer of the Multi-Layer Malware Detection
Engine. Executes suspicious drone/RPA payloads inside a kernel-limited
Linux sandbox, watches them via four `/proc` monitors, correlates
findings against threat intelligence, and emits a three-level verdict
(`CLEAN` / `SUSPICIOUS` / `MALICIOUS`) with a complete behavioural
trace.

Pipeline position:

```
Ingestion Interceptor
  → Game-Theoretic Threat Estimator
  → Inspection Strategy Selector
  → [Signature Scanner | AI/ML Classifier | Sandbox Analyzer]  ← this module
  → Metadata Sanitizer
  → Threat Intelligence Correlator
  → Response & Quarantine Manager
  → Security Dashboard & Feedback Loop
```

## Requirements

- Python ≥ 3.10
- Linux kernel (required for `resource.setrlimit` and `/proc` monitoring)
- `psutil` (required — the only third-party dependency, used by the process monitor)

On non-Linux hosts the module still loads and static stages (routing,
archive inspection, scoring, IOC correlation) still run; the execution
and monitor stages are skipped and the report carries an explicit
warning.

## Quick Start

### 1. As a library

```python
from sandbox_analyzer import SandboxAnalyzer, SandboxConfig

analyzer = SandboxAnalyzer(SandboxConfig())
report = analyzer.analyze("/tmp/sample.py", drone_id="DRN-001")
print(report.verdict.value, report.risk_score)
print(report.summary())
```

### 2. Wiring a production Threat Intelligence Correlator

```python
from sandbox_analyzer import (
    SandboxAnalyzer, SandboxConfig, ThreatIntelClient,
)

class RemoteCorrelatorClient(ThreatIntelClient):
    source = "threat_intelligence_correlator"
    def __init__(self, endpoint):
        self.endpoint = endpoint
    def query(self, file_hash, observed_ips, observed_domains):
        return requests.post(self.endpoint, json={
            "hash": file_hash,
            "ips": list(observed_ips),
            "domains": list(observed_domains),
        }).json()

analyzer = SandboxAnalyzer(
    config=SandboxConfig(),
    threat_intel_client=RemoteCorrelatorClient("https://tic.internal/api/v1/query"),
)
```

### 3. Wiring custom feedback callbacks

```python
from sandbox_analyzer import SandboxAnalyzer, build_sink

analyzer = SandboxAnalyzer(
    feedback_sink=build_sink(
        response_manager=lambda r: response_mgr.apply(r.verdict.value, r.file_path),
        dashboard=lambda r: dashboard.emit(r.to_dict()),
        ml_queue=lambda r: ml_queue.enqueue(r.to_dict(include_events=True)),
    ),
)
```

### 4. Standalone demo

```bash
python -m sandbox_analyzer.run_demo
```

Runs four stages: a safe CSV (skipped), a disguised script (magic-byte
detection), an archive with a double-extension member, and — on Linux
— a script that mimics C2 behaviour to trigger the network monitor +
IOC match.

## Running the Test Suite

```bash
python -m unittest sandbox_analyzer.tests.test_analyzer -v
# or
python -m pytest sandbox_analyzer/tests/ -v
```

50 tests covering:

- config defaults, overrides, and `__post_init__` validation
- File Router magic-byte vs extension priority
- Archive Handler: plain, encrypted-no-key, encrypted-with-key, double-extension, depth cap
- Risk scoring weights and verdict banding
- IOC correlation hash / IP / domain match; domain regex filename-safety
- Feedback sinks: base, logging, composed, exception isolation
- End-to-end static paths (safe skip, Windows-PE `SUSPICIOUS` short-circuit, archive)
- Live execution (Linux-only, auto-skipped elsewhere)
- Helpers (`compute_file_hash`, `is_encrypted_zip`, `action_for`)

## Module Layout

```
sandbox_analyzer/
├── __init__.py              # public API re-exports
├── config.py                # SandboxConfig dataclass + __post_init__ validation
├── models.py                # dataclasses: SandboxReport, MonitorEvent, ...
├── router.py                # Stage 1 — magic bytes + extension → RoutingDecision
├── archive_handler.py       # Stage 2 — ZIP extraction, encryption / bomb / double-ext
├── execution.py             # Stage 3 — subprocess under setrlimit + watchdog
├── monitors.py              # Stage 4 — FS / Network / Process / Privilege monitors
├── scoring.py               # Stage 5 — additive behaviour-weight scoring
├── ioc.py                   # Stage 6 — ThreatIntelClient + LocalThreatIntelClient
├── verdict.py               # Stage 7 — threshold mapping + action strings
├── feedback.py              # Stage 8 — FeedbackSink + LoggingFeedbackSink + build_sink
├── analyzer.py              # SandboxAnalyzer orchestrator (all 8 stages)
├── run_demo.py              # standalone demo
├── tests/
│   └── test_analyzer.py     # 50 stdlib-unittest tests
└── README.md                # this file
```

## Key Configuration Knobs

| Group | Knob | Default | Meaning |
| :--- | :--- | :---: | :--- |
| Routing | `skip_safe_files` | `True` | SAFE files (CSV/TXT/JSON/LOG) return CLEAN immediately |
| Routing | `flag_windows_executables` | `True` | MZ-header files flagged, not executed |
| Archive | `max_extract_depth` | 3 | Max recursion into nested ZIPs |
| Archive | `zip_bomb_ratio` | 0.005 | Abort extraction below this ratio |
| Archive | `zip_bomb_min_size_bytes` | 10 MB | Only check ratio above this uncompressed size |
| Archive | `encrypted_no_key_score` | 25 | Risk bump for encrypted archive with no declared key |
| Archive | `double_extension_score` | 30 | Risk bump per double-extension member |
| Execution | `memory_bytes` | 128 MB | `RLIMIT_AS` cap |
| Execution | `cpu_seconds` | 20 | `RLIMIT_CPU` cap (delivers `SIGXCPU`) |
| Execution | `file_bytes` | 32 MB | `RLIMIT_FSIZE` cap |
| Execution | `max_processes` | 50 | `RLIMIT_NPROC` cap (fork-bomb guard) |
| Execution | `wall_timeout_seconds` | 30 | Watchdog kill timeout |
| Execution | `empty_environment` | `True` | Run with `env={}` to avoid leakage |
| Monitors | `poll_interval_seconds` | 0.2 | Monitor polling cadence |
| Monitors | `enable_filesystem_monitor` | `True` | `/proc/<pid>/fd` writes |
| Monitors | `enable_network_monitor` | `True` | `/proc/net/tcp` diff |
| Monitors | `enable_process_monitor` | `True` | `psutil` child-tree walk |
| Monitors | `enable_privilege_monitor` | `True` | `/proc/<pid>/status` CapEff + VmRSS |
| Monitors | `memory_spike_threshold_kb` | 51200 | RSS jump (in KB) that triggers `memory_inject` |
| Scoring | `behavior_weights` | see `config.py` | Per-category risk weights (additive) |
| IOC | `ioc_match_bonus` | 20 | Risk bump on any IOC match |
| IOC | `enable_ioc_correlation` | `True` | Disable to skip Stage 6 |
| Verdict | `suspicious_threshold` | 25 | Score ≥ this → `SUSPICIOUS` |
| Verdict | `malicious_threshold` | 60 | Score ≥ this → `MALICIOUS` |
| Feedback | `enable_feedback_hooks` | `True` | Disable to suppress all three post-verdict callbacks |
| Logging | `log_level` | `"INFO"` | Host installs handlers |

## Integration Seams

| Seam | Reference implementation | Production backend |
| :--- | :--- | :--- |
| `threat_intel_client` | `LocalThreatIntelClient` (in-memory sets) | Subclass `ThreatIntelClient` and talk to VirusTotal / AlienVault OTX / MISP / the project's Threat Intelligence Correlator |
| `feedback_sink` | `LoggingFeedbackSink` (stdlib logging) | Subclass `FeedbackSink` or build one with `build_sink(...)` to bridge to Response Manager, Dashboard, and ML retraining queue |
| `SandboxConfig.behavior_weights` | Engineering-judgement defaults | Refine empirically against a labelled malware corpus during evaluation |
| `SandboxConfig.suspicious_paths / suspicious_processes` | Standard Linux persistence/credential paths | Extend for mission-specific sensitive paths |

## Operational Stats

`SandboxAnalyzer.stats` is a live dict:

```python
{
  "total_analyzed":       142,
  "total_clean":           97,
  "total_suspicious":      28,
  "total_malicious":       17,
  "total_skipped":         41,
  "total_archive_runs":    18,
  "total_execution_runs":  84,
  "total_errors":           0,
  "last_report_id":        "sbx_8a0c19d41f52",
}
```

Monitor:

- `total_malicious / total_analyzed` — detection rate.
- `total_errors` — rising indicates environment issues (missing psutil, read-only `/proc`).
- `total_execution_runs / total_analyzed` — how often the expensive stages actually run.

## Troubleshooting

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| `RuntimeError: sandbox execution requires POSIX resource.setrlimit` | Running on Windows / macOS | Deploy on Linux; the module's static stages still work cross-platform |
| Monitors record zero events for a clearly malicious file | Process exits faster than `poll_interval_seconds` | Lower `poll_interval_seconds` or add brief `time.sleep` calls in test fixtures |
| `psutil` import fails | Dependency not installed | `pip install psutil` |
| Always `CLEAN` on archives with suspicious payloads | Threat-intel client returns no matches **and** nested execution is short-lived | Supply a populated `LocalThreatIntelClient` / production correlator; check `report.archive_result.suspicious_flags` |
| `config` rejected at startup | `__post_init__` caught an inconsistency | Read the `ValueError` message; thresholds must satisfy `malicious_threshold > suspicious_threshold > 0` |

## See Also

- `docs/design_sandbox_analyzer.md` — detailed design document.
- `sandbox_explained_v2_(1).ipynb` — the research notebook this module productionises.
- `threat_estimator/` — upstream module whose `T_S` decides whether this sandbox runs.
- `ingestion_interceptor/` — upstream interceptor producing the artifacts this sandbox examines.
- `metadata_sanitizer/` — downstream module invoked after the sandbox on sanitisable payloads.
