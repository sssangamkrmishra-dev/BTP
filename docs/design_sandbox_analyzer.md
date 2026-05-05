# Design Document: Sandbox Analyzer

| Field              | Value                                                                                       |
|--------------------|---------------------------------------------------------------------------------------------|
| Module             | `sandbox_analyzer/`                                                                         |
| Version            | 1.0                                                                                         |
| Status             | Production                                                                                  |
| Layer              | Layer 3 of the Multi-Layer Malware Detection Engine                                         |
| Upstream           | Inspection Strategy Selector (triggered when Threat Score is HIGH)                          |
| Downstream         | Response & Quarantine Manager, Threat Intelligence Correlator, Security Dashboard / ML Loop |
| Research notebook  | `sandbox_explained_v2_(1).ipynb`                                                            |
| Python version     | 3.10+                                                                                       |
| Platform           | Linux (kernel `setrlimit` + `/proc` required for Stages 3 and 4)                            |
| External deps      | `psutil` (required by the process monitor)                                                  |

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
10. [Risk Scoring Reference](#10-risk-scoring-reference)
11. [Configuration Reference](#11-configuration-reference)
12. [Security & Threat Model](#12-security--threat-model)
13. [Performance Characteristics](#13-performance-characteristics)
14. [Testing Strategy](#14-testing-strategy)
15. [Operations](#15-operations)
16. [Risk Assessment](#16-risk-assessment)
17. [Glossary](#17-glossary)

---

## 1. Executive Summary

The Sandbox Analyzer is Layer 3 of the Multi-Layer Malware Detection
Engine. It activates only when the Game-Theoretic Threat Estimator
has scored an ingestion submission as HIGH — the static Signature
Scanner and AI/ML Classifier (Layers 1 and 2) run on every submission,
but the expensive dynamic analysis here is reserved for the small
minority of inputs that look genuinely suspicious.

The analyzer executes one suspicious artifact inside a kernel-limited
Linux sandbox, observes it through four `/proc`-based monitors, scores
the resulting behavioural events, correlates any observed indicators
against threat intelligence, and emits one of three verdicts
(`CLEAN`, `SUSPICIOUS`, `MALICIOUS`) together with a fully serialisable
audit trail.

Three design decisions are load-bearing:

1. **Magic-byte routing.** Extensions are never trusted — the File
   Router reads the first 16 bytes of every artifact and uses the
   extension only as a fallback. A `.jpg` that begins with `#!` is
   handled as a script, not an image.
2. **Encrypted archives are evidence, not a challenge.** The Archive
   Handler never attempts password cracking. An encrypted archive
   arriving in a drone feed with no declared key is itself a suspicious
   indicator and adds risk points; extraction is skipped.
3. **Kernel-level isolation, userspace observation.** Resource caps
   (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`,
   `RLIMIT_CORE`) are applied in a `preexec_fn` so they are in place
   before the target's `exec()`. Monitoring is done from outside the
   process by reading `/proc` — the monitored process cannot spoof what
   the kernel reports about it.

## 2. Goals and Non-Goals

### 2.1 Goals

| ID    | Goal                                                                                                     |
|-------|----------------------------------------------------------------------------------------------------------|
| G-1   | Produce a bounded risk score and a three-level verdict for every submission handed to `analyze()`        |
| G-2   | Identify file type via magic bytes, with extension as fallback, to defeat trivial disguise               |
| G-3   | Safely handle archives (ZIP) with bomb detection, depth caps, and encrypted-payload flagging              |
| G-4   | Execute suspicious files under kernel-enforced resource limits that malware cannot bypass                |
| G-5   | Observe the running process via four independent `/proc` monitors at a configurable poll cadence         |
| G-6   | Correlate observed IOCs (file hash, IPs, domains) against threat intelligence through an injected client |
| G-7   | Expose pluggable integration seams for threat intel, response management, dashboard, and ML retraining   |
| G-8   | Fail closed on mis-configurations (`SandboxConfig.__post_init__`) and degrade safely on non-Linux hosts  |
| G-9   | Emit a forensically complete report (routing, archive findings, execution results, events, score, IOC)  |
| G-10  | Maintain processing statistics for operational monitoring (`stats` property)                             |

### 2.2 Non-Goals

| ID     | Non-Goal                                                                                                        |
|--------|-----------------------------------------------------------------------------------------------------------------|
| NG-1   | Windows executable emulation — PE files are flagged `SUSPICIOUS` for analyst review and never executed; cross-VM execution is out of scope for this module |
| NG-2   | Dictionary attacks on encrypted archives — encrypted-no-key is scored as a suspicious indicator instead          |
| NG-3   | Signature-based antivirus scanning or ML-based classification — handled by Layers 1 and 2                        |
| NG-4   | Native drone protocol ingestion — the Ingestion Interceptor delivers artifacts on disk                           |
| NG-5   | Persistence of reports / findings — the host persists `SandboxReport.to_dict()` to its chosen store              |
| NG-6   | Distributed sandbox coordination — one analyzer instance per edge node; cross-node fan-out is the host's concern |
| NG-7   | Sandbox escape research / exploit mitigation beyond POSIX `setrlimit` + `/proc` observation                      |

---

## 3. System Context

### 3.1 Position in the edge malware detection pipeline

```
DRONE / RPA
    │  payload + metadata
    ▼
┌────────────────────────────────────────────────────────────────────┐
│              EDGE MALWARE DETECTION ENGINE                         │
│                                                                    │
│  Ingestion Interceptor                                             │
│  Game-Theoretic Threat Estimator                                   │
│  Inspection Strategy Selector                                      │
│    LOW  → Signature Scanner                                        │
│    MED  → Signature + AI/ML Classifier                             │
│    HIGH → Signature + AI/ML + Sandbox Analyzer  ◄── this module    │
│                                                                    │
│  Metadata Sanitizer                                                │
│  Threat Intelligence Correlator                                    │
│  Response & Quarantine Manager                                     │
│  Security Dashboard & Feedback Loop                                │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 Integration seams

The analyzer is driven by one public call (`analyze(file_path,
drone_id, ...)`) and two dependency-injected seams. Both seams have a
reference implementation that is safe in isolation; production
deployments subclass or replace them.

| Seam                   | Reference implementation                         | Production backend                                                                                                 |
|------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `threat_intel_client`  | `LocalThreatIntelClient` (in-memory sets)        | Subclass of `ThreatIntelClient` talking to VirusTotal / AlienVault OTX / MISP / internal Threat Intelligence Correlator |
| `feedback_sink`        | `LoggingFeedbackSink` (structured log lines)     | Subclass of `FeedbackSink` — or compose via `build_sink(...)` — bridging to Response & Quarantine Manager, Security Dashboard, and the ML retraining queue |

The analyzer performs **no network, filesystem (beyond the sandbox
work dir), or subprocess calls** outside the target artifact's own
execution. All cross-module side effects flow through the two seams.

---

## 4. Architecture Overview

### 4.1 Module layout

```
sandbox_analyzer/
├── __init__.py              # public API re-exports
├── config.py                # SandboxConfig dataclass + __post_init__ validation
├── models.py                # SandboxReport, MonitorEvent, RoutingDecision, ...
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
└── README.md
```

### 4.2 Internal pipeline

```
analyze(file_path, drone_id, ...)
    │
    ▼
 ┌───────────────────────────────────────────────────────┐
 │                 SANDBOX ANALYZER                       │
 │                                                        │
 │  Stage 1  File Router                                  │
 │     magic bytes → true file type; extension fallback   │
 │     SAFE    → short-circuit, verdict CLEAN             │
 │     WINDOWS → short-circuit, verdict SUSPICIOUS        │
 │               (flagged for analyst review, not run)    │
 │           │                                            │
 │           ▼                                            │
 │  Stage 2  Archive Handler (ARCHIVE only)               │
 │     encrypted-no-key → +risk, skip extraction          │
 │     double-extension → +risk per member                │
 │     ZIP-bomb ratio   → abort extraction                │
 │     extract → nested ZIPs recurse (bounded)            │
 │           │                                            │
 │           ▼                                            │
 │  Stage 3  Isolated Execution (Linux only)              │
 │     preexec setrlimit: AS, CPU, FSIZE, NPROC, CORE     │
 │     empty env, isolated cwd, 30s watchdog              │
 │           │                                            │
 │           ▼                                            │
 │  Stage 4  Four monitors, 200 ms poll                   │
 │     /proc/<pid>/fd + fdinfo   → FileSystemMonitor      │
 │     /proc/net/tcp diff        → NetworkMonitor         │
 │     psutil children(recursive)→ ProcessMonitor         │
 │     /proc/<pid>/status        → PrivilegeMonitor       │
 │           │                                            │
 │           ▼                                            │
 │  Stage 5  Risk Scoring                                 │
 │     ∑ behavior_weights[event.category]                 │
 │     + archive extra_risk + IOC bonus                   │
 │           │                                            │
 │           ▼                                            │
 │  Stage 6  IOC Correlation (ThreatIntelClient)          │
 │     hash + observed IPs + observed domains → match?    │
 │           │                                            │
 │           ▼                                            │
 │  Stage 7  Verdict                                      │
 │     score < 25   → CLEAN                               │
 │     25 ≤ s < 60  → SUSPICIOUS                          │
 │     score ≥ 60   → MALICIOUS                           │
 │           │                                            │
 │           ▼                                            │
 │  Stage 8  Feedback (FeedbackSink)                      │
 │     notify_response_manager(report)                    │
 │     notify_dashboard(report)                           │
 │     queue_for_ml(report)                               │
 │                                                        │
 └───────────────────────────────────────────────────────┘
                 │
                 ▼
         SandboxReport
```

### 4.3 Component dependency diagram

```
                            ┌───────────────────────┐
                            │   SandboxAnalyzer     │
                            │      (analyzer.py)    │
                            └──┬──┬──┬──┬──┬──┬──┬──┘
                               │  │  │  │  │  │  │
         ┌─────────────────────┘  │  │  │  │  │  └─────────────┐
         │                        │  │  │  │  │                │
         ▼                        │  │  │  │  │                ▼
 ┌──────────────┐                 │  │  │  │  │        ┌──────────────┐
 │ route_file   │                 │  │  │  │  │        │ FeedbackSink │
 │ (router.py)  │                 │  │  │  │  │        │(feedback.py) │
 └──────────────┘                 │  │  │  │  │        └──────────────┘
                 ┌────────────────┘  │  │  │  └────────────────┐
                 ▼                   │  │  │                   ▼
         ┌──────────────┐            │  │  │         ┌───────────────────┐
         │handle_archive│            │  │  │         │ ThreatIntelClient │
         │ (archive_h..)│            │  │  │         │     (ioc.py)      │
         └──────────────┘            │  │  │         └───────────────────┘
                          ┌──────────┘  │  └─────────┐
                          ▼             ▼            ▼
                  ┌────────────┐  ┌──────────┐  ┌──────────────┐
                  │execute_file│  │ monitors │  │compute_risk_ │
                  │(execution) │  │(monitors)│  │    score     │
                  └────────────┘  └──────────┘  └──────────────┘

  reads SandboxConfig (config.py)
  returns SandboxReport (models.py)
```

---

## 5. Component Design

### 5.1 `SandboxConfig` (`config.py`)

Single `@dataclass` holding every tunable: routing behaviour
(`skip_safe_files`, `flag_windows_executables`), archive caps
(`max_extract_depth`, `zip_bomb_ratio`, `zip_bomb_min_size_bytes`,
`encrypted_no_key_score`, `double_extension_score`), execution limits
(`memory_bytes`, `cpu_seconds`, `file_bytes`, `max_processes`,
`wall_timeout_seconds`, `empty_environment`), monitor flags + poll
cadence, suspicious-target lists (paths, processes, shells, executable
extensions), risk-scoring weights, IOC bonus, verdict thresholds, and
feedback enable flag.

`__post_init__` fails the constructor if:

- `malicious_threshold ≤ suspicious_threshold`,
- any resource cap is ≤ 0,
- `zip_bomb_ratio ∉ (0, 1]`,
- `poll_interval_seconds ≤ 0`,
- any behaviour weight is negative,
- clamp bounds are inverted.

### 5.2 File Router (`router.py`)

Reads the first 16 bytes of the artifact, matches against
`MAGIC_BYTES`, and falls back to `EXTENSION_MAP` if no magic matches.
Produces a `RoutingDecision` with category, interpreter (for scripts),
skip flag (for SAFE), magic-match flag, and a human-readable reason.

Magic bytes covered: ZIP (`PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`),
ELF (`\x7fELF`), JPEG, PNG, GIF, PDF, Windows PE (`MZ`), shebang
(`#!`).

### 5.3 Archive Handler (`archive_handler.py`)

`handle_archive(zip_path, output_dir, config, provided_password, depth)`
implements the encrypted-is-suspicious, ratio-based-bomb, and
double-extension safety layers. Recursion through nested ZIPs is
bounded by `config.max_extract_depth`. Every finding contributes an
`ArchiveResult.suspicious_flags` entry and increments
`ArchiveResult.extra_risk_score`; the orchestrator synthesises
corresponding `MonitorEvent`s (category `file_write_executable` for
double-extension, `high_entropy_write` otherwise) so scoring is
uniform across discovery mechanisms.

### 5.4 Isolated Execution (`execution.py`)

`execute_file(file_path, config, interpreter, ..., on_pid)` launches a
child with `subprocess.Popen` and a `preexec_fn` that calls
`resource.setrlimit` for `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`,
`RLIMIT_NPROC`, and `RLIMIT_CORE`. The `on_pid` callback hands the
child PID to the orchestrator as soon as it is known, so monitors can
attach without racing the target.

A daemon watchdog thread sends `SIGKILL` at
`config.wall_timeout_seconds`. `communicate()` carries an additional
`communicate_grace_seconds` so genuine clean exits are not mis-reported
as timeouts. On non-Linux hosts the function raises a clear
`RuntimeError`; the orchestrator skips execution on such hosts.

### 5.5 Four Monitors (`monitors.py`)

Every monitor appends `MonitorEvent` rows to a shared thread-safe
`EventLog`. All are instantiated via `build_monitors(pid, log, config)`
which respects the four `enable_*_monitor` flags.

| Monitor              | Source                                   | Events raised                                         |
|----------------------|------------------------------------------|--------------------------------------------------------|
| `FileSystemMonitor`  | `/proc/<PID>/fd` + `/proc/<PID>/fdinfo`  | `file_system_write`, `file_write_executable`          |
| `NetworkMonitor`     | `/proc/net/tcp` baseline diff             | `network_connect`                                     |
| `ProcessMonitor`     | `psutil.Process(pid).children(True)`      | `process_spawn`, `shell_command`                      |
| `PrivilegeMonitor`   | `/proc/<PID>/status` (`CapEff`, `VmRSS`)  | `privilege_escalation`, `memory_inject`               |

`ProcessMonitor` uses two sets from `SandboxConfig` to classify
children: `shell_processes` is the canonical shell list
(`bash`, `sh`, `zsh`, `dash`, `fish`), and `suspicious_processes`
is the broader lateral-movement set (`wget`, `curl`, `nc`, `sudo`,
compilers, cron tools, ...). Children whose name falls in either set
are recorded as `shell_command` so the scoring engine treats
suspicious-tool invocations as seriously as shell spawns; everything
else is recorded as `process_spawn`.

### 5.6 Risk Scoring (`scoring.py`)

`compute_risk_score(events, config)` sums
`config.behavior_weights[ev.category]` across all events and returns a
`ScoreBreakdown` with totals, per-category counts, and a pre-sorted
`top_factors` list. Unknown categories contribute zero so new
event kinds can be introduced in the monitors without breaking this
stage.

### 5.7 IOC Correlation (`ioc.py`)

`correlate_iocs(file_path, events, config, client)` computes the
file's SHA-256, extracts IPs and domains from `Network`-monitor events,
and hands all three to the injected `ThreatIntelClient.query()`. The
response is translated into an `IOCResult` with `bonus_score =
config.ioc_match_bonus` on any match.

Client exceptions are **swallowed** and logged — a transient Threat
Intelligence Correlator outage must not prevent verdict emission.

### 5.8 Verdict (`verdict.py`)

Pure threshold mapping:

- `score < suspicious_threshold` → `CLEAN`
- `suspicious_threshold ≤ score < malicious_threshold` → `SUSPICIOUS`
- `score ≥ malicious_threshold` → `MALICIOUS`

`action_for(verdict)` returns the operator-facing action string
consumed by the Response & Quarantine Manager.

### 5.9 Feedback (`feedback.py`)

`FeedbackSink` declares three no-op methods
(`notify_response_manager`, `notify_dashboard`, `queue_for_ml`).
`LoggingFeedbackSink` is the reference implementation; `build_sink(...)`
composes a sink from three callables without subclassing. The
orchestrator invokes each method with per-channel exception isolation
so a broken dashboard does not block the response manager.

### 5.10 `SandboxAnalyzer` (`analyzer.py`)

The orchestrator. Public surface:

- `analyze(file_path, drone_id, artifact_id=None, archive_password=None, threat_score=None) → SandboxReport`
- `stats` property — live counters (`total_analyzed`, `total_clean`,
  `total_suspicious`, `total_malicious`, `total_skipped`,
  `total_archive_runs`, `total_execution_runs`, `total_errors`,
  `last_report_id`).

Thread safety: a single `SandboxAnalyzer` instance is intended for one
request-handling thread at a time. Host processes that fan out across
threads should instantiate one analyzer per worker and share only the
two injected dependencies (which must be thread-safe themselves). The
reference `LocalThreatIntelClient` and `LoggingFeedbackSink` satisfy
this contract.

Platform handling: on non-Linux hosts, Stages 3 and 4 are skipped and
the report carries a warning. Stages 1, 2, 5, 6, 7, and 8 still run,
so routing, archive safety, and IOC correlation remain available for
investigation in development environments.

---

## 6. Data Models

All models are `@dataclass`-based with a `to_dict()` method for
structured logging and wire transport.

### 6.1 `SandboxReport` (output)

Returned by every call to `analyze()`. Carries the verdict, the score,
and the full per-stage audit trail.

| Field                 | Type                          | Notes                                                                 |
|-----------------------|-------------------------------|-----------------------------------------------------------------------|
| `report_id`           | str                           | Opaque ID prefixed `sbx_`                                             |
| `file_path`           | str                           | Absolute path on disk                                                 |
| `file_hash`           | str                           | SHA-256 hex, empty string on I/O error                                |
| `drone_id`            | str                           | Propagated from the caller                                            |
| `artifact_id`         | Optional[str]                 | `artifact://…` ID for cross-module correlation                        |
| `file_category`       | str (`FileCategory` value)    |                                                                       |
| `routing`             | Optional[RoutingDecision]     |                                                                       |
| `skipped`             | bool                          | True if a short-circuit fired (SAFE → `CLEAN`, WINDOWS → `SUSPICIOUS`) |
| `skip_reason`         | Optional[str]                 | Human-readable reason set alongside `skipped=True`                    |
| `archive_result`      | Optional[ArchiveResult]       | Present for `ARCHIVE` categorisations                                 |
| `execution_results`   | List[ExecutionResult]         | One per executed file (archives may produce several)                  |
| `events`              | List[MonitorEvent]            | Full behavioural trace                                                |
| `score_breakdown`     | Optional[ScoreBreakdown]      |                                                                       |
| `ioc_result`          | Optional[IOCResult]           |                                                                       |
| `risk_score`          | int                           | Total score after archive bonus and IOC bonus                         |
| `verdict`             | Verdict                       | `CLEAN` / `SUSPICIOUS` / `MALICIOUS`                                  |
| `action`              | str                           | Operator-facing action for the Response Manager                       |
| `created_at`          | str (ISO-8601 UTC)            |                                                                       |
| `duration_sec`        | float                         | End-to-end wall-clock                                                 |
| `warnings`, `errors`  | List[str]                     |                                                                       |
| `config_snapshot`     | Dict[str, Any]                | Subset of `SandboxConfig` used for this report (for forensic replay)  |

### 6.2 Supporting models

| Model                | Purpose                                                                                |
|----------------------|----------------------------------------------------------------------------------------|
| `RoutingDecision`    | Stage 1 output: category, interpreter, should-skip, magic-match, details               |
| `ArchiveResult`      | Stage 2 output: extracted files, encryption flags, double-extension list, risk delta   |
| `ExecutionResult`    | Stage 3 output per file: pid, exit code, stdout/stderr previews, timed-out, duration   |
| `MonitorEvent`       | Stage 4 observation: timestamp, monitor, category, detail, structured data             |
| `ScoreBreakdown`     | Stage 5 output: total score, per-category totals, per-category counts, top factors     |
| `IOCResult`          | Stage 6 output: any-match flag, matched hashes/IPs/domains, bonus, source              |
| `Verdict`            | Enum — `CLEAN`, `SUSPICIOUS`, `MALICIOUS`                                              |
| `FileCategory`       | Enum — `EXECUTABLE`, `SCRIPT`, `ARCHIVE`, `IMAGE`, `DOCUMENT`, `SAFE`, `WINDOWS`, `UNKNOWN` |
| `MonitorName`        | Enum — `FileSystem`, `Network`, `Process`, `Privilege`, `ArchiveHandler`, `Router`, `Execution` |

---

## 7. API Specification

### 7.1 Construction

```python
SandboxAnalyzer(
    config:              Optional[SandboxConfig]    = None,
    threat_intel_client: Optional[ThreatIntelClient] = None,
    feedback_sink:       Optional[FeedbackSink]     = None,
)
```

All three arguments have reference implementations, so the minimum
viable instantiation is `SandboxAnalyzer()`.

### 7.2 Primary methods

| Method                                                                  | Purpose                                                                      |
|-------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `analyze(file_path, drone_id, artifact_id=None, archive_password=None, threat_score=None) -> SandboxReport` | Run all eight stages on one artifact                                          |
| `stats` (property)                                                      | Live counters for operational monitoring                                      |

### 7.3 Supporting APIs

Each stage exports a pure-function or class that can be consumed
standalone for unit testing, batch jobs, or custom orchestration:

- `route_file(path, skip_safe_files=True) → RoutingDecision`
- `handle_archive(zip_path, out_dir, config, provided_password=None, depth=0) → ArchiveResult`
- `execute_file(path, config, interpreter=None, work_dir=None, env=None, on_pid=None) → ExecutionResult`
- `build_monitors(pid, log, config) → list[Monitor]`
- `compute_risk_score(events, config) → ScoreBreakdown`
- `correlate_iocs(file_path, events, config, client=None) → IOCResult`
- `determine_verdict(score, config) → Verdict` / `action_for(verdict) → str`
- `ThreatIntelClient`, `LocalThreatIntelClient`, `FeedbackSink`, `LoggingFeedbackSink`, `build_sink(...)`

### 7.4 Integration example

```python
from sandbox_analyzer import (
    SandboxAnalyzer, SandboxConfig,
    ThreatIntelClient, build_sink,
)

class CorrelatorClient(ThreatIntelClient):
    source = "threat_intelligence_correlator"
    def query(self, file_hash, observed_ips, observed_domains):
        return tic_backend.lookup(file_hash, observed_ips, observed_domains)

analyzer = SandboxAnalyzer(
    config=SandboxConfig(),
    threat_intel_client=CorrelatorClient(),
    feedback_sink=build_sink(
        response_manager=response_mgr.apply,
        dashboard=dashboard.emit,
        ml_queue=ml_retraining_queue.enqueue,
    ),
)

report = analyzer.analyze(
    file_path=artifact.pointer_storage,
    drone_id=artifact.drone_id,
    artifact_id=artifact.artifact_id,
    archive_password=feed_metadata.archive_password,
    threat_score=threat_estimate.threat_score,
)
```

---

## 8. Input / Output Specification

### 8.1 Input contract

`analyze()` takes one file path plus structured metadata:

| Argument           | Type           | Required | Meaning                                                                           |
|--------------------|----------------|----------|-----------------------------------------------------------------------------------|
| `file_path`        | str            | Yes      | Absolute path to the artifact on disk (produced by the Ingestion Interceptor)      |
| `drone_id`         | str            | Yes      | Originating drone identifier; carried through to the report and feedback callbacks |
| `artifact_id`      | Optional[str]  | No       | `artifact://…` ID from the Ingestion Interceptor; propagated for correlation      |
| `archive_password` | Optional[str]  | No       | Key from feed metadata for encrypted archives; `None` = not declared              |
| `threat_score`     | Optional[float]| No       | `T_S` from the Game-Theoretic Threat Estimator; recorded for audit, not used for routing |

Preconditions (caller's responsibility — the sandbox does not
re-validate):

- The file exists and is readable. (If it does not, the router records
  a warning and the execution stage emits an `ExecutionResult` with an
  `error` field; the run still completes with a `CLEAN` verdict based
  on zero observed behaviour.)
- The artifact has already been authenticated by the Ingestion Interceptor.
- The caller has chosen to run the sandbox (typically because `T_S ≥ θ_high`).

### 8.2 Integration-seam contracts

**`ThreatIntelClient.query(file_hash, observed_ips, observed_domains) -> dict`**
must return a dict with exactly these four keys:

```
{
  "matched_hashes":  list[str],
  "matched_ips":     list[str],
  "matched_domains": list[str],
  "any_match":       bool,
}
```

**`FeedbackSink`** has three methods that accept a full `SandboxReport`:

- `notify_response_manager(report)` — the Response & Quarantine Manager applies the action.
- `notify_dashboard(report)` — the Security Dashboard logs the full report.
- `queue_for_ml(report)` — the ML retraining queue receives the behavioural trace and label.

### 8.3 Output contract

`SandboxReport.to_dict(include_events=True)` is the stable wire
format consumed by downstream modules. `include_events=False` drops
the event list (replacing it with `event_count`) for
high-volume logging while preserving every other field.

Example (`include_events=False`, verdict = `MALICIOUS`):

```
{
  "report_id":     "sbx_8a0c19d41f52",
  "file_path":     "/var/artifacts/DRN-002/payload.py",
  "file_hash":     "e3b0c44298fc1c14...",
  "drone_id":      "DRN-002",
  "artifact_id":   "artifact://c1d2e3f4",
  "file_category": "script",
  "skipped":       false,
  "skip_reason":   null,
  "risk_score":    85,
  "verdict":       "MALICIOUS",
  "action":        "Block. Alert SOC/SIEM. Flag drone feed as compromised.",
  "created_at":    "2025-10-13T03:05:45.123456+00:00",
  "duration_sec":  2.14,
  "warnings":      [],
  "errors":        [],
  "routing":       { "category": "script", "interpreter": "python3",
                     "should_skip": false, "magic_match": true,
                     "details": "Script — run with declared interpreter" },
  "score_breakdown": { "total_score": 65, "by_category": { "network_connect": 50,
                       "shell_command": 25 }, "event_count": { ... },
                       "top_factors": [ "network_connect (x2 = +50)", "shell_command (x1 = +25)" ] },
  "ioc_result":    { "any_match": true, "matched_hashes": [],
                     "matched_ips": ["203.0.113.42"], "matched_domains": [],
                     "bonus_score": 20, "source": "threat_intelligence_correlator" },
  "execution_results": [ { "pid": 14223, "exit_code": 0, "duration_sec": 1.83,
                           "timed_out": false, "error": null, ... } ],
  "event_count":   3,
  "config_snapshot": { "memory_bytes": 134217728, "cpu_seconds": 20, ... }
}
```

### 8.4 Downstream consumption contract

Downstream modules should consume only the stable fields below; the
rest are audit-only and their schema may evolve:

| Consumer                              | Fields read                                                              |
|---------------------------------------|--------------------------------------------------------------------------|
| Response & Quarantine Manager         | `verdict`, `action`, `drone_id`, `file_path`, `report_id`                |
| Threat Intelligence Correlator (feedback-loop ingress) | `file_hash`, `ioc_result.matched_ips`, `verdict` (to learn from malicious samples) |
| Security Dashboard / SIEM             | Full `to_dict(include_events=True)` — forensic replay                    |
| ML retraining queue                   | `events` categories + `verdict` label                                    |

---

## 9. Sequence Diagrams

### 9.1 Happy path — SAFE CSV

```
Caller               SandboxAnalyzer    Router
  │ analyze(...)        │                  │
  │────────────────────▶│ route_file() ───▶│
  │                     │◀──────────────── │  SAFE, should_skip=True
  │                     │ short-circuit     │
  │                     │ verdict = CLEAN   │
  │                     │ dispatch feedback │
  │◀────────────────────│ SandboxReport     │
```

### 9.2 Archive path (double extension)

```
Caller       SandboxAnalyzer    Router      ArchiveHandler    Scoring   Verdict   Feedback
  │ analyze(zip) │                │              │               │         │         │
  │─────────────▶│ route_file ───▶│              │               │         │         │
  │              │◀────────────── │ ARCHIVE      │               │         │         │
  │              │ handle_archive ──────────────▶│ scan listing │         │         │
  │              │◀────────────────────────────  │ double-ext    │         │         │
  │              │                               │ +30 risk      │         │         │
  │              │ extract + (optionally execute per-file)       │         │         │
  │              │ compute_risk_score ────────────────────────▶ │         │         │
  │              │◀──────────────────────────────────────────── │ total    │         │
  │              │ correlate_iocs (client)                                │         │
  │              │ determine_verdict ──────────────────────────────────▶│         │
  │              │◀─────────────────────────────────────────────────────│ SUSP/MAL │
  │              │ dispatch feedback ────────────────────────────────────────────▶│
  │◀─────────────│ SandboxReport                                                    │
```

### 9.3 Execute + monitor path

```
Caller    Analyzer       Router     execute_file    Monitors     TI-Client   Scoring   FeedbackSink
  │ analyze │               │            │              │            │           │          │
  │────────▶│ route_file ─▶│            │              │            │           │          │
  │         │◀─────────────│ SCRIPT     │              │            │           │          │
  │         │ Popen + preexec_fn setrlimit ───────────▶│            │           │          │
  │         │               │            │              │            │           │          │
  │         │ on_pid(pid) ──────────────▶│              │            │           │          │
  │         │                            │  build monitors(pid) ────▶│            │           │          │
  │         │                            │ target runs  │            │           │          │
  │         │                            │◀────────────▶│  poll every 200ms     │           │          │
  │         │ proc.communicate(timeout) ─▶              │            │           │          │
  │         │◀──── stdout/stderr/exit ───│              │            │           │          │
  │         │ gather events ───────────────────────────│            │           │          │
  │         │ compute_risk_score ─────────────────────────────────────▶          │          │
  │         │ correlate_iocs ────────────────────────────────────▶│            │          │
  │         │◀─────────────────────────────────────────────────── │ IOCResult  │          │
  │         │ determine_verdict ─────────────────────────────────────────────▶│          │
  │         │ dispatch feedback ───────────────────────────────────────────────────────▶│
  │◀────────│ SandboxReport                                                              │
```

---

## 10. Risk Scoring Reference

The default `behavior_weights` are:

```
event category            weight   rationale
─────────────────────────────────────────────────────────────────────
self_replication             40    copies itself into persistence locations
privilege_escalation         35    setuid / effective-capability gain
memory_inject                35    sudden VmRSS spike (payload unpacking)
api_hooking                  30
file_write_executable        30    drops a new binary or script
network_connect              25    any outbound TCP attempt (SYN_SENT or ESTABLISHED)
shell_command                25    shell spawned by a data file
registry_write               20
high_entropy_write           15    packed / encrypted write
dns_lookup                   15
process_spawn                10    generic child process
file_delete                  10
file_system_write             5    low-weight baseline
```

Additive signals bolted onto the behaviour score:

| Signal                              | Points                              | Source                                          |
|-------------------------------------|-------------------------------------|-------------------------------------------------|
| Encrypted archive, no declared key  | `config.encrypted_no_key_score` (25)| Archive Handler                                 |
| Double-extension member in archive  | `config.double_extension_score` (30) per occurrence | Archive Handler                                 |
| Any IOC match                       | `config.ioc_match_bonus` (20)       | IOC correlator                                  |

Verdict bands:

```
score  <  25   →  CLEAN
25 ≤ score < 60 →  SUSPICIOUS
score ≥ 60     →  MALICIOUS
```

Calibration discipline: the approach (weighted additive scoring of
behavioural features) is standard in open-source dynamic-analysis
sandboxes; the specific weights are engineering judgements seeded from
threat severity and are expected to be re-tuned against a labelled
malware corpus during evaluation.

---

## 11. Configuration Reference

Every field of `SandboxConfig`, with defaults:

| Group     | Field                          | Default                                  | Meaning                                                                  |
|-----------|--------------------------------|------------------------------------------|--------------------------------------------------------------------------|
| Routing   | `skip_safe_files`              | `True`                                   | SAFE files return CLEAN without execution                                |
| Routing   | `flag_windows_executables`     | `True`                                   | Windows PE files short-circuit with verdict `SUSPICIOUS`; never executed |
| Archive   | `max_extract_depth`            | 3                                        | Nesting cap for recursive ZIP extraction                                 |
| Archive   | `zip_bomb_ratio`               | 0.005                                    | Abort extraction when compressed/uncompressed < this                      |
| Archive   | `zip_bomb_min_size_bytes`      | 10 MB                                    | Only check ratio above this uncompressed size                             |
| Archive   | `encrypted_no_key_score`       | 25                                       | Risk bump for encrypted archive with no declared key                     |
| Archive   | `double_extension_score`       | 30                                       | Risk bump per double-extension member                                    |
| Execution | `memory_bytes`                 | 128 MB                                   | `RLIMIT_AS` cap                                                          |
| Execution | `cpu_seconds`                  | 20                                       | `RLIMIT_CPU` cap                                                         |
| Execution | `file_bytes`                   | 32 MB                                    | `RLIMIT_FSIZE` cap                                                       |
| Execution | `max_processes`                | 50                                       | `RLIMIT_NPROC` cap                                                       |
| Execution | `wall_timeout_seconds`         | 30                                       | Watchdog kill                                                            |
| Execution | `empty_environment`            | `True`                                   | Run with `env={}`                                                        |
| Execution | `communicate_grace_seconds`    | 2                                        | Grace after wall timeout for `proc.communicate`                           |
| Monitors  | `poll_interval_seconds`        | 0.2                                      | Monitor poll cadence                                                     |
| Monitors  | `enable_filesystem_monitor`    | `True`                                   |                                                                          |
| Monitors  | `enable_network_monitor`       | `True`                                   |                                                                          |
| Monitors  | `enable_process_monitor`       | `True`                                   |                                                                          |
| Monitors  | `enable_privilege_monitor`     | `True`                                   |                                                                          |
| Monitors  | `memory_spike_threshold_kb`    | 51200                                    | RSS jump (KB) that triggers `memory_inject`                              |
| Monitors  | `stdout_capture_bytes` / `stderr_capture_bytes` | 2000 / 2000              | Output caps stored in `ExecutionResult`                                   |
| Lists     | `suspicious_paths`             | see `config.py`                          | Paths that are suspicious to write into                                   |
| Lists     | `suspicious_processes`         | see `config.py`                          | Lateral-movement tools (`wget`, `curl`, `nc`, `sudo`, compilers, cron) — names in this set are recorded as `shell_command` |
| Lists     | `shell_processes`              | `{bash, sh, zsh, dash, fish}`            | Canonical shells; always recorded as `shell_command`                      |
| Lists     | `executable_extensions`        | `(.sh, .py, .elf, .bin, .pl, .rb)`       | Used to promote `file_system_write` to `file_write_executable`            |
| Scoring   | `behavior_weights`             | see §10                                  | Per-category additive weights                                            |
| IOC       | `enable_ioc_correlation`       | `True`                                   |                                                                          |
| IOC       | `ioc_match_bonus`              | 20                                       | Score bump on any IOC match                                              |
| Verdict   | `suspicious_threshold`         | 25                                       |                                                                          |
| Verdict   | `malicious_threshold`          | 60                                       | Must be strictly greater than `suspicious_threshold`                     |
| Feedback  | `enable_feedback_hooks`        | `True`                                   | Disable to suppress all three post-verdict callbacks                     |
| Logging   | `log_level`                    | `"INFO"`                                 | Host installs handlers                                                   |

---

## 12. Security & Threat Model

### 12.1 Adversary model

The attacker's goal is to have a malicious payload complete one or
more harmful actions without tripping the verdict threshold. Known
vectors and mitigations:

| Vector                                                                         | Mitigation in this module                                                                                   |
|--------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Rename a script to look like an image to escape file-extension classification  | Magic-byte inspection beats extension; `#!` / ELF / ZIP / PE all detected by header                          |
| Ship malware inside an encrypted ZIP so automated analysers cannot read it     | Encrypted-no-key is scored as +25 and extraction is skipped — no dictionary attacks                          |
| Hide a binary inside a double-extension archive member (`recon.jpg.sh`)        | Double-extension detection adds +30 per member before extraction                                             |
| Exhaust sandbox memory or CPU to crash analysis                                | Kernel-enforced `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`, `RLIMIT_CORE`                      |
| Fork a legion of children to escape observation                                | `RLIMIT_NPROC` caps total children; `ProcessMonitor` walks the full descendent tree                          |
| Connect to a C2 server quickly then exit before the poll fires                 | Kernel records SYN_SENT in `/proc/net/tcp`; the baseline diff catches the row even after the process exits   |
| Bypass process observation by tampering with `/proc/<PID>/status`              | `/proc` is kernel-maintained; the monitored process cannot rewrite what it reports about itself              |
| Use legitimate-looking behaviour to bias scoring                               | Additive scoring across four independent monitors makes single-action evasion insufficient for `MALICIOUS`   |
| Leverage environment variables or cwd to find host data                        | Empty environment (`env={}`) and isolated temp cwd                                                           |
| Produce a core dump to exfiltrate memory                                       | `RLIMIT_CORE = 0` disables core dumps                                                                        |
| Ship a Windows PE to a Linux sandbox expecting it to be forwarded unanalysed   | Router short-circuit marks PE as `SUSPICIOUS` (quarantine + analyst review); never forwarded as `CLEAN`      |

### 12.2 Non-repudiation

Every `SandboxReport` carries `report_id`, `created_at`, the full
event trace, per-file `ExecutionResult`s, the score breakdown, the
IOC result (including the backend's `source` tag), and a snapshot of
the knobs that produced the decision. Persisting
`report.to_dict(include_events=True)` is sufficient for replay.

### 12.3 Input trust boundary

The analyzer trusts that the caller has:

- authenticated the drone via the Ingestion Interceptor,
- decided (via the Threat Estimator) that this artifact warrants dynamic analysis,
- placed the artifact on a filesystem the analyzer can read.

The analyzer does **not** re-authenticate the source or re-validate
the file format. Invoking `analyze()` on unvetted input is out of
scope and unsupported.

### 12.4 Fail-closed configuration

`SandboxConfig.__post_init__` rejects inconsistent deployments at
construction time (inverted verdict thresholds, zero / negative
resource caps, out-of-range compression ratio, negative behaviour
weights). There is no silent-degrade path for bad configs.

### 12.5 External side effects

- **Subprocess execution.** One child process per analysed file, with
  kernel-enforced caps and a 30-second watchdog.
- **Filesystem.** Temporary directories under the OS default
  (`tempfile.mkdtemp`) for archive extraction and execution cwd; cleaned
  up after each call when owned by the analyzer.
- **Network.** Zero. The sandbox should run on a network-isolated
  host. Network *observation* happens via `/proc/net/tcp` without ever
  opening sockets from the analyzer itself.

---

## 13. Performance Characteristics

### 13.1 Latency budget

| Phase                                | Typical time (Linux, single core)                        |
|--------------------------------------|-----------------------------------------------------------|
| Routing (magic-byte read)            | < 1 ms                                                    |
| Archive extraction (small ZIP)       | 10 – 100 ms                                               |
| Subprocess launch + setrlimit        | 5 – 20 ms                                                 |
| Target execution                     | dominated by the target itself; capped at 30 s            |
| Monitor polling                      | ~1 ms per poll per monitor; 5 polls/sec × 4 monitors      |
| Risk scoring                         | O(n) over events; sub-millisecond for typical n < 1000    |
| IOC correlation                      | dominated by the injected client; reference impl < 1 ms   |
| Verdict + feedback dispatch          | microseconds                                              |
| **Full `analyze()` on a short-lived script** | **0.5 – 2 s**                                      |
| **Full `analyze()` on a long-running target** | **bounded by `wall_timeout_seconds` (30 s default)** |

### 13.2 Memory bounds

| Structure                  | Bound                                                  |
|----------------------------|--------------------------------------------------------|
| Target process             | `config.memory_bytes` (128 MB default) — kernel-enforced |
| Sandbox file writes        | `config.file_bytes` (32 MB default) — kernel-enforced  |
| Child processes            | `config.max_processes` (50 default) — kernel-enforced  |
| Monitor event log          | O(events); unbounded per report but each event is small |
| Per-analysis temp dirs     | Cleaned up on return                                   |

### 13.3 Throughput

Dynamic analysis is expensive by design. A single analyzer instance
sustains tens of analyses per minute for short-lived targets; long
targets are bounded by `wall_timeout_seconds`. Because each analyser
instance owns only ephemeral per-call state, horizontal scaling is
trivial: one instance per ingestion worker, sharing the two injected
dependencies (both of which are thread-safe).

---

## 14. Testing Strategy

50 tests live in `sandbox_analyzer/tests/test_analyzer.py`. Run with:

```bash
python -m unittest sandbox_analyzer.tests.test_analyzer -v
# or
python -m pytest sandbox_analyzer/tests/ -v
```

Coverage groups:

| Group                      | Count | Highlights                                                                                                        |
|----------------------------|:-----:|-------------------------------------------------------------------------------------------------------------------|
| `TestSandboxConfig`        | 7     | Defaults, overrides, and every `__post_init__` rejection (inverted thresholds, zero limits, bad ratio, negative weights) |
| `TestFileRouter`           | 6     | Magic-byte precedence, CSV/ZIP/EXE detection, interpreter selection, unknown-type                                 |
| `TestArchiveHandler`       | 7     | Plain extraction, encrypted-no-key, encrypted-with-metadata-key, double-extension, depth cap, double-extension predicate (true/false) |
| `TestScoringAndVerdict`    | 6     | Empty, single-write, suspicious band, malicious band, unknown categories → 0, top-factors ordering                |
| `TestIOC`                  | 7     | Hash / IP match, structured `data` field extraction, loopback filter, bonus application, disabled path, error swallowing, domain regex rejects filenames |
| `TestFeedbackSinks`        | 3     | Base no-op, logging sink, `build_sink` composition                                                                |
| `TestAnalyzerStatic`       | 8     | Cross-platform paths: SAFE skip, Windows PE → `SUSPICIOUS` (not forwarded), archive double-ext, JSON round-trip, feedback invocation + isolation, stats, Windows-PE counter |
| `TestAnalyzerLive`         | 1     | Linux-only integration test (auto-skipped elsewhere)                                                              |
| `TestHelpers`              | 5     | `compute_file_hash` stable + missing file, `is_encrypted_zip` positive (via byte-level flag patching) and negative, `action_for`         |

Invariants specifically enforced:

- All three verdict bands (`CLEAN` / `SUSPICIOUS` / `MALICIOUS`) are
  reachable without live execution — in particular, Windows PE input
  reaches `SUSPICIOUS` without executing a subprocess.
- Unknown event categories contribute zero — new monitors can be added
  without breaking scoring.
- `SandboxReport.to_dict()` round-trips through `json.dumps`.
- Feedback-channel exceptions never propagate to the caller.
- Domain-extraction regex does not false-match bare filenames
  (`photo.jpg`) — only multi-label FQDNs reach the threat-intel client.
- `LocalThreatIntelClient.source == "local_stub"` so a dashboard can
  tell the reference implementation from a real correlator at a glance.

---

## 15. Operations

### 15.1 Deployment

Single-process Python library. Deploy on Linux edge nodes with:

1. Python ≥ 3.10
2. `psutil` (required — used by `ProcessMonitor`)
3. Network isolation — the host should not have outbound connectivity
   so that observed C2 attempts fail cleanly into `SYN_SENT` rows the
   network monitor can detect.
4. A writable temp directory for extraction / execution cwds.

The host process is responsible for:

- Constructing the `SandboxConfig` (or accepting the defaults).
- Wiring a real `ThreatIntelClient` subclass pointing at the Threat
  Intelligence Correlator.
- Wiring a real `FeedbackSink` (or `build_sink(...)`) to the Response
  & Quarantine Manager, Security Dashboard, and ML retraining queue.
- Installing log handlers for the `sandbox_analyzer` package logger.

### 15.2 Monitoring checklist

Scrape `SandboxAnalyzer.stats` periodically and alert on:

| Signal                                           | Alert when                                                                    |
|--------------------------------------------------|-------------------------------------------------------------------------------|
| `total_malicious / total_analyzed`               | Sudden shift up or down by > 30 % vs. recent baseline                         |
| `total_errors / total_analyzed`                  | > 1 % — indicates environment issues (missing `psutil`, read-only `/proc`)    |
| `total_execution_runs / total_analyzed`          | Drops toward zero — most submissions are hitting SAFE / WINDOWS short-circuit |
| `last_report_id` unchanged for multiple minutes  | No traffic reaching the sandbox                                               |
| p99 `duration_sec` from reports                  | Approaching `wall_timeout_seconds` — targets are timing out                   |

### 15.3 Runbook snippets

- **Sandbox CPU saturated.** Lower `config.wall_timeout_seconds`
  temporarily; more submissions will bucket into `SUSPICIOUS` via
  timeouts rather than completing analysis. Review whether the Threat
  Estimator is routing too many submissions to HIGH.
- **`psutil` import fails on startup.** `pip install psutil` and
  restart. Without it, `ProcessMonitor` becomes a no-op and shell /
  process spawn events are missed.
- **Threat Intelligence Correlator down.** The sandbox swallows
  `ThreatIntelClient.query()` exceptions and continues; the report
  will show `ioc_result.source` with a non-stub value and `any_match =
  False`. No action required beyond reviving the correlator.
- **Config rejected on startup.** Read the `ValueError` raised from
  `SandboxConfig.__post_init__`; fix the offending field; redeploy.
- **All reports come back `CLEAN` unexpectedly.** Inspect a sample
  `SandboxReport`: check `skipped`/`skip_reason` first (likely SAFE
  short-circuit), then `execution_results` (are Linux stages enabled?),
  then `events` (is the monitor poll cadence too slow for short-lived
  targets?).

---

## 16. Risk Assessment

| Risk                                                                         | Likelihood | Impact | Mitigation                                                                                                         |
|------------------------------------------------------------------------------|:----------:|:------:|---------------------------------------------------------------------------------------------------------------------|
| Behaviour weights diverge from the observed malware distribution             | High (day 0) | Medium | Weights live in `SandboxConfig.behavior_weights`; refresh from a labelled corpus during evaluation without code changes |
| Short-lived targets exit before monitors poll                                 | Medium     | Medium | `config.poll_interval_seconds` is tunable; the analyzer runs one final sweep after the process exits               |
| Host `/proc` not available (containers without `/proc`, non-Linux)           | Medium     | High   | Module short-circuits Stages 3 and 4 with an explicit warning in the report; deploy only on Linux in production    |
| `ThreatIntelClient` backend is flaky                                         | Medium     | Low    | Exceptions are swallowed; verdicts continue without IOC bonus                                                      |
| `FeedbackSink` raises in one channel                                         | Medium     | Low    | Per-channel exception isolation; other channels still fire                                                         |
| Malicious archive nests ZIPs beyond `max_extract_depth`                      | Low        | Low    | Depth cap halts recursion and flags the truncation                                                                 |
| Attacker uses a platform-specific payload we cannot execute (Windows PE)     | Medium     | Medium | Flagged for manual review (`FileCategory.WINDOWS`); a Windows-VM adapter may be added as a separate module         |
| Host forgets to install `psutil`                                             | Low        | Medium | `ProcessMonitor` becomes a safe no-op; README + runbook call this out                                              |
| Monitor noise from other processes on the host leaks into `NetworkMonitor`   | Medium     | Low    | Network baseline diff is per-analysis; deploy on dedicated / isolated hosts to minimise noise                       |
| Sandbox host is compromised and subverts the monitors                        | Low        | High   | Out of scope; the sandbox's security depends on host integrity — run under host-level EDR and restricted access     |

---

## 17. Glossary

- **C2 server** — Command & Control: an attacker-controlled host that a
  compromised system "calls home" to for instructions and payloads.
- **IOC** — Indicator of Compromise: a piece of evidence (hash, IP,
  domain, path) that a system has been compromised.
- **Magic bytes** — The first few bytes of a file that identify its
  true format regardless of filename extension.
- **`/proc`** — The Linux pseudo-filesystem that exposes kernel state
  as files; used here for every monitor except `ProcessMonitor`
  (which uses `psutil`).
- **`setrlimit` / RLIMIT_\*** — POSIX system call and resource-limit
  identifiers used to cap memory (AS), CPU time (CPU), file size
  (FSIZE), child processes (NPROC), and core dumps (CORE).
- **ZIP bomb** — A crafted archive whose uncompressed size is many
  orders of magnitude larger than its compressed size.
- **Double extension** — Disguise where a dangerous final extension
  (`.sh`, `.exe`) is hidden behind a benign middle extension
  (`.jpg`, `.pdf`).
- **Shebang** — The `#!interpreter` line at the start of a Unix
  script that tells the kernel how to execute it.
- **Stackelberg equilibrium** — The leader-follower game solution
  produced by the Threat Estimator upstream of this module; the
  sandbox itself does not solve any games.
- **SIGXCPU** — Signal delivered to a process that exceeds its
  `RLIMIT_CPU` allowance.
