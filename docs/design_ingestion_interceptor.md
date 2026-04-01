# Design Document: Ingestion Interceptor

| Field            | Value                                                                   |
|------------------|-------------------------------------------------------------------------|
| **Version**      | 2.0                                                                     |
| **Status**       | Implemented                                                             |
| **Module**       | `ingestion_interceptor/`                                                |
| **Authors**      | Sangam Kumar Mishra                                                     |
| **PI**           | Dr. Padmalochan Bera, IIT Bhubaneswar                                  |
| **Sponsor**      | Bharat Electronics Ltd (BEL)                                            |
| **Project**      | Detection and Prevention of Malware and Malicious File Injection in RPA/Drone Feeds |
| **Created**      | 2025-10-13                                                              |
| **Last Updated** | 2026-04-01                                                              |
| **Depends On**   | Python 3.9+, `hashlib`, `hmac`, `dataclasses`, `json`, `uuid`, `logging` |
| **Depended On By** | Game-Theoretic Threat Estimator, Metadata Sanitizer, Security Dashboard |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Goals and Non-Goals](#2-goals-and-non-goals)
3. [System Context](#3-system-context)
4. [Architecture Overview](#4-architecture-overview)
5. [Component Design](#5-component-design)
6. [Data Models](#6-data-models)
7. [API Specification](#7-api-specification)
8. [Sequence Diagrams](#8-sequence-diagrams)
9. [Input/Output Specification](#9-inputoutput-specification)
10. [Security Considerations](#10-security-considerations)
11. [Configuration Reference](#11-configuration-reference)
12. [Requirements](#12-requirements)
13. [Performance Requirements](#13-performance-requirements)
14. [Dependencies](#14-dependencies)
15. [Testing Strategy](#15-testing-strategy)
16. [Deployment and Operations](#16-deployment-and-operations)
17. [Risk Assessment](#17-risk-assessment)
18. [Implementation Roadmap](#18-implementation-roadmap)
19. [Glossary](#19-glossary)

---

## 1. Executive Summary

The **Ingestion Interceptor** is the first line of defence in the Multi-Layered
Malware Detection and Threat Prevention System for drone and Remotely Piloted
Aircraft (RPA) data streams. Developed under a Bharat Electronics Ltd (BEL)
sponsored research project at IIT Bhubaneswar, this module sits at the edge
network boundary between untrusted drone platforms and the operational security
infrastructure.

The Ingestion Interceptor acts as a **secure data funnel** that prevents
uncontrolled input from entering the analysis pipeline. Every incoming drone
submission --- containing video, imagery, telemetry, and metadata --- passes
through a seven-stage processing pipeline:

1. **Structure Validation** --- verifies required fields, data types, timestamps,
   size limits, and path traversal defences.
2. **Device Authentication** --- verifies drone identity through a device
   registry, HMAC-SHA256 signature verification, and configurable unknown-device
   policy enforcement.
3. **Metadata Extraction** --- extracts and normalizes mission context,
   geolocation, telemetry summaries, and additional metadata with
   pre-sanitization.
4. **Payload Security Analysis** --- applies a 9-point security heuristic to
   every payload file, detecting encrypted content, nested archives, executable
   extensions, MIME mismatches, and other indicators.
5. **Checksum Verification** --- computes and compares SHA-256 checksums to
   detect file tampering.
6. **Artifact Cataloging** --- generates unique artifact identifiers, storage
   pointers, and thumbnail references.
7. **Output Assembly** --- produces a structured `IngestResult` containing
   `IngestMetadata` and `ArtifactRecord` entries.

The output feeds directly into the **Game-Theoretic Threat Estimator**, which
uses the extracted metadata, security flags, device reputation, and zone risk
to compute a Stackelberg-equilibrium threat score (T_S) that determines the
inspection depth applied by downstream detection engines.

The module also supports a **secure uplink channel** from the control center,
enabling real-time quarantine commands, device revocations, zone risk updates,
and dynamic parameter adjustment --- fulfilling the BEL proposal requirement
for a live feedback loop between the security dashboard and the edge detection
engine.

---

## 2. Goals and Non-Goals

### 2.1 Goals

| ID   | Goal                                                                                   |
|------|----------------------------------------------------------------------------------------|
| G-1  | Authenticate source devices using metadata (timestamps, drone ID, geolocation) per BEL proposal Section 4.2 |
| G-2  | Validate data format, structure, and integrity of every incoming drone submission       |
| G-3  | Extract and record metadata: drone ID, mission zone, timestamps, encryption status     |
| G-4  | Identify ZIP/encrypted file types and flag them for deferred deep analysis              |
| G-5  | Act as a secure data funnel preventing uncontrolled input into the analysis pipeline    |
| G-6  | Support secure uplink communication from the control center (quarantine commands, dynamic parameter adjustment, live feedback loop) |
| G-7  | Produce structured output compatible with the Game-Theoretic Threat Estimator input contract |
| G-8  | Provide configurable, defence-in-depth security posture with tuneable thresholds       |
| G-9  | Maintain processing statistics for operational monitoring                               |
| G-10 | Support both class-based and functional API entry points                                |

### 2.2 Non-Goals

| ID    | Non-Goal                                                                              |
|-------|---------------------------------------------------------------------------------------|
| NG-1  | Deep content inspection (malware scanning, AI/ML classification, sandboxing) --- handled by downstream Multi-Layer Malware Detection Engine |
| NG-2  | Full metadata sanitization (EXIF scrubbing, embedded script removal) --- handled by Metadata Sanitizer module |
| NG-3  | Threat score computation or game-theoretic analysis --- handled by Game-Theoretic Threat Estimator |
| NG-4  | Long-term artifact storage management --- handled by storage infrastructure            |
| NG-5  | Security dashboard rendering --- handled by Logging & Feedback Loop layer              |
| NG-6  | Real-time video stream processing --- the module handles discrete submission payloads  |

---

## 3. System Context

The Ingestion Interceptor operates within a three-layer architecture as defined
in the BEL project proposal. The following diagram shows the complete system
with all modules and the data flow between them.

### 3.1 Full System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1: DRONE / RPA PLATFORM                       │
│                                                                             │
│   Remotely Piloted Aircraft transmitting video, images, telemetry,          │
│   and metadata over secure or insecure uplink channels                      │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
                     Video, Images, Telemetry, Metadata
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  LAYER 2: EDGE MALWARE DETECTION ENGINE                     │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 1: INGESTION INTERCEPTOR  ◄── THIS MODULE        │  │
│  │                                                                       │  │
│  │  Validate ──► Authenticate ──► Extract Metadata ──► Analyze Payloads │  │
│  │      ──► Verify Checksums ──► Create Artifacts ──► Build Output      │  │
│  │                                                                       │  │
│  │  ◄── Uplink Receiver (quarantine, config updates, device revocation) │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                    IngestResult (metadata + artifacts)                       │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 2: METADATA EXTRACTOR                             │  │
│  │  (Integrated within Ingestion Interceptor as a sub-component)        │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 3: GAME-THEORETIC THREAT ESTIMATOR                │  │
│  │                                                                       │  │
│  │  Computes T_S (threat score 0.0 - 1.0) using Stackelberg game        │  │
│  │  theory. Inputs: security flags, reputation, zone risk, file          │  │
│  │  attributes, mission sensitivity.                                     │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                        T_S determines inspection level                      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 4: INSPECTION STRATEGY SELECTOR                    │  │
│  │                                                                       │  │
│  │  T_S < 0.4  ──► Low    ──► Signature Scan Only                       │  │
│  │  T_S 0.4-0.7 ─► Medium ──► Signature Scan + AI/ML Classifier        │  │
│  │  T_S >= 0.7 ──► High   ──► Signature + AI/ML + Sandbox Execution    │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 5: MULTI-LAYER MALWARE DETECTION ENGINE            │  │
│  │                                                                       │  │
│  │  ┌──────────────────┐ ┌───────────────┐ ┌────────────────────────┐   │  │
│  │  │ Signature Scanner│ │ AI/ML         │ │ Sandbox Executor       │   │  │
│  │  │ (YARA, ClamAV)   │ │ Classifier    │ │ (Isolated environment) │   │  │
│  │  └──────────────────┘ └───────────────┘ └────────────────────────┘   │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 6: METADATA SANITIZER                             │  │
│  │                                                                       │  │
│  │  EXIF scrubbing, embedded script removal, header sanitization,        │  │
│  │  steganography pre-screening                                          │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 7: THREAT INTELLIGENCE CORRELATOR                  │  │
│  │                                                                       │  │
│  │  Cross-references findings against known threat databases,            │  │
│  │  IOCs, and historical incident data                                   │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 8: RESPONSE & QUARANTINE MANAGER                   │  │
│  │                                                                       │  │
│  │  Automated response actions: quarantine, alert, block, release        │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                          │
└──────────────────────────────────┼──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  LAYER 3: LOGGING & FEEDBACK LOOP                           │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              MODULE 9: SECURITY DASHBOARD                             │  │
│  │                                                                       │  │
│  │  Real-time visualization, audit logs, alerting, uplink command        │  │
│  │  dispatch back to edge modules                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│                    ▲                                       │                 │
│                    │         Feedback Loop                 │                 │
│                    └───────────────────────────────────────┘                 │
│                              (Uplink commands to Ingestion Interceptor)      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Ingestion Interceptor Boundary Context

```
                   ┌───────────────────────────────────────────────────────┐
                   │              TRUST BOUNDARY                           │
                   │                                                       │
  ┌────────┐       │  ┌─────────────────────────────────────────────────┐  │
  │ Drone  │ ─────────►│         INGESTION INTERCEPTOR                  │  │
  │ / RPA  │  JSON  │  │                                                 │  │
  │Platform│ payload│  │  Input:  Raw drone submission JSON              │  │
  └────────┘       │  │  Output: IngestResult (metadata + artifacts)    │  │
                   │  │                    OR error report               │  │
                   │  └──────────────┬──────────────────────────────────┘  │
                   │                 │                                      │
                   │                 │ IngestResult                         │
                   │                 ▼                                      │
                   │  ┌─────────────────────────────────────────────────┐  │
                   │  │  Game-Theoretic Threat Estimator                │  │
                   │  │  Consumes: ingest_metadata, artifact_records    │  │
                   │  │  Produces: T_S (threat score 0.0 - 1.0)        │  │
                   │  └─────────────────────────────────────────────────┘  │
                   │                                                       │
  ┌────────────┐   │  ┌─────────────────────────────────────────────────┐  │
  │ Security   │ ─────►│  Uplink Receiver (inside Interceptor)          │  │
  │ Dashboard  │ cmds │  │  Commands: QUARANTINE, RELEASE, REVOKE_DEVICE, │
  │ / Control  │   │  │  UPDATE_ZONE_RISK, UPDATE_CONFIG, FORCE_RESCAN │  │
  │ Center     │   │  └─────────────────────────────────────────────────┘  │
  └────────────┘   │                                                       │
                   └───────────────────────────────────────────────────────┘
```

---

## 4. Architecture Overview

### 4.1 Module Structure

```
ingestion_interceptor/
├── __init__.py              Public API surface and package exports
├── config.py                InterceptorConfig dataclass (all tuneable parameters)
├── models.py                Data model definitions (6 dataclasses)
├── validator.py             Structure and constraint validation
├── authenticator.py         Device registry, signature verification, auth orchestration
├── payload_analyzer.py      9-point security heuristic analysis and risk scoring
├── checksum_verifier.py     SHA-256 file integrity verification and URI resolution
├── metadata_extractor.py    Mission context, geo, telemetry, additional metadata
├── artifact_manager.py      Artifact ID generation, storage pointers, thumbnails
├── uplink.py                Control center uplink command handling
├── interceptor.py           Main orchestrator (7-stage pipeline)
└── tests/
    └── test_interceptor.py  31 unit tests across all components
```

### 4.2 Component Dependency Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                         interceptor.py                               │
│                    (IngestionInterceptor class)                       │
│                                                                      │
│  Orchestrates all components in a 7-stage sequential pipeline        │
└───┬──────┬──────┬──────┬──────┬──────┬──────┬───────────────────────┘
    │      │      │      │      │      │      │
    ▼      │      │      │      │      │      │
┌────────┐ │      │      │      │      │      │
│config  │ │      │      │      │      │      │
│.py     │◄┼──────┼──────┼──────┼──────┼──────┘ (shared by all)
└────────┘ │      │      │      │      │
           ▼      │      │      │      │
    ┌───────────┐ │      │      │      │
    │validator  │ │      │      │      │
    │.py        │ │      │      │      │
    └───────────┘ │      │      │      │
                  ▼      │      │      │
    ┌──────────────────┐ │      │      │
    │authenticator.py  │ │      │      │
    │                  │ │      │      │
    │ DeviceRegistry   │ │      │      │
    │ SignatureVerifier │ │      │      │
    │ Authenticator    │ │      │      │
    └──────────────────┘ │      │      │
                         ▼      │      │
    ┌───────────────────────┐   │      │
    │metadata_extractor.py  │   │      │
    │                       │   │      │
    │ Mission, Geo,         │   │      │
    │ Telemetry, Additional │   │      │
    └───────────────────────┘   │      │
                                ▼      │
    ┌──────────────────────────────┐   │
    │payload_analyzer.py           │   │
    │                              │   │
    │ 9 security checks            │   │
    │ Risk scoring                 │   │
    │ Threat note generation       │   │
    └──────────────────────────────┘   │
                                       ▼
    ┌──────────────────────┐   ┌────────────────────┐
    │checksum_verifier.py  │   │artifact_manager.py │
    │                      │   │                    │
    │ SHA-256 computation  │   │ ID generation      │
    │ URI resolution       │   │ Storage pointers   │
    │ Integrity matching   │   │ Thumbnail refs     │
    └──────────────────────┘   └────────────────────┘

    ┌──────────────────────────────────────────────────┐
    │uplink.py                                         │
    │                                                  │
    │ UplinkReceiver   (command queue, polling)        │
    │ UplinkCommandHandler (dispatch + state mutation) │
    │                                                  │
    │ Modifies: authenticator registry, zone risk map, │
    │           quarantine set                         │
    └──────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────┐
    │models.py                                         │
    │                                                  │
    │ GeoLocation, PayloadEntry, DroneSubmission,      │
    │ ArtifactRecord, IngestMetadata, IngestResult     │
    │                                                  │
    │ (imported by all modules above)                  │
    └──────────────────────────────────────────────────┘
```

### 4.3 Data Flow Through the Pipeline

```
  Raw JSON ──► validate_submission()
                    │
                    │ errors? ──► REJECT (IngestResult.success=False)
                    │
                    ▼
              DroneSubmission.from_dict()
                    │
                    ▼
              Authenticator.authenticate()
                    │
                    │ status="rejected"? ──► REJECT
                    │
                    ▼
              extract_mission_context()
              extract_geo_metadata()
              extract_telemetry_summary()
              extract_additional_metadata()
                    │
                    ▼
              ┌─────────────────────────┐
              │  FOR EACH payload:      │
              │                         │
              │  analyze_payload()      │──► security_flags[]
              │  verify_checksum()      │──► checksum_verified
              │  create_artifact_record │──► ArtifactRecord
              └─────────┬───────────────┘
                        │
                        ▼
              Build IngestMetadata
              (aggregate flags, zone risk, threat notes)
                        │
                        ▼
              IngestResult(success=True,
                  ingest_metadata=...,
                  artifact_records=[...])
```

---

## 5. Component Design

### 5.1 `config.py` --- Configuration

**Purpose:** Centralizes all tuneable parameters into a single immutable-style
dataclass. Every other module receives its configuration through this object,
ensuring consistent behaviour across the pipeline.

**Design rationale:** A single configuration dataclass avoids scattered magic
constants and makes the system testable by allowing callers to inject different
configurations per test case. Default values are chosen for a balanced security
posture suitable for field deployment.

**Key parameter groups:**
- **Validation** --- `require_signature`, `max_payload_size_bytes`,
  `max_payloads_per_submission`, `allowed_mime_types`
- **Security thresholds** --- `large_binary_threshold`, `suspicious_mime_types`,
  `suspicious_extensions`
- **Authentication** --- `auth_backend`, `auth_timeout_seconds`,
  `unknown_device_policy`
- **Checksum** --- `checksum_algorithm`, `verify_checksums`
- **Storage** --- `storage_backend`, `storage_base_path`, `artifact_uri_prefix`
- **Zone risk** --- `default_zone_risk`
- **Logging** --- `log_level`, `structured_logging`
- **Uplink** --- `uplink_enabled`, `uplink_endpoint`,
  `uplink_poll_interval_seconds`

### 5.2 `models.py` --- Data Models

**Purpose:** Defines typed dataclasses for every entity that flows through the
pipeline, from raw input parsing to final output assembly.

**Design rationale:** Typed dataclasses provide compile-time-like safety for
field access, self-documenting APIs, and straightforward serialization via
`to_dict()` methods. Every model includes a `from_dict()` class method for
safe deserialization with fallback defaults, preventing `KeyError` crashes on
malformed input.

**Six dataclasses:**
- `GeoLocation` --- latitude, longitude, altitude with validation-aware parsing
- `PayloadEntry` --- individual file metadata including encryption/container flags
- `DroneSubmission` --- complete parsed input with all optional fields
- `ArtifactRecord` --- per-file output record with security analysis results
- `IngestMetadata` --- aggregated submission metadata for downstream consumers
- `IngestResult` --- top-level pipeline output (success path or error path)

### 5.3 `validator.py` --- Structure Validation

**Purpose:** First-pass validation of the raw JSON dict before any processing
occurs. Rejects structurally invalid submissions early, preventing downstream
modules from operating on malformed data.

**Validation checks performed:**
1. Required top-level fields: `drone_id`, `timestamp`, `payloads`
2. `drone_id` is a non-empty string
3. `timestamp` is a valid ISO 8601 string; warns if >24h in the future
4. `payloads` is a non-empty list, within count limits
5. Signature presence enforced when `require_signature=True`
6. Each payload has `type`, `filename`, `mime`, `size_bytes`
7. `size_bytes` is a non-negative number within configured maximum
8. MIME type is within the allowed whitelist (warning, not fatal)
9. Filename is a non-empty string without path traversal characters (`/`, `\`)

**Return contract:** Returns `(errors: List[str], warnings: List[str])`. Errors
are fatal and halt the pipeline. Warnings are informational and propagated to
the output.

### 5.4 `authenticator.py` --- Device Authentication

**Purpose:** Three-layer authentication system that verifies the identity and
trust status of the submitting drone device.

**Architecture:**

```
┌────────────────────────────────────────────────────────────────────┐
│                        Authenticator                               │
│                   (orchestration layer)                             │
│                                                                    │
│  ┌────────────────────┐    ┌──────────────────────────────────┐   │
│  │  DeviceRegistry     │    │  SignatureVerifier                │   │
│  │                     │    │                                   │   │
│  │  lookup(drone_id)   │    │  verify(drone_id, signature,     │   │
│  │  register_device()  │    │         payload_hash)             │   │
│  │  revoke_device()    │    │                                   │   │
│  │  list_devices()     │    │  Schemes: HMAC-SHA256             │   │
│  │                     │    │  (Ed25519 planned)                │   │
│  │  Backends:          │    │                                   │   │
│  │  - In-memory dict   │    │  Key store: drone_id -> secret    │   │
│  │  - JSON file        │    │                                   │   │
│  └────────────────────┘    └──────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

**Authentication flow:**
1. Look up `drone_id` in the device registry.
2. If not found, apply `unknown_device_policy` (`flag` / `reject` / `allow`).
3. If found, check for revocation status.
4. If a cryptographic signature is provided, verify it using HMAC-SHA256 against
   the submission's payload hash. Failed signature verification downgrades trust.
5. Return `AuthResult` with status, reputation, trust flag, and detail dict.

**`AuthResult.status` values:**
- `authenticated` --- device found, trusted, signature valid (if checked)
- `untrusted` --- device found but not trusted, or signature verification failed
- `unknown` --- device not in registry, `flag` or `allow` policy applied
- `rejected` --- device not in registry with `reject` policy, or device revoked
- `error` --- internal authentication failure

### 5.5 `payload_analyzer.py` --- Security Heuristic Analysis

**Purpose:** Applies a 9-point security heuristic to each individual payload
file, producing a set of security flags that feed into risk scoring and
downstream threat estimation.

**Security checks:**

| #  | Flag                     | Severity   | Trigger Condition                                                  |
|----|--------------------------|------------|--------------------------------------------------------------------|
| 1  | `encrypted_payload`      | medium     | `payload.encryption == True`                                       |
| 2  | `nested_archive`         | medium     | `payload.container == True`                                        |
| 3  | `large_binary`           | low        | `payload.size_bytes >= large_binary_threshold` (default 10 MB)     |
| 4  | `suspicious_mime`        | high       | MIME type in `suspicious_mime_types` set                            |
| 5  | `executable_file`        | critical   | File extension in `suspicious_extensions` set (.exe, .dll, etc.)   |
| 6  | `double_extension`       | high       | Filename has 2+ dots with final extension in suspicious set        |
| 7  | `hidden_file`            | medium     | Filename starts with `.` (Unix hidden file convention)             |
| 8  | `zero_size_file`         | medium     | `size_bytes == 0` for video, image, or archive types               |
| 9  | `mime_extension_mismatch`| medium     | Declared MIME does not match expected extensions for that MIME type |

**Risk scoring:** `compute_payload_risk_score()` computes a normalized score
(0.0--1.0) from the set of flags using severity weights:

```
critical = 1.0,  high = 0.7,  medium = 0.4,  low = 0.2
score = min(1.0, sum(weights) / 3.0)
```

This risk score provides quick triage before the more sophisticated
game-theoretic analysis.

**Threat notes:** `generate_threat_notes()` produces human-readable notes
combining security flags and authentication status, used for dashboard display
and audit logging.

### 5.6 `checksum_verifier.py` --- Integrity Verification

**Purpose:** Computes and verifies SHA-256 checksums for payload files to detect
tampering between the drone platform and the edge ingestion point.

**Capabilities:**
- `compute_file_checksum()` --- streams a file from disk in 64 KB chunks,
  computing the hash without loading the entire file into memory.
- `compute_bytes_checksum()` --- computes the hash of raw bytes (used for
  submission-level payload hashing during authentication).
- `verify_checksum()` --- compares a computed checksum against a declared
  expected value. Returns `True` (match), `False` (mismatch / possible
  tampering), or `None` (verification skipped).
- `resolve_file_path()` --- resolves `file:/` URIs and relative paths to local
  filesystem paths. Returns `None` for remote URIs (`s3://`, `minio://`) that
  cannot be verified locally.

**Supported algorithms:** SHA-256 (default), SHA-1, SHA-512, MD5.

**Stub checksum handling:** Checksums ending in `...` (e.g., `a1b2c3d4...`) are
recognized as placeholders and silently skipped.

### 5.7 `metadata_extractor.py` --- Metadata Extraction

**Purpose:** Extracts, normalizes, and pre-sanitizes metadata from drone
submissions to produce structured data for downstream analysis.

**Four extraction functions:**

1. **`extract_mission_context()`** --- Extracts `mission_id`, `mission_zone`,
   `operator_id`, `firmware_version`, and `mission_sensitivity` (from
   `additional_metadata`). Normalizes sensitivity to lowercase.

2. **`extract_geo_metadata()`** --- Validates geolocation coordinates with
   sanity bounds:
   - Latitude: -90 to +90
   - Longitude: -180 to +180
   - Altitude: -500 m to 100,000 m
   Returns `None` if any coordinate is out of range.

3. **`extract_telemetry_summary()`** --- Passes through telemetry data while
   detecting anomalies:
   - Battery level outside 0--100%
   - Negative speed
   - Signal strength outside 0--100
   - Heading outside 0--360 degrees
   Anomalies are appended as a `telemetry_anomalies` list.

4. **`extract_additional_metadata()`** --- Pre-sanitization step that:
   - Strips dangerous keys: `__proto__`, `constructor`, `prototype`, `eval`,
     `exec`
   - Truncates string values exceeding 10,000 characters
   - Returns `None` if no safe keys remain

### 5.8 `artifact_manager.py` --- Artifact Management

**Purpose:** Generates unique identifiers, storage pointers, and thumbnail
references for each payload, creating the `ArtifactRecord` objects that
downstream modules use to locate and process files.

**Key functions:**
- `generate_artifact_id()` --- produces `artifact://<16-hex-chars>` URIs
- `generate_ingest_id()` --- produces `ingest_<12-hex-chars>` identifiers
- `build_storage_pointer()` --- constructs storage URIs based on backend:
  - Filesystem: `<storage_base_path>/<drone_id>/<filename>`
  - S3/MinIO: `<artifact_uri_prefix>/<drone_id>/<ingest_id>/<unique>_<filename>`
- `resolve_storage_pointer()` --- uses the payload's existing URI if present,
  otherwise constructs one
- `generate_thumbnail_ref()` --- produces `thumb://<12-hex-chars>` for image
  and video payloads
- `create_artifact_record()` --- assembles a complete `ArtifactRecord`

### 5.9 `uplink.py` --- Control Center Communication

**Purpose:** Enables bidirectional communication from the control center to the
edge interceptor, supporting real-time operational commands.

**Architecture:**

```
┌──────────────────────┐           ┌──────────────────────────────┐
│  Control Center /    │           │  UplinkReceiver              │
│  Security Dashboard  │ ─────────►│                              │
│                      │  commands │  Modes:                      │
│  Dispatches:         │           │  - memory (unit testing)     │
│  - Quarantine        │           │  - file   (JSON file watch)  │
│  - Release           │           │  - gRPC   (production)       │
│  - Revoke Device     │           │  - MQTT   (production)       │
│  - Update Zone Risk  │           │                              │
│  - Update Config     │           │  Queue + acknowledgement     │
│  - Force Rescan      │           └───────────┬──────────────────┘
└──────────────────────┘                       │
                                               ▼
                                ┌──────────────────────────────┐
                                │  UplinkCommandHandler         │
                                │                              │
                                │  Dispatch table:             │
                                │  QUARANTINE ──► add to set   │
                                │  RELEASE    ──► remove       │
                                │  REVOKE     ──► registry mut │
                                │  ZONE_RISK  ──► risk map mut │
                                └──────────────────────────────┘
```

**Command types:**

| Command             | Target              | Effect                                              |
|---------------------|---------------------|------------------------------------------------------|
| `QUARANTINE`        | `ingest_id`         | Adds ingest ID to quarantine set                     |
| `RELEASE`           | `ingest_id`         | Removes ingest ID from quarantine set                |
| `REVOKE_DEVICE`     | `drone_id`          | Sets `trusted=False, revoked=True` in device registry|
| `UPDATE_ZONE_RISK`  | `*`                 | Updates zone risk map (params: `zone`, `risk`)       |
| `UPDATE_CONFIG`     | `*`                 | Reserved for dynamic configuration updates           |
| `FORCE_RESCAN`      | `ingest_id`         | Reserved for triggering re-analysis                  |

### 5.10 `interceptor.py` --- Main Orchestrator

**Purpose:** The `IngestionInterceptor` class ties all modules together into
a coherent seven-stage sequential pipeline. It is the primary entry point for
processing drone submissions.

**Initialization parameters:**
- `config` --- `InterceptorConfig` instance (or default)
- `device_registry` --- dict mapping `drone_id` to device info
- `zone_risk_lookup` --- dict mapping zone names to risk scores
- `key_store` --- dict mapping `drone_id` to HMAC shared secrets

**Processing pipeline (`process()` method):**
1. Process any pending uplink commands
2. Validate submission structure
3. Parse into `DroneSubmission` model
4. Authenticate source device
5. Extract metadata (mission, geo, telemetry, additional)
6. For each payload: analyze security, verify checksum, create artifact
7. Assemble `IngestMetadata` and return `IngestResult`

**Additional capabilities:**
- `process_batch()` --- processes multiple submissions sequentially
- `stats` property --- returns `{total_processed, total_rejected, total_flagged}`
- `authenticator` property --- exposes the authenticator for direct access
- `uplink_receiver` property --- exposes the uplink receiver for command injection

**Functional API:** `ingestion_interceptor()` provides a backward-compatible
functional interface that creates a temporary `IngestionInterceptor` and
processes a single submission, returning a plain dict.

---

## 6. Data Models

### 6.1 `GeoLocation`

```
┌──────────────────────────────────────────────────────────────┐
│ GeoLocation                                                  │
├──────────────┬──────────┬────────────────────────────────────┤
│ Field        │ Type     │ Description                        │
├──────────────┼──────────┼────────────────────────────────────┤
│ lat          │ float    │ Latitude (-90 to +90)              │
│ lon          │ float    │ Longitude (-180 to +180)           │
│ alt          │ float    │ Altitude in meters (default 0.0)   │
├──────────────┴──────────┴────────────────────────────────────┤
│ Methods: to_dict(), from_dict(d) -> Optional[GeoLocation]   │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 `PayloadEntry`

```
┌──────────────────────────────────────────────────────────────┐
│ PayloadEntry                                                 │
├──────────────┬──────────────────┬────────────────────────────┤
│ Field        │ Type             │ Description                │
├──────────────┼──────────────────┼────────────────────────────┤
│ type         │ str              │ File type category         │
│              │                  │ (video, image, archive,    │
│              │                  │  telemetry, text)          │
│ filename     │ str              │ Original filename          │
│ mime         │ str              │ MIME type declaration       │
│ size_bytes   │ int              │ File size in bytes         │
│ encryption   │ bool             │ Whether file is encrypted  │
│              │                  │ (default False)            │
│ container    │ bool             │ Whether file is an archive │
│              │                  │ or container (default False)|
│ checksum     │ Optional[str]    │ Declared checksum for      │
│              │                  │ integrity verification     │
│ uri          │ Optional[str]    │ Storage URI (file:/,       │
│              │                  │ s3://, relative path)      │
├──────────────┴──────────────────┴────────────────────────────┤
│ Methods: to_dict(), from_dict(d) -> PayloadEntry             │
└──────────────────────────────────────────────────────────────┘
```

### 6.3 `DroneSubmission`

```
┌──────────────────────────────────────────────────────────────────┐
│ DroneSubmission                                                  │
├─────────────────────┬───────────────────────┬────────────────────┤
│ Field               │ Type                  │ Description        │
├─────────────────────┼───────────────────────┼────────────────────┤
│ drone_id            │ str                   │ Unique device ID   │
│ timestamp           │ str                   │ ISO 8601 timestamp │
│ payloads            │ List[PayloadEntry]    │ File entries       │
│ mission_id          │ Optional[str]         │ Mission identifier │
│ mission_zone        │ Optional[str]         │ Operational zone   │
│ geo                 │ Optional[GeoLocation] │ GPS coordinates    │
│ telemetry           │ Optional[Dict]        │ Drone telemetry    │
│ signature           │ Optional[str]         │ Cryptographic sig  │
│ firmware_version    │ Optional[str]         │ Firmware version   │
│ operator_id         │ Optional[str]         │ Human operator ID  │
│ additional_metadata │ Optional[Dict]        │ Extension fields   │
├─────────────────────┴───────────────────────┴────────────────────┤
│ Methods: from_dict(d) -> DroneSubmission                         │
└──────────────────────────────────────────────────────────────────┘
```

### 6.4 `ArtifactRecord`

```
┌──────────────────────────────────────────────────────────────────┐
│ ArtifactRecord                                                   │
├───────────────────┬──────────────────┬───────────────────────────┤
│ Field             │ Type             │ Description               │
├───────────────────┼──────────────────┼───────────────────────────┤
│ artifact_id       │ str              │ Unique artifact URI       │
│                   │                  │ (artifact://<hex>)        │
│ filename          │ str              │ Original filename         │
│ type              │ str              │ File type category        │
│ mime              │ str              │ MIME type                 │
│ size_bytes        │ int              │ File size in bytes        │
│ encryption        │ bool             │ Whether encrypted         │
│ container         │ bool             │ Whether archive/container │
│ security_flags    │ List[str]        │ Detected security flags   │
│ checksum_verified │ Optional[bool]   │ True/False/None           │
│ thumbnail         │ Optional[str]    │ Thumbnail URI for visual  │
│                   │                  │ types (thumb://<hex>)     │
│ pointer_storage   │ Optional[str]    │ Storage URI for file      │
│                   │                  │ retrieval                 │
├───────────────────┴──────────────────┴───────────────────────────┤
│ Methods: to_dict()                                               │
└──────────────────────────────────────────────────────────────────┘
```

### 6.5 `IngestMetadata`

```
┌──────────────────────────────────────────────────────────────────┐
│ IngestMetadata                                                   │
├─────────────────────┬───────────────────────┬────────────────────┤
│ Field               │ Type                  │ Description        │
├─────────────────────┼───────────────────────┼────────────────────┤
│ ingest_id           │ str                   │ Unique ingest ID   │
│                     │                       │ (ingest_<hex>)     │
│ drone_id            │ str                   │ Source device ID   │
│ timestamp           │ str                   │ Original timestamp │
│ received_at         │ str                   │ Server receive time│
│ mission_id          │ Optional[str]         │ Mission identifier │
│ mission_zone        │ Optional[str]         │ Operational zone   │
│ geo                 │ Optional[Dict]        │ Validated GPS data │
│ operator_id         │ Optional[str]         │ Operator ID        │
│ firmware_version    │ Optional[str]         │ Firmware version   │
│ num_files           │ int                   │ Payload count      │
│ total_size_bytes    │ int                   │ Sum of all sizes   │
│ insecure_flags      │ List[str]             │ Aggregated flags   │
│ auth_result         │ str                   │ Auth status string │
│ auth_details        │ Optional[Dict]        │ Full auth details  │
│ reputation          │ Optional[float]       │ Device reputation  │
│ zone_risk           │ Optional[float]       │ Zone risk score    │
│ notes               │ str                   │ Threat notes       │
│ additional_metadata │ Optional[Dict]        │ Sanitized metadata │
├─────────────────────┴───────────────────────┴────────────────────┤
│ Methods: to_dict()                                               │
└──────────────────────────────────────────────────────────────────┘
```

### 6.6 `IngestResult`

```
┌──────────────────────────────────────────────────────────────────┐
│ IngestResult                                                     │
├──────────────────┬──────────────────────────┬────────────────────┤
│ Field            │ Type                     │ Description        │
├──────────────────┼──────────────────────────┼────────────────────┤
│ success          │ bool                     │ Pipeline outcome   │
│ ingest_metadata  │ Optional[IngestMetadata] │ Metadata (if ok)   │
│ artifact_records │ List[ArtifactRecord]     │ Per-file records   │
│ errors           │ List[str]                │ Fatal errors       │
│ warnings         │ List[str]                │ Non-fatal warnings │
├──────────────────┴──────────────────────────┴────────────────────┤
│ Methods: to_dict()                                               │
│                                                                  │
│ Success path: {"ingest_metadata": {...}, "artifact_records": []} │
│ Error path:   {"error": True, "errors": [...], "warnings": []}  │
└──────────────────────────────────────────────────────────────────┘
```

### 6.7 Supporting Models

**`AuthResult`** (in `authenticator.py`):

```
┌──────────────────────────────────────────────────────────────┐
│ AuthResult                                                   │
├────────────┬──────────────────┬───────────────────────────────┤
│ Field      │ Type             │ Description                   │
├────────────┼──────────────────┼───────────────────────────────┤
│ status     │ str              │ authenticated / untrusted /   │
│            │                  │ unknown / rejected / error    │
│ drone_id   │ str              │ Device identifier             │
│ reputation │ Optional[float]  │ Reputation score from registry│
│ trusted    │ bool             │ Trust flag (default False)    │
│ details    │ Optional[Dict]   │ Extended authentication info  │
├────────────┴──────────────────┴───────────────────────────────┤
│ Methods: to_dict()                                            │
└──────────────────────────────────────────────────────────────┘
```

**`UplinkCommand`** (in `uplink.py`):

```
┌──────────────────────────────────────────────────────────────┐
│ UplinkCommand                                                │
├──────────────┬──────────────────┬─────────────────────────────┤
│ Field        │ Type             │ Description                 │
├──────────────┼──────────────────┼─────────────────────────────┤
│ command_type │ CommandType      │ Enum: QUARANTINE, RELEASE,  │
│              │                  │ UPDATE_CONFIG, REVOKE_DEVICE│
│              │                  │ UPDATE_ZONE_RISK,FORCE_RESCAN│
│ target       │ str              │ drone_id, ingest_id, or "*" │
│ parameters   │ Dict[str, Any]   │ Command-specific parameters │
│ timestamp    │ float            │ Unix timestamp of creation  │
│ command_id   │ str              │ Unique command identifier   │
├──────────────┴──────────────────┴─────────────────────────────┤
│ Methods: to_dict()                                            │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. API Specification

### 7.1 Class-Based API: `IngestionInterceptor`

**Constructor:**

```python
IngestionInterceptor(
    config: Optional[InterceptorConfig] = None,
    device_registry: Optional[Dict[str, Dict[str, Any]]] = None,
    zone_risk_lookup: Optional[Dict[str, float]] = None,
    key_store: Optional[Dict[str, str]] = None,
)
```

| Parameter        | Type                              | Description                                  |
|------------------|-----------------------------------|----------------------------------------------|
| `config`         | `Optional[InterceptorConfig]`     | Configuration object; defaults if `None`     |
| `device_registry`| `Optional[Dict[str, Dict]]`      | Map of `drone_id` to device info dicts       |
| `zone_risk_lookup`| `Optional[Dict[str, float]]`    | Map of zone names to risk scores (0.0--1.0)  |
| `key_store`      | `Optional[Dict[str, str]]`       | Map of `drone_id` to HMAC shared secrets     |

**Methods:**

| Method                    | Signature                                             | Returns        | Description                          |
|---------------------------|-------------------------------------------------------|----------------|--------------------------------------|
| `process(drone_json)`     | `(Dict[str, Any]) -> IngestResult`                    | `IngestResult` | Process a single drone submission    |
| `process_batch(submissions)` | `(List[Dict[str, Any]]) -> List[IngestResult]`     | `List[IngestResult]` | Process multiple submissions    |

**Properties:**

| Property          | Type              | Description                                    |
|-------------------|-------------------|------------------------------------------------|
| `stats`           | `Dict[str, int]`  | `{total_processed, total_rejected, total_flagged}` |
| `authenticator`   | `Authenticator`   | Direct access to the authenticator instance    |
| `uplink_receiver` | `UplinkReceiver`  | Direct access to the uplink receiver           |

### 7.2 Functional API

```python
ingestion_interceptor(
    drone_json: Dict[str, Any],
    device_registry: Optional[Dict[str, Dict[str, Any]]] = None,
    require_signature: bool = False,
    zone_risk_lookup: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]
```

Creates a temporary `IngestionInterceptor` instance with the given parameters
and processes a single submission. Returns the result as a plain dictionary
(via `IngestResult.to_dict()`). Provided for backward compatibility with
prototype code.

### 7.3 Module-Level Functions

**`validator.py`:**

| Function                   | Signature                                                                 | Returns                    |
|----------------------------|---------------------------------------------------------------------------|----------------------------|
| `validate_submission()`    | `(drone_json: Dict, config: InterceptorConfig) -> Tuple[List, List]`     | `(errors, warnings)`       |
| `parse_timestamp()`        | `(ts_str: str) -> datetime`                                               | Parsed datetime object     |

**`authenticator.py`:**

| Function / Method            | Signature                                                              | Returns       |
|------------------------------|------------------------------------------------------------------------|---------------|
| `Authenticator.authenticate()` | `(drone_id, signature=None, payload_hash="") -> AuthResult`         | `AuthResult`  |
| `DeviceRegistry.lookup()`    | `(drone_id: str) -> Optional[Dict]`                                    | Device info   |
| `DeviceRegistry.register_device()` | `(drone_id: str, info: Dict) -> None`                           | None          |
| `DeviceRegistry.revoke_device()` | `(drone_id: str) -> bool`                                          | Success flag  |
| `SignatureVerifier.verify()` | `(drone_id, signature, payload_hash) -> Dict`                          | `{valid, reason}` |

**`payload_analyzer.py`:**

| Function                      | Signature                                                              | Returns         |
|-------------------------------|------------------------------------------------------------------------|-----------------|
| `analyze_payload()`           | `(payload: PayloadEntry, config: InterceptorConfig) -> List[str]`     | Security flags  |
| `compute_payload_risk_score()`| `(flags: List[str]) -> float`                                          | Score 0.0--1.0  |
| `generate_threat_notes()`     | `(flags: List[str], auth_status: str) -> str`                          | Human-readable  |

**`checksum_verifier.py`:**

| Function                   | Signature                                                                 | Returns           |
|----------------------------|---------------------------------------------------------------------------|-------------------|
| `compute_file_checksum()`  | `(filepath, algorithm="sha256", chunk_size=65536) -> Optional[str]`      | Hex digest        |
| `compute_bytes_checksum()` | `(data: bytes, algorithm="sha256") -> Optional[str]`                      | Hex digest        |
| `verify_checksum()`        | `(filepath, expected_checksum, algorithm="sha256") -> Optional[bool]`    | True/False/None   |
| `resolve_file_path()`      | `(uri, storage_base="") -> Optional[str]`                                 | Local path        |

**`metadata_extractor.py`:**

| Function                        | Signature                                              | Returns            |
|---------------------------------|--------------------------------------------------------|--------------------|
| `extract_mission_context()`     | `(submission: DroneSubmission) -> Dict[str, Any]`      | Mission context    |
| `extract_geo_metadata()`        | `(submission: DroneSubmission) -> Optional[Dict]`      | Validated geo data |
| `extract_telemetry_summary()`   | `(submission: DroneSubmission) -> Optional[Dict]`      | Telemetry summary  |
| `extract_additional_metadata()` | `(submission: DroneSubmission) -> Optional[Dict]`      | Sanitized metadata |

**`artifact_manager.py`:**

| Function                   | Signature                                                              | Returns          |
|----------------------------|------------------------------------------------------------------------|------------------|
| `generate_artifact_id()`   | `() -> str`                                                            | `artifact://<hex>` |
| `generate_ingest_id()`     | `() -> str`                                                            | `ingest_<hex>`   |
| `build_storage_pointer()`  | `(payload, drone_id, ingest_id, config) -> str`                        | Storage URI      |
| `create_artifact_record()` | `(payload, security_flags, drone_id, ingest_id, config, checksum_verified) -> ArtifactRecord` | ArtifactRecord |

**`uplink.py`:**

| Function / Method                  | Signature                                       | Returns          |
|------------------------------------|-------------------------------------------------|------------------|
| `UplinkReceiver.push_command()`    | `(command: UplinkCommand) -> None`              | None             |
| `UplinkReceiver.poll_commands()`   | `() -> List[UplinkCommand]`                     | Pending commands |
| `UplinkReceiver.acknowledge()`     | `(command_id: str) -> None`                     | None             |
| `UplinkCommandHandler.handle()`    | `(command: UplinkCommand) -> Dict[str, Any]`    | Result dict      |

---

## 8. Sequence Diagrams

### 8.1 Main Processing Flow (Happy Path)

```
  Caller                Interceptor          Validator       Authenticator
    │                       │                    │                │
    │  process(drone_json)  │                    │                │
    │──────────────────────►│                    │                │
    │                       │                    │                │
    │                       │  _process_uplink() │                │
    │                       │  (check pending    │                │
    │                       │   commands)        │                │
    │                       │                    │                │
    │                       │  validate_         │                │
    │                       │  submission()      │                │
    │                       │───────────────────►│                │
    │                       │                    │                │
    │                       │  (errors=[], warnings=[])          │
    │                       │◄───────────────────│                │
    │                       │                    │                │
    │                       │  DroneSubmission   │                │
    │                       │  .from_dict()      │                │
    │                       │                    │                │
    │                       │  compute_bytes_    │                │
    │                       │  checksum()        │                │
    │                       │  (payload hash     │                │
    │                       │   for auth)        │                │
    │                       │                    │                │
    │                       │  authenticate()    │                │
    │                       │───────────────────────────────────►│
    │                       │                    │                │
    │                       │  AuthResult(status="authenticated")│
    │                       │◄───────────────────────────────────│
    │                       │                    │                │

  Caller                Interceptor       MetadataExtractor   PayloadAnalyzer
    │                       │                    │                │
    │                       │  extract_mission   │                │
    │                       │  _context()        │                │
    │                       │───────────────────►│                │
    │                       │  mission context   │                │
    │                       │◄───────────────────│                │
    │                       │                    │                │
    │                       │  extract_geo_      │                │
    │                       │  metadata()        │                │
    │                       │───────────────────►│                │
    │                       │  validated geo     │                │
    │                       │◄───────────────────│                │
    │                       │                    │                │
    │                       │  extract_telemetry │                │
    │                       │  _summary()        │                │
    │                       │───────────────────►│                │
    │                       │  telemetry + anomalies             │
    │                       │◄───────────────────│                │
    │                       │                    │                │
    │                       │  extract_additional│                │
    │                       │  _metadata()       │                │
    │                       │───────────────────►│                │
    │                       │  sanitized metadata│                │
    │                       │◄───────────────────│                │
    │                       │                    │                │

  Caller                Interceptor       PayloadAnalyzer  ChecksumVerifier
    │                       │                    │                │
    │                       │  ┌─── FOR EACH payload ──────────┐ │
    │                       │  │                                │ │
    │                       │  │ analyze_payload()              │ │
    │                       │  │────────────────►│              │ │
    │                       │  │ security_flags[]│              │ │
    │                       │  │◄────────────────│              │ │
    │                       │  │                 │              │ │
    │                       │  │ verify_checksum()              │ │
    │                       │  │───────────────────────────────►│ │
    │                       │  │ True / False / None            │ │
    │                       │  │◄───────────────────────────────│ │
    │                       │  │                                │ │
    │                       │  │ create_artifact_record()       │ │
    │                       │  │ (artifact_manager)             │ │
    │                       │  │                                │ │
    │                       │  └────────────────────────────────┘ │
    │                       │                    │                │
    │                       │  Build IngestMetadata               │
    │                       │  (aggregate flags,                  │
    │                       │   zone_risk, notes)                 │
    │                       │                    │                │
    │  IngestResult         │                    │                │
    │  (success=True,       │                    │                │
    │   metadata, artifacts)│                    │                │
    │◄──────────────────────│                    │                │
    │                       │                    │                │
```

### 8.2 Authentication Flow (Detailed)

```
  Interceptor           Authenticator        DeviceRegistry    SignatureVerifier
    │                       │                    │                │
    │  authenticate(        │                    │                │
    │    drone_id,          │                    │                │
    │    signature,         │                    │                │
    │    payload_hash)      │                    │                │
    │──────────────────────►│                    │                │
    │                       │                    │                │
    │                       │  lookup(drone_id)  │                │
    │                       │───────────────────►│                │
    │                       │                    │                │
    │                       │                    │                │
    │     ┌─────────────────┼── CASE 1: Not found│                │
    │     │                 │◄───────────────────│                │
    │     │                 │  (None)            │                │
    │     │                 │                    │                │
    │     │  if policy ==   │                    │                │
    │     │  "reject":      │                    │                │
    │     │  return AuthResult(status="rejected")│                │
    │     │                 │                    │                │
    │     │  else:          │                    │                │
    │     │  return AuthResult(status="unknown") │                │
    │     └─────────────────┤                    │                │
    │                       │                    │                │
    │     ┌─────────────────┼── CASE 2: Found, revoked           │
    │     │                 │◄───────────────────│                │
    │     │                 │  {revoked: True}   │                │
    │     │                 │                    │                │
    │     │  return AuthResult(status="rejected")│                │
    │     └─────────────────┤                    │                │
    │                       │                    │                │
    │     ┌─────────────────┼── CASE 3: Found, active            │
    │     │                 │◄───────────────────│                │
    │     │                 │  {trusted, reputation}              │
    │     │                 │                    │                │
    │     │  if signature   │                    │                │
    │     │  provided:      │                    │                │
    │     │                 │  verify(drone_id,  │                │
    │     │                 │    signature,      │                │
    │     │                 │    payload_hash)   │                │
    │     │                 │───────────────────────────────────►│
    │     │                 │                    │                │
    │     │                 │  {valid: bool, reason: str}        │
    │     │                 │◄───────────────────────────────────│
    │     │                 │                    │                │
    │     │  if valid:      │                    │                │
    │     │    status =     │                    │                │
    │     │    "authenticated"                   │                │
    │     │    (if trusted) │                    │                │
    │     │                 │                    │                │
    │     │  if not valid:  │                    │                │
    │     │    trusted =    │                    │                │
    │     │    False        │                    │                │
    │     │    status =     │                    │                │
    │     │    "untrusted"  │                    │                │
    │     │                 │                    │                │
    │     │  return AuthResult(status, reputation, trusted)      │
    │     └─────────────────┤                    │                │
    │                       │                    │                │
    │  AuthResult           │                    │                │
    │◄──────────────────────│                    │                │
    │                       │                    │                │
```

### 8.3 Uplink Command Flow

```
  Control Center        UplinkReceiver     UplinkCommandHandler   Authenticator
    │                       │                    │                    │
    │  push_command(        │                    │                    │
    │    UplinkCommand(     │                    │                    │
    │    REVOKE_DEVICE,     │                    │                    │
    │    "DRN-005"))        │                    │                    │
    │──────────────────────►│                    │                    │
    │                       │                    │                    │
    │   (command queued)    │                    │                    │
    │                       │                    │                    │
    ├───────────────────────┼─── Later, during ──┼────────────────────┤
    │                       │    process() call  │                    │
    │                       │                    │                    │
  Interceptor               │                    │                    │
    │                       │                    │                    │
    │  _process_uplink_     │                    │                    │
    │  commands()           │                    │                    │
    │                       │                    │                    │
    │  poll_commands()      │                    │                    │
    │──────────────────────►│                    │                    │
    │                       │                    │                    │
    │  [UplinkCommand(...)] │                    │                    │
    │◄──────────────────────│                    │                    │
    │                       │                    │                    │
    │  handle(command)      │                    │                    │
    │──────────────────────────────────────────►│                    │
    │                       │                    │                    │
    │                       │                    │  revoke_device(    │
    │                       │                    │    "DRN-005")      │
    │                       │                    │───────────────────►│
    │                       │                    │                    │
    │                       │                    │  {trusted: False,  │
    │                       │                    │   revoked: True}   │
    │                       │                    │◄───────────────────│
    │                       │                    │                    │
    │  {"status":"revoked"} │                    │                    │
    │◄──────────────────────────────────────────│                    │
    │                       │                    │                    │
    │  acknowledge(cmd_id)  │                    │                    │
    │──────────────────────►│                    │                    │
    │                       │                    │                    │
    │  (command marked as   │                    │                    │
    │   processed; will not │                    │                    │
    │   appear in next poll)│                    │                    │
    │                       │                    │                    │
```

### 8.4 Rejection Flow (Validation Failure)

```
  Caller                Interceptor          Validator
    │                       │                    │
    │  process(             │                    │
    │    {"drone_id": ""})  │                    │
    │──────────────────────►│                    │
    │                       │                    │
    │                       │  validate_         │
    │                       │  submission()      │
    │                       │───────────────────►│
    │                       │                    │
    │                       │  errors=["invalid_drone_id:..."]
    │                       │◄───────────────────│
    │                       │                    │
    │                       │  stats[            │
    │                       │  "total_rejected"] │
    │                       │  += 1              │
    │                       │                    │
    │  IngestResult(        │                    │
    │    success=False,     │                    │
    │    errors=[...])      │                    │
    │◄──────────────────────│                    │
    │                       │                    │
```

---

## 9. Input/Output Specification

### 9.1 Input: Drone Submission JSON

**Complete example with all fields:**

```json
{
  "drone_id": "DRN-001",
  "timestamp": "2025-10-13T03:00:12Z",
  "mission_id": "MSN-142",
  "mission_zone": "zone-a",
  "geo": {
    "lat": 12.971598,
    "lon": 77.594566,
    "alt": 120.0
  },
  "payloads": [
    {
      "type": "video",
      "filename": "drn001_fpv_001.mp4",
      "mime": "video/mp4",
      "size_bytes": 4500000,
      "encryption": false,
      "container": false,
      "checksum": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
      "uri": "file:/drone_remote_store/DRN-001/drn001_fpv_001.mp4"
    },
    {
      "type": "image",
      "filename": "drn001_ir_001.tiff",
      "mime": "image/tiff",
      "size_bytes": 2100000,
      "encryption": false,
      "container": false,
      "checksum": "a3f2b8c1..."
    }
  ],
  "telemetry": {
    "speed": 12.5,
    "heading": 145.2,
    "battery": 78.4,
    "signal_strength": 92.0
  },
  "signature": "hmac-sha256:4a8c9f2b1d3e5f7a0b2c4d6e8f0a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e0f1",
  "firmware_version": "v1.2.0",
  "operator_id": "OP-12",
  "additional_metadata": {
    "camera_model": "CAM-X1000",
    "flight_plan_id": "FP-2025-142",
    "mission_sensitivity": "high"
  }
}
```

**Minimal valid submission:**

```json
{
  "drone_id": "DRN-001",
  "timestamp": "2025-10-13T03:00:12Z",
  "payloads": [
    {
      "type": "image",
      "filename": "test.jpg",
      "mime": "image/jpeg",
      "size_bytes": 50000
    }
  ]
}
```

### 9.2 Output: IngestResult (Success Path)

```json
{
  "ingest_metadata": {
    "ingest_id": "ingest_a1b2c3d4e5f6",
    "drone_id": "DRN-001",
    "timestamp": "2025-10-13T03:00:12Z",
    "received_at": "2025-10-13T03:00:13.456789+00:00",
    "mission_id": "MSN-142",
    "mission_zone": "zone-a",
    "geo": {
      "lat": 12.971598,
      "lon": 77.594566,
      "alt": 120.0
    },
    "operator_id": "OP-12",
    "firmware_version": "v1.2.0",
    "num_files": 2,
    "total_size_bytes": 6600000,
    "insecure_flags": [],
    "auth_result": "authenticated",
    "auth_details": {
      "status": "authenticated",
      "drone_id": "DRN-001",
      "trusted": true,
      "reputation": 0.9
    },
    "reputation": 0.9,
    "zone_risk": 0.6,
    "notes": "normal feed",
    "additional_metadata": {
      "camera_model": "CAM-X1000",
      "flight_plan_id": "FP-2025-142",
      "mission_sensitivity": "high"
    }
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://a1b2c3d4e5f6a7b8",
      "filename": "drn001_fpv_001.mp4",
      "type": "video",
      "mime": "video/mp4",
      "size_bytes": 4500000,
      "encryption": false,
      "container": false,
      "security_flags": [],
      "checksum_verified": true,
      "thumbnail": "thumb://c3d4e5f6a7b8",
      "pointer_storage": "file:/drone_remote_store/DRN-001/drn001_fpv_001.mp4"
    },
    {
      "artifact_id": "artifact://b2c3d4e5f6a7b8c9",
      "filename": "drn001_ir_001.tiff",
      "type": "image",
      "mime": "image/tiff",
      "size_bytes": 2100000,
      "encryption": false,
      "container": false,
      "security_flags": [],
      "checksum_verified": null,
      "thumbnail": "thumb://d4e5f6a7b8c9",
      "pointer_storage": "s3://forensics/artifacts/DRN-001//a1b2c3d4_drn001_ir_001.tiff"
    }
  ],
  "warnings": []
}
```

### 9.3 Output: IngestResult (Error Path)

```json
{
  "error": true,
  "errors": [
    "missing_field:drone_id",
    "missing_field:timestamp"
  ],
  "warnings": []
}
```

### 9.4 Output: IngestResult (Flagged Submission)

```json
{
  "ingest_metadata": {
    "ingest_id": "ingest_f7e8d9c0b1a2",
    "drone_id": "DRN-UNKNOWN",
    "timestamp": "2025-10-13T04:15:00Z",
    "received_at": "2025-10-13T04:15:01.123456+00:00",
    "mission_id": null,
    "mission_zone": null,
    "geo": null,
    "num_files": 1,
    "total_size_bytes": 15000000,
    "insecure_flags": [
      "encrypted_payload",
      "large_binary",
      "nested_archive"
    ],
    "auth_result": "unknown",
    "reputation": null,
    "zone_risk": null,
    "notes": "device unknown; defer analysis: encrypted or nested contents; large binary - consider selective sampling"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://e8d9c0b1a2f3e4d5",
      "filename": "bundle.zip",
      "type": "archive",
      "mime": "application/zip",
      "size_bytes": 15000000,
      "encryption": true,
      "container": true,
      "security_flags": [
        "encrypted_payload",
        "nested_archive",
        "large_binary"
      ],
      "checksum_verified": null,
      "thumbnail": null,
      "pointer_storage": "s3://forensics/artifacts/DRN-UNKNOWN/..."
    }
  ],
  "warnings": []
}
```

### 9.5 Downstream Interface: Game-Theoretic Threat Estimator

The Game-Theoretic Threat Estimator consumes `IngestResult` and computes:

```
Inputs from IngestResult:
  - ingest_metadata.insecure_flags   --> flag count, severity weights
  - ingest_metadata.reputation       --> R (reputation factor)
  - ingest_metadata.zone_risk        --> Z (zone risk factor)
  - artifact_records[].size_bytes    --> file size risk component
  - artifact_records[].type          --> type-based risk weighting
  - additional_metadata.mission_sensitivity --> mission sensitivity factor

Computation:
  I_base   = f(file_sizes, types, flag_severities)
  I_prime  = I_base * mission_sensitivity_multiplier
  T_S      = Stackelberg_equilibrium(I_prime, R, Z)

Output:
  T_S in [0.0, 1.0]
    T_S < 0.4   --> Low risk    --> Signature Scan only
    T_S 0.4-0.7 --> Medium risk --> Signature + AI/ML Classifier
    T_S >= 0.7  --> High risk   --> Signature + AI/ML + Sandbox Execution
```

---

## 10. Security Considerations

### 10.1 Input Validation Defences

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| Path traversal prevention      | Reject filenames containing `/` or `\`                   | Directory traversal, file overwrite attacks  |
| Size limit enforcement         | Configurable `max_payload_size_bytes` (default 500 MB)   | Resource exhaustion, denial of service       |
| Payload count limit            | `max_payloads_per_submission` (default 50)               | Batch flooding, memory exhaustion            |
| Timestamp validation           | ISO 8601 parsing, future-time warning                    | Replay attacks, timestamp spoofing           |
| Required field enforcement     | Fatal errors on missing `drone_id`, `timestamp`, `payloads` | Malformed input injection                 |
| MIME type whitelist             | Configurable `allowed_mime_types` (warning on unknown)   | Unexpected file type smuggling               |

### 10.2 Authentication Defences

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| Device registry verification   | Lookup against known device database                     | Unauthorized device submissions              |
| HMAC-SHA256 signatures         | Cryptographic payload integrity + source authentication  | Submission tampering, impersonation          |
| Configurable unknown policy    | `reject` / `flag` / `allow` for unregistered devices     | Rogue drone injection                        |
| Device revocation              | Uplink `REVOKE_DEVICE` command                           | Compromised device continued access          |
| Trust downgrade on sig failure | Failed signature sets `trusted=False`                    | Forged signatures with known device IDs      |

### 10.3 Payload Security Analysis

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| Encrypted content detection    | `encryption` flag check                                  | Hidden malware in encrypted containers       |
| Nested archive detection       | `container` flag check                                   | Archive bombs, recursive extraction attacks  |
| Executable extension detection | Check against suspicious extension set                   | Direct executable file injection             |
| Double extension detection     | Multi-dot filename analysis                              | Extension spoofing (photo.jpg.exe)           |
| MIME-extension mismatch        | Cross-reference declared MIME vs file extension          | MIME type spoofing                           |
| Hidden file detection          | Unix dot-prefix check                                    | Hidden malicious files                       |
| Zero-size file detection       | Flag empty files for expected-content types              | Placeholder / marker file attacks            |
| Suspicious MIME detection      | Check against known-dangerous MIME types                 | Executable MIME smuggling                    |

### 10.4 Integrity Defences

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| SHA-256 checksum verification  | Compare computed vs declared checksums                   | File tampering during transmission           |
| Payload hash for auth          | Hash entire submission for signature verification        | Submission-level tampering                   |
| Streaming hash computation     | 64 KB chunk-based file hashing                           | Memory exhaustion on large files             |

### 10.5 Metadata Defences

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| Prototype injection stripping  | Remove `__proto__`, `constructor`, `prototype`, `eval`, `exec` | Prototype pollution, code injection     |
| Value truncation               | Cap string values at 10,000 characters                   | Payload injection via metadata fields        |
| Geolocation sanity bounds      | Reject lat/lon/alt outside physical ranges               | Spoofed location data                        |
| Telemetry anomaly detection    | Flag impossible values (negative speed, >100% battery)   | Compromised drone telemetry                  |

### 10.6 Operational Security

| Defence                        | Implementation                                           | Threat Mitigated                            |
|--------------------------------|----------------------------------------------------------|---------------------------------------------|
| Uplink command authentication  | Command queue with ID-based acknowledgement              | Unauthorized command injection               |
| Dynamic zone risk updates      | Real-time risk level adjustment from control center      | Evolving threat landscape                    |
| Quarantine support             | Ingest-level quarantine via uplink commands               | Contain suspicious submissions               |
| Structured logging             | All processing events logged with context                | Forensic investigation, audit trail          |

---

## 11. Configuration Reference

### 11.1 Full `InterceptorConfig` Parameter Table

| Parameter                     | Type    | Default                    | Description                                                    |
|-------------------------------|---------|----------------------------|----------------------------------------------------------------|
| **Validation**                |         |                            |                                                                |
| `require_signature`           | `bool`  | `False`                    | Reject submissions without cryptographic signatures            |
| `max_payload_size_bytes`      | `int`   | `500_000_000` (500 MB)     | Hard cap per individual payload file                           |
| `max_payloads_per_submission` | `int`   | `50`                       | Maximum number of payload files per submission                 |
| `allowed_mime_types`          | `set`   | See 11.2                   | Whitelist of acceptable MIME types (warning on mismatch)       |
| **Security Thresholds**       |         |                            |                                                                |
| `large_binary_threshold`      | `int`   | `10_000_000` (10 MB)       | Size threshold for `large_binary` security flag                |
| `suspicious_mime_types`       | `set`   | See 11.3                   | MIME types that trigger `suspicious_mime` flag                  |
| `suspicious_extensions`       | `set`   | See 11.4                   | File extensions that trigger `executable_file` flag            |
| **Authentication**            |         |                            |                                                                |
| `auth_backend`                | `str`   | `"registry"`               | Authentication backend: `registry`, `jwt`, `mtls`              |
| `auth_timeout_seconds`        | `float` | `5.0`                      | Timeout for authentication operations                          |
| `unknown_device_policy`       | `str`   | `"flag"`                   | Policy for unregistered devices: `flag`, `reject`, `allow`     |
| **Checksum**                  |         |                            |                                                                |
| `checksum_algorithm`          | `str`   | `"sha256"`                 | Hash algorithm: `sha256`, `sha1`, `sha512`, `md5`             |
| `verify_checksums`            | `bool`  | `True`                     | Whether to verify file checksums when files are accessible     |
| **Storage**                   |         |                            |                                                                |
| `storage_backend`             | `str`   | `"filesystem"`             | Storage backend: `filesystem`, `s3`, `minio`                   |
| `storage_base_path`           | `str`   | `"drone_remote_store"`     | Base path for filesystem storage                               |
| `artifact_uri_prefix`         | `str`   | `"s3://forensics/artifacts"` | URI prefix for S3/MinIO storage pointers                     |
| **Zone Risk**                 |         |                            |                                                                |
| `default_zone_risk`           | `float` | `0.5`                      | Default zone risk when zone is not in the lookup table         |
| **Logging**                   |         |                            |                                                                |
| `log_level`                   | `str`   | `"INFO"`                   | Python logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`      |
| `structured_logging`          | `bool`  | `True`                     | Enable structured (JSON-friendly) log format                   |
| **Uplink**                    |         |                            |                                                                |
| `uplink_enabled`              | `bool`  | `False`                    | Enable uplink command receiver                                 |
| `uplink_endpoint`             | `str`   | `""`                       | Endpoint URL for uplink communication (gRPC/MQTT)              |
| `uplink_poll_interval_seconds`| `float` | `10.0`                     | Polling interval for file-based uplink mode                    |

### 11.2 Default Allowed MIME Types

```
video/mp4, video/x-matroska, video/avi,
image/jpeg, image/png, image/tiff, image/bmp,
application/json, text/plain, text/csv,
application/zip, application/x-tar, application/gzip,
application/octet-stream
```

### 11.3 Default Suspicious MIME Types

```
application/x-msdownload, application/x-executable,
application/x-dosexec, application/octet-stream
```

### 11.4 Default Suspicious Extensions

```
exe, dll, bat, cmd, ps1, sh, vbs, js, msi, scr, com
```

---

## 12. Requirements

### 12.1 Functional Requirements

These requirements are derived from the BEL project proposal (Sections 4.2,
5.1, and 6.3).

| ID    | Requirement                                                                            | BEL Ref  | Status      |
|-------|----------------------------------------------------------------------------------------|----------|-------------|
| FR-1  | Authenticate source devices using metadata (timestamps, drone ID, geolocation)         | 4.2.1    | Implemented |
| FR-2  | Validate data format, structure, and integrity of all incoming submissions             | 4.2.2    | Implemented |
| FR-3  | Extract and record metadata: drone ID, mission zone, timestamps, encryption status     | 4.2.3    | Implemented |
| FR-4  | Identify ZIP/encrypted file types and flag for deferred analysis                       | 4.2.4    | Implemented |
| FR-5  | Act as a secure data funnel preventing uncontrolled input into analysis pipeline        | 4.2.5    | Implemented |
| FR-6  | Support secure uplink from control center: quarantine commands                         | 4.2.6    | Implemented |
| FR-7  | Support dynamic parameter adjustment via uplink                                        | 4.2.6    | Implemented |
| FR-8  | Support live feedback loop between dashboard and edge                                  | 4.2.6    | Implemented |
| FR-9  | Produce structured output compatible with Game-Theoretic Threat Estimator              | 5.1      | Implemented |
| FR-10 | Support device revocation to immediately block compromised drones                      | 6.3      | Implemented |
| FR-11 | Support zone risk updates for dynamic threat landscape adaptation                      | 6.3      | Implemented |
| FR-12 | Generate unique artifact identifiers for traceability across the pipeline              | 5.1      | Implemented |
| FR-13 | Verify file integrity through cryptographic checksums                                  | 4.2.2    | Implemented |
| FR-14 | Detect MIME-extension mismatches as a spoofing indicator                                | 4.2.4    | Implemented |
| FR-15 | Detect double-extension filenames as an evasion indicator                               | 4.2.4    | Implemented |
| FR-16 | Enforce configurable size limits per payload file                                      | 4.2.5    | Implemented |
| FR-17 | Enforce configurable payload count limits per submission                                | 4.2.5    | Implemented |
| FR-18 | Pre-sanitize metadata to strip prototype injection vectors                             | 4.2.3    | Implemented |
| FR-19 | Detect telemetry anomalies (negative speed, invalid battery, etc.)                     | 4.2.1    | Implemented |
| FR-20 | Support batch processing of multiple submissions                                       | 5.1      | Implemented |

### 12.2 Non-Functional Requirements

| ID     | Requirement                                                                           | Status      |
|--------|---------------------------------------------------------------------------------------|-------------|
| NFR-1  | Module must be stateless per-request (state only in registry and uplink handler)      | Implemented |
| NFR-2  | All configuration must be centralized in a single config object                       | Implemented |
| NFR-3  | All data models must use typed dataclasses with serialization support                 | Implemented |
| NFR-4  | Checksum computation must use streaming (chunked) reads, not full-file memory load    | Implemented |
| NFR-5  | All security-relevant events must be logged with structured context                   | Implemented |
| NFR-6  | Module must have zero external dependencies beyond Python 3.9 standard library        | Implemented |
| NFR-7  | Module must support both class-based and functional API entry points                  | Implemented |
| NFR-8  | Authentication backend must be pluggable (registry, JWT, mTLS)                        | Partial     |
| NFR-9  | Uplink receiver must support pluggable transport (memory, file, gRPC, MQTT)           | Partial     |
| NFR-10 | All public functions must have docstrings with clear parameter/return documentation   | Implemented |

---

## 13. Performance Requirements

### 13.1 Throughput Targets

| Metric                         | Target                        | Rationale                                         |
|--------------------------------|-------------------------------|---------------------------------------------------|
| Single submission latency      | < 50 ms (without I/O)        | Edge processing must not bottleneck the pipeline   |
| Per-payload analysis latency   | < 5 ms per payload            | Heuristic checks are CPU-bound, not I/O-bound      |
| Batch throughput               | 100+ submissions/second       | Supports multi-drone concurrent operations          |
| Checksum verification          | Bounded by disk I/O           | Streaming 64 KB chunks; no full-file memory load   |
| Memory per submission          | < 10 MB overhead              | Metadata-only processing; no payload content loaded |

### 13.2 Scalability Considerations

| Aspect                  | Current Design                  | Production Path                            |
|-------------------------|---------------------------------|--------------------------------------------|
| Concurrency             | Sequential processing           | asyncio / thread pool for I/O-bound ops    |
| Device registry         | In-memory dict or JSON file     | Database (PostgreSQL/Redis) or API service  |
| Uplink transport        | Memory queue or file polling    | gRPC bidirectional streaming or MQTT        |
| Artifact storage        | Local filesystem / URI pointers | S3/MinIO with pre-signed URLs              |
| Checksum verification   | Local file access only          | Remote hash verification API               |

### 13.3 Resource Bounds

| Resource         | Bound                                                                |
|------------------|----------------------------------------------------------------------|
| CPU              | O(n) per submission where n = number of payloads                     |
| Memory           | O(n) for artifact records; constant per validation/auth step         |
| Disk I/O         | Only for checksum verification (optional) and file-based uplink      |
| Network          | None in current implementation; future gRPC/MQTT for uplink          |

---

## 14. Dependencies

### 14.1 Runtime Dependencies

| Dependency       | Version  | Source          | Purpose                                        |
|------------------|----------|-----------------|------------------------------------------------|
| Python           | >= 3.9   | Standard        | Runtime environment                            |
| `dataclasses`    | built-in | Standard Library| Typed data model definitions                   |
| `hashlib`        | built-in | Standard Library| SHA-256, SHA-1, SHA-512, MD5 hash computation  |
| `hmac`           | built-in | Standard Library| HMAC-SHA256 signature verification             |
| `json`           | built-in | Standard Library| JSON serialization/deserialization              |
| `uuid`           | built-in | Standard Library| Unique identifier generation                   |
| `logging`        | built-in | Standard Library| Structured event logging                       |
| `datetime`       | built-in | Standard Library| Timestamp parsing and generation               |
| `os`             | built-in | Standard Library| File path resolution                           |
| `time`           | built-in | Standard Library| Performance timing, command timestamps         |
| `enum`           | built-in | Standard Library| CommandType enumeration                        |

The module has **zero external dependencies**. All functionality is implemented
using the Python standard library only.

### 14.2 Development Dependencies

| Dependency       | Version  | Purpose                                        |
|------------------|----------|------------------------------------------------|
| `unittest`       | built-in | Test framework (31 unit tests)                 |
| `pytest`         | >= 7.0   | Alternative test runner (optional)             |

### 14.3 Downstream Module Dependencies

| Module                              | Depends On From This Module               |
|-------------------------------------|-------------------------------------------|
| Game-Theoretic Threat Estimator     | `IngestResult`, `IngestMetadata`, `ArtifactRecord` |
| Metadata Sanitizer                  | `ArtifactRecord.pointer_storage` for file access   |
| Security Dashboard                  | `IngestResult.to_dict()` for display               |
| Response & Quarantine Manager       | `IngestMetadata.insecure_flags`, `auth_result`     |

---

## 15. Testing Strategy

### 15.1 Test Suite Overview

The test suite contains **31 unit tests** organized across 6 test classes,
covering all pipeline components.

**Location:** `ingestion_interceptor/tests/test_interceptor.py`

**Execution:**
```
python -m unittest ingestion_interceptor.tests.test_interceptor -v
python -m pytest ingestion_interceptor/tests/ -v
```

### 15.2 Test Classes and Coverage

| Test Class                  | Tests | Coverage Area                                     |
|-----------------------------|-------|---------------------------------------------------|
| `TestValidator`             | 8     | Structure validation, missing fields, path traversal, size limits, timestamps, signature enforcement |
| `TestPayloadAnalyzer`       | 8     | All 9 security flags, risk scoring (clean, critical), MIME mismatch, double extension |
| `TestAuthenticator`         | 5     | Trusted/untrusted/unknown/rejected/revoked device states, policy enforcement |
| `TestInterceptorPipeline`   | 5     | End-to-end processing (normal, suspicious, invalid), backward-compatible API, stats tracking |
| `TestUplink`                | 2     | Command push/poll cycle, acknowledgement and deduplication |
| `TestChecksumVerifier`      | 3     | Bytes checksum computation, file URI resolution, S3 URI handling |

### 15.3 Test Data Strategy

All tests use the `_make_sample()` factory function that produces a minimal
valid drone submission. Tests apply targeted overrides to test specific
conditions without duplicating boilerplate. This ensures tests remain focused
and maintainable as the schema evolves.

### 15.4 Testing Gaps and Future Coverage

| Area                              | Current State      | Planned                              |
|-----------------------------------|--------------------|--------------------------------------|
| HMAC signature verification       | Not directly tested| Add test with matching key/signature |
| File-based checksum verification  | Not tested (no fixture files) | Add fixture files or mock I/O |
| File-based uplink receiver        | Not tested         | Add JSON file fixtures               |
| Telemetry anomaly detection       | Implicitly tested  | Add explicit anomaly assertion tests |
| Geolocation boundary validation   | Implicitly tested  | Add explicit out-of-range tests      |
| Metadata pre-sanitization         | Implicitly tested  | Add prototype injection test         |
| Concurrent batch processing       | Not tested         | Add thread safety tests              |
| Configuration edge cases          | Partial            | Add tests for extreme config values  |

---

## 16. Deployment and Operations

### 16.1 Deployment Topology

```
┌──────────────────────────────────────────────────────────────────────┐
│                     EDGE DEPLOYMENT NODE                             │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Ingestion Interceptor Process                                 │  │
│  │                                                                │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐  │  │
│  │  │  Interceptor  │  │  Device       │  │  Uplink Receiver    │  │  │
│  │  │  Pipeline     │  │  Registry     │  │  (gRPC/MQTT client) │  │  │
│  │  └──────┬───────┘  └──────────────┘  └──────────┬──────────┘  │  │
│  │         │                                        │             │  │
│  │         ▼                                        │             │  │
│  │  ┌──────────────┐                                │             │  │
│  │  │  Local Store  │                                │             │  │
│  │  │  (artifacts)  │                                │             │  │
│  │  └──────────────┘                                │             │  │
│  └─────────┬────────────────────────────────────────┼─────────────┘  │
│            │                                        │                │
│            │ IngestResult                           │ Uplink         │
│            ▼                                        │ Commands       │
│  ┌────────────────────┐                             │                │
│  │  Threat Estimator   │                             │                │
│  │  + Detection Engine │                             │                │
│  └────────────────────┘                             │                │
│                                                      │                │
└──────────────────────────────────────────────────────┼────────────────┘
                                                       │
                                              Secure Network Link
                                                       │
                                                       ▼
                                          ┌──────────────────────┐
                                          │  Control Center /    │
                                          │  Security Dashboard  │
                                          └──────────────────────┘
```

### 16.2 Operational Modes

| Mode           | Use Case                     | Configuration                                   |
|----------------|------------------------------|-------------------------------------------------|
| **Standalone** | Testing, development         | In-memory registry, memory uplink, filesystem    |
| **File-backed**| Demo, integration testing    | JSON file registry, file-based uplink polling    |
| **Production** | Field deployment             | Database registry, gRPC/MQTT uplink, S3 storage  |

### 16.3 Monitoring and Observability

**Built-in statistics (`stats` property):**
- `total_processed` --- submissions that completed the full pipeline
- `total_rejected` --- submissions rejected at validation or authentication
- `total_flagged` --- submissions with one or more security flags

**Logging:**
- All processing events logged at INFO level with timing and flag data
- Authentication events logged with device ID and outcome
- Uplink commands logged with command type and result
- Checksum mismatches logged at WARNING level
- Registry load failures logged at ERROR level

**Recommended production monitoring:**
- Export `stats` to Prometheus/StatsD at regular intervals
- Ship logs to ELK/Loki for centralized search
- Alert on `total_rejected` spike (possible attack)
- Alert on `total_flagged / total_processed` ratio exceeding threshold

### 16.4 Configuration Management

For production deployments, the `InterceptorConfig` dataclass can be
initialized from environment variables or a YAML/JSON configuration file.
The recommended approach is to load configuration at startup and pass it to
the `IngestionInterceptor` constructor. Dynamic configuration updates are
supported via the `UPDATE_CONFIG` uplink command (reserved for future
implementation).

---

## 17. Risk Assessment

| ID   | Risk                                                     | Likelihood | Impact   | Mitigation                                                   |
|------|----------------------------------------------------------|------------|----------|--------------------------------------------------------------|
| R-1  | Rogue drone submits malicious payload                    | High       | Critical | Device registry + signature verification + unknown policy    |
| R-2  | Malware hidden in encrypted archive                      | High       | Critical | `encrypted_payload` + `nested_archive` flags; deferred to sandbox |
| R-3  | Double-extension evasion (photo.jpg.exe)                 | Medium     | High     | `double_extension` + `executable_file` flags                 |
| R-4  | MIME type spoofing                                       | Medium     | High     | `mime_extension_mismatch` + `suspicious_mime` flags          |
| R-5  | Submission flooding (DoS)                                | Medium     | High     | Payload count and size limits; future: per-device rate limiting |
| R-6  | Path traversal in filenames                              | Medium     | Critical | Reject filenames containing `/` or `\`                       |
| R-7  | Prototype pollution via metadata                         | Low        | High     | Strip `__proto__`, `constructor`, etc. from additional metadata |
| R-8  | Compromised drone continues submitting                   | Medium     | Critical | Uplink `REVOKE_DEVICE` command for immediate revocation      |
| R-9  | File tampering during transmission                       | Medium     | High     | SHA-256 checksum verification against declared values        |
| R-10 | Zone risk changes not reflected in analysis              | Low        | Medium   | Uplink `UPDATE_ZONE_RISK` for dynamic zone risk adjustment  |
| R-11 | Telemetry spoofing by compromised firmware               | Medium     | Medium   | Telemetry anomaly detection (negative speed, invalid battery)|
| R-12 | Large binary exhausts processing resources               | Low        | Medium   | `large_binary` flag + configurable threshold; streaming checksums |
| R-13 | Replay attack with old valid submission                  | Low        | Medium   | Timestamp validation with future-time warning; future: nonce tracking |
| R-14 | In-memory registry lost on process restart               | Medium     | Medium   | File-backed registry mode; production: database backend      |
| R-15 | Uplink command injection by adversary                    | Low        | Critical | Uplink channel authentication; command ID tracking           |

---

## 18. Implementation Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| **Phase 1** | Core framework: config, models, validator, authenticator | Done |
| **Phase 1** | Payload analyzer (9-point security heuristic) | Done |
| **Phase 1** | Checksum verifier (SHA-256 integrity verification) | Done |
| **Phase 1** | Metadata extractor (mission context, geo, telemetry) | Done |
| **Phase 1** | Artifact manager (ID generation, storage pointers) | Done |
| **Phase 1** | Uplink receiver and command handler | Done |
| **Phase 1** | Main orchestrator (IngestionInterceptor class) | Done |
| **Phase 1** | Unit test suite (31 tests) | Done |
| **Phase 2** | Ed25519 asymmetric signature verification | Planned |
| **Phase 2** | mTLS authentication for drone-to-edge communication | Planned |
| **Phase 2** | Rate limiting per drone_id (flood attack prevention) | Planned |
| **Phase 2** | Firmware version whitelisting | Planned |
| **Phase 3** | Async processing with asyncio for high-throughput | Planned |
| **Phase 3** | Redis/Kafka integration for distributed command queuing | Planned |
| **Phase 3** | Real S3/MinIO storage backend integration | Planned |
| **Phase 3** | gRPC/MQTT uplink channel (replace file/memory modes) | Planned |
| **Phase 3** | Prometheus metrics export for monitoring | Planned |

---

## 19. Glossary

| Term                        | Definition                                                                                           |
|-----------------------------|------------------------------------------------------------------------------------------------------|
| **RPA**                     | Remotely Piloted Aircraft; unmanned aerial vehicles operated by a remote pilot                        |
| **Edge Network Boundary**   | The network perimeter where data from external (untrusted) sources enters the internal (trusted) infrastructure |
| **Ingestion**               | The process of receiving, validating, and cataloging incoming data submissions                        |
| **Payload**                 | An individual file (video, image, telemetry data, etc.) contained within a drone submission           |
| **Artifact**                | A cataloged payload file with a unique identifier, storage pointer, and security analysis results     |
| **Security Flag**           | A named indicator of a potentially suspicious attribute detected during payload analysis              |
| **Device Registry**         | A database of known drone devices with their trust status, reputation scores, and metadata            |
| **Reputation Score**        | A numerical value (0.0--1.0) representing the historical trustworthiness of a drone device           |
| **Zone Risk**               | A numerical value (0.0--1.0) representing the threat level associated with a geographic operational zone |
| **T_S (Threat Score)**      | The output of the Game-Theoretic Threat Estimator; a value in [0.0, 1.0] determining inspection depth |
| **Stackelberg Game**        | A game-theoretic model where a leader (defender) commits to a strategy before a follower (attacker) responds; used to compute optimal inspection allocation |
| **HMAC-SHA256**             | Hash-based Message Authentication Code using SHA-256; provides both data integrity and authentication |
| **MIME Type**               | Multipurpose Internet Mail Extensions type; a standardized way to indicate the nature of a file      |
| **Path Traversal**          | An attack that uses directory navigation characters (`../`) in filenames to access files outside the intended directory |
| **Prototype Pollution**     | A JavaScript/JSON injection attack that manipulates object prototypes via `__proto__` or `constructor` keys |
| **Uplink**                  | The communication channel from the control center/security dashboard to the edge interceptor         |
| **Quarantine**              | The action of isolating a suspicious submission to prevent further processing until manual review     |
| **Pre-sanitization**        | A lightweight metadata cleaning step performed at ingestion time; distinct from the full Metadata Sanitizer module |
| **Ingest ID**               | A unique identifier (format: `ingest_<12-hex-chars>`) assigned to each successfully processed submission |
| **Artifact ID**             | A unique identifier (format: `artifact://<16-hex-chars>`) assigned to each cataloged payload file    |
| **BEL**                     | Bharat Electronics Limited; the project sponsor and defence electronics manufacturer                 |
| **IIT Bhubaneswar**         | Indian Institute of Technology Bhubaneswar; the research institution executing the project           |
