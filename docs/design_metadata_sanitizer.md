# Design Document: Metadata Sanitizer

| Field | Value |
|---|---|
| **Document Version** | 2.0 |
| **Status** | Implementation Complete (Phase 1-2) |
| **Module** | `metadata_sanitizer/` |
| **Authors** | Sangam Kumar Mishra |
| **Created** | 2025-10 |
| **Last Updated** | 2026-04 |
| **Depends On** | Ingestion Interceptor, Game-Theoretic Threat Estimator |
| **Depended On By** | Threat Intelligence Correlator, Response & Quarantine Manager |

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
9. [Sanitization Rules](#9-sanitization-rules)
10. [Configuration Reference](#10-configuration-reference)
11. [Security Considerations](#11-security-considerations)
12. [Performance Requirements](#12-performance-requirements)
13. [Dependencies](#13-dependencies)
14. [Testing Strategy](#14-testing-strategy)
15. [Deployment and Operations](#15-deployment-and-operations)
16. [Risk Assessment](#16-risk-assessment)
17. [Implementation Roadmap](#17-implementation-roadmap)
18. [Glossary](#18-glossary)

---

## 1. Executive Summary

The **Metadata Sanitizer** is a dedicated security module within the Multi-Layered Malware Detection and Threat Prevention System for drone/RPA data streams. It inspects and cleans embedded metadata in payload files (images, videos, PDFs, archives, telemetry) to neutralize covert channels, strip tracking data, and remove exploit payloads hidden in metadata fields.

**Key capabilities:**
- EXIF scrubbing for images (GPS, MakerNote, UserComment, embedded thumbnails)
- JavaScript/auto-action removal from PDFs
- Video metadata atom cleaning (MP4/MKV GPS tracks, custom atoms)
- Archive structure inspection (path traversal, zip bombs, hidden executables)
- Text/telemetry normalization (encoding, null bytes, embedded scripts)
- Threat-score-driven mode selection (strip / selective / audit-only)
- Full forensic audit trail with before/after metadata hashing

The module operates **after** the Malware Detection Engine as a defense-in-depth layer, cleaning files that passed malware scanning but may still carry embedded threats.

---

## 2. Goals and Non-Goals

### 2.1 Goals

| # | Goal | Rationale |
|---|---|---|
| G1 | Remove operationally dangerous metadata from all supported file types | Prevent covert data exfiltration and exploit delivery via metadata |
| G2 | Support three sanitization modes (strip, selective, audit-only) | Different operational contexts demand different aggressiveness levels |
| G3 | Automatically select mode based on threat score from the Game-Theoretic Estimator | Adaptive defense that scales response to observed threat level |
| G4 | Preserve file integrity and rendering correctness after sanitization | Cleaned files must remain usable for operational purposes |
| G5 | Produce full forensic audit trails | Every modification must be traceable for incident response |
| G6 | Integrate with Ingestion Interceptor artifact records | Seamless pipeline from ingestion through sanitization |
| G7 | Handle missing dependencies gracefully | System degrades to warnings rather than crashes when optional libraries are absent |

### 2.2 Non-Goals

| # | Non-Goal | Reason |
|---|---|---|
| NG1 | Malware detection or signature scanning | Delegated to the Malware Detection Engine (upstream) |
| NG2 | Deep content analysis (image recognition, video frame analysis) | Separate concern; belongs in domain-specific analysis modules |
| NG3 | Real-time streaming processing | Operates on stored files post-ingestion; near-real-time is sufficient |
| NG4 | Modification of media content (pixels, audio, video frames) | Only metadata is touched; media data remains byte-identical |
| NG5 | Archive decompression and recursive scanning | Archive contents are scanned by the Malware Detection Engine |

---

## 3. System Context

### 3.1 Position in Detection Pipeline

The Metadata Sanitizer occupies a specific position in the multi-layered detection pipeline, running **after** malware detection and **before** the Threat Intelligence Correlator.

```
┌──────────────────────────────────────────────────────────────────┐
│                    DRONE / RPA PLATFORM                          │
│             (Video, Images, Telemetry, Documents)                │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                   INGESTION INTERCEPTOR                          │
│                                                                  │
│   Validate → Authenticate → Extract Metadata → Analyze          │
│   → Verify Checksums → Create Artifacts                         │
│                                                                  │
│   Output: IngestResult {ingest_metadata, artifact_records[]}     │
└─────────────────────────────┬────────────────────────────────────┘
                              │ artifact_records + ingest_metadata
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│              GAME-THEORETIC THREAT ESTIMATOR                     │
│                                                                  │
│   Computes T_S (threat score 0.0-1.0) using Stackelberg         │
│   equilibrium from: impact, reputation, zone risk, flags         │
│                                                                  │
│   Output: T_S + inspection_level (Low/Medium/High)               │
└─────────────────────────────┬────────────────────────────────────┘
                              │ T_S, inspection_level
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│             MULTI-LAYER MALWARE DETECTION ENGINE                 │
│                                                                  │
│   Signature scan → ML classifier → Sandbox (if High)             │
│   Quarantines truly malicious files                              │
└─────────────────────────────┬────────────────────────────────────┘
                              │ files that passed detection
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│    ┌─────────────────────────────────────────────────────────┐   │
│    │              METADATA SANITIZER                         │   │
│    │                                                         │   │  ◄── THIS MODULE
│    │   ┌──────────┐ ┌──────────┐ ┌──────────┐              │   │
│    │   │  Image   │ │  Video   │ │   PDF    │              │   │
│    │   │ Handler  │ │ Handler  │ │ Handler  │              │   │
│    │   └──────────┘ └──────────┘ └──────────┘              │   │
│    │   ┌──────────┐ ┌──────────┐                            │   │
│    │   │ Archive  │ │  Text    │                            │   │
│    │   │ Handler  │ │ Handler  │                            │   │
│    │   └──────────┘ └──────────┘                            │   │
│    │                                                         │   │
│    │   Input:  artifact_records + T_S + file bytes           │   │
│    │   Output: SanitizationResult per artifact               │   │
│    └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬────────────────────────────────────┘
                              │ sanitization reports + cleaned files
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│           THREAT INTELLIGENCE CORRELATOR                         │
│                                                                  │
│   Correlates sanitization findings with known IoC patterns       │
│   Extracted metadata patterns serve as indicators of compromise  │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│           RESPONSE & QUARANTINE MANAGER                          │
│                                                                  │
│   Files that fail sanitization verification → quarantine         │
│   Cleaned files → forward to operational network                 │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Why Separate from Ingestion Interceptor?

| Aspect | Ingestion Interceptor | Metadata Sanitizer |
|---|---|---|
| **Operates on** | Wire-level UDP packets (Stage 0) and parsed dicts (Stages 1-7) | File-level embedded metadata (binary content) |
| **Position** | First stage (before threat estimation) | After malware detection engine |
| **Concerns** | Structure validation, authentication, cataloging | Deep content inspection, EXIF scrubbing, script removal |
| **Dependencies** | None (stdlib only, entry point) | Pillow, piexif, pikepdf, mutagen (optional) |
| **Latency** | Must be near-zero for real-time ingestion | Can tolerate slightly higher latency (post-triage) |
| **Failure mode** | Rejects entire submission | Can fail per-file; submission already cataloged |
| **Modifies files** | Never (read-only analysis) | Yes (strips/rewrites metadata) |

### 3.2.1 Wire I/O — out of scope (rationale)

Unlike the Ingestion Interceptor, the Metadata Sanitizer **does not have a
wire entry point and is not intended to**. It runs entirely inside the
trust boundary that the Interceptor establishes:

- **Inputs are already-trusted Python objects:** an `ArtifactRecord` dict
  (from `IngestionInterceptor.process()`), a threat score (from the
  Game-Theoretic Estimator), and `insecure_flags` from `IngestMetadata`.
  All of these have already been authenticated, validated, and cataloged
  upstream.
- **File bytes come from local edge-node storage**, addressed by the
  artifact's `pointer_storage` URI. The file was placed there by the
  ingestion pipeline; no untrusted network channel is involved.
- **Sending file bytes over a wire protocol would be a regression.**
  Sanitizer reads multi-megabyte videos and PDFs for parsing; framing
  those into UDP packets adds latency and protocol ceremony for zero
  security benefit because the data is already authenticated.

Stage 0 packet reception belongs to Module 1 (Ingestion Interceptor)
only. Modules 2-9 in the BEL architecture are internal pipeline stages
that pass Python objects and filesystem references in-process.

### 3.3 Data Flow Between Modules

```
                      Ingestion Interceptor
                              │
                    ┌─────────┴──────────┐
                    │                    │
              IngestMetadata      ArtifactRecord[]
              (insecure_flags,    (artifact_id, mime,
               auth_result,        pointer_storage,
               zone_risk)          security_flags)
                    │                    │
                    └─────────┬──────────┘
                              │
                    Game-Theoretic Estimator
                              │
                         threat_score (T_S)
                              │
                    Malware Detection Engine
                              │
                    (passed files only)
                              │
                              ▼
                    ┌─────────────────────┐
                    │ Metadata Sanitizer  │
                    │                     │
                    │ Inputs:             │
                    │  - artifact_record  │
                    │  - pointer_storage  │──→ file bytes on disk
                    │  - threat_score     │──→ mode selection
                    │  - insecure_flags   │──→ escalation signal
                    │                     │
                    │ Outputs:            │
                    │  - SanitizationResult│
                    │  - cleaned file     │
                    └─────────┬───────────┘
                              │
                    ┌─────────┴──────────┐
                    │                    │
          SanitizationResult     Cleaned file
          (changes[], warnings,  (metadata stripped,
           before/after hash)     content preserved)
                    │                    │
                    ▼                    ▼
          Threat Intelligence    Operational Network
             Correlator          (via Response Manager)
```

---

## 4. Architecture Overview

### 4.1 Module Structure

```
metadata_sanitizer/
├── __init__.py                 # Public API and package exports
├── config.py                   # SanitizerConfig dataclass
├── models.py                   # SanitizationResult, SanitizationChange, etc.
├── sanitizer.py                # MetadataSanitizer orchestrator class
│
├── handlers/                   # File-type specific handlers
│   ├── __init__.py             # Handler registry and routing
│   ├── base_handler.py         # Abstract base class (ABC)
│   ├── image_handler.py        # JPEG, PNG, TIFF — EXIF scrubbing
│   ├── video_handler.py        # MP4, MKV, AVI — atom cleaning
│   ├── pdf_handler.py          # PDF — JS/action removal
│   ├── archive_handler.py      # ZIP, TAR — structure inspection
│   └── text_handler.py         # TXT, CSV, JSON — encoding normalization
│
├── rules/                      # Declarative sanitization rules
│   ├── __init__.py             # Rule set exports
│   ├── exif_rules.py           # EXIF tag strip/keep/flag lists
│   ├── pdf_rules.py            # PDF dangerous keys and patterns
│   └── video_rules.py          # Video atom strip/preserve lists
│
├── tests/                      # Test suite
│   ├── __init__.py
│   └── test_sanitizer.py       # 94 unit tests
│
└── run_demo.py                 # Demo runner with sample files
```

### 4.2 Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    MetadataSanitizer                          │
│                    (sanitizer.py)                             │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │    Mode       │  │   Storage    │  │   Statistics     │   │
│  │   Resolver    │  │   Pointer    │  │   Tracker        │   │
│  │              │  │   Resolver   │  │                  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────┘   │
│         │                 │                                   │
│         ▼                 ▼                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               Handler Registry                         │  │
│  │            (handlers/__init__.py)                       │  │
│  │                                                        │  │
│  │  MIME type ──→ Handler class lookup ──→ cached instance │  │
│  └────────────────────────┬───────────────────────────────┘  │
│                           │                                   │
│     ┌─────────┬───────────┼───────────┬──────────┐           │
│     ▼         ▼           ▼           ▼          ▼           │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌─────────┐ ┌───────┐       │
│  │ Image │ │ Video │ │  PDF  │ │ Archive │ │ Text  │       │
│  │Handler│ │Handler│ │Handler│ │ Handler │ │Handler│       │
│  └───┬───┘ └───┬───┘ └───┬───┘ └────┬────┘ └───┬───┘       │
│      │         │         │          │          │             │
│      ▼         ▼         ▼          ▼          ▼             │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              Sanitization Rules                      │     │
│  │     exif_rules    pdf_rules    video_rules           │     │
│  └─────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
        │                                           │
        ▼                                           ▼
   SanitizationResult                        Cleaned File
   (audit trail)                             (on disk)
```

### 4.3 Handler Interface (BaseHandler)

Every file-type handler implements this interface:

```
┌─────────────────────────────────────────────┐
│              BaseHandler (ABC)               │
├─────────────────────────────────────────────┤
│ + config: SanitizerConfig                   │
│ + logger: Logger                            │
├─────────────────────────────────────────────┤
│ + extract_metadata(file_path) → Dict        │  ── Read embedded metadata
│ + sanitize(file, output, mode) → Changes[]  │  ── Apply rules, write cleaned file
│ + verify(file_path) → bool                  │  ── Re-parse to confirm validity
│ + supported_mimes() → Set[str]              │  ── MIME types handled
│ + is_available() → bool                     │  ── Dependency check (class method)
│ + handler_name() → str                      │  ── Human-readable name
├─────────────────────────────────────────────┤
│ # create_metadata_snapshot(meta) → Snapshot │  ── Hash + size snapshot
│ # make_change(field, action, ...) → Change  │  ── Change record builder
│ # check_field_size_anomaly(field, val, th)  │  ── Oversized field detector
└─────────────────────────────────────────────┘
          △           △           △
          │           │           │
   ┌──────┘     ┌─────┘     ┌────┘
   │            │            │
┌──────┐   ┌──────┐   ┌──────┐
│Image │   │Video │   │ PDF  │   ...
│Hdlr  │   │Hdlr  │   │Hdlr  │
└──────┘   └──────┘   └──────┘
```

---

## 5. Component Design

### 5.1 MetadataSanitizer (Orchestrator)

**File:** `sanitizer.py`

The orchestrator manages the sanitization pipeline for each file:

```
Input: artifact_record + threat_score
                │
                ▼
    ┌───────────────────────┐
    │   1. Resolve Mode     │  threat_score → strip/selective/audit_only
    │      (or use override)│  insecure_flags → escalation
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   2. Pre-Checks       │  file exists? size within limits?
    │                       │  MIME excluded? handler available?
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   3. Extract Before   │  handler.extract_metadata()
    │      Metadata         │  → MetadataSnapshot (hash, size)
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   4. Preserve Original│  copy file → file.orig (forensics)
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   5. Sanitize         │  handler.sanitize(file, output, mode)
    │                       │  → List[SanitizationChange]
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   6. Verify Output    │  handler.verify(output_file)
    │                       │  if fails → restore original
    └───────────┬───────────┘
                │
                ▼
    ┌───────────────────────┐
    │   7. Extract After    │  handler.extract_metadata()
    │      Metadata         │  → MetadataSnapshot (compare)
    └───────────┬───────────┘
                │
                ▼
    SanitizationResult
```

**Key design decisions:**
- **Handler caching:** One handler instance per class, reused across files
- **Fail-safe:** If sanitization corrupts a file, the original is restored from the `.orig` copy and the result's `sanitized` flag is reset to `False` so stats and the caller-facing report reflect the rollback

### 5.2 Mode Resolver

The sanitization mode is determined by a priority chain:

```
Priority 1: mode_override (explicit parameter)
    │ if provided → use directly
    ▼
Priority 2: threat_score (from Game-Theoretic Estimator)
    │ T_S >= 0.7 → "strip"      (aggressive: remove all non-essential)
    │ T_S <= 0.3 → "audit_only" (passive: log only)
    │ otherwise  → "selective"   (balanced: remove known-dangerous)
    ▼
Priority 3: insecure_flags (from Ingestion Interceptor)
    │ contains executable_file/suspicious_mime/double_extension → "strip"
    ▼
Priority 4: config.default_mode
    │ → "selective" (factory default)
```

### 5.3 Handler Registry

```python
# handlers/__init__.py — MIME type → Handler class mapping
HANDLER_REGISTRY = {
    "image/jpeg":       ImageHandler,
    "image/png":        ImageHandler,
    "image/tiff":       ImageHandler,
    "video/mp4":        VideoHandler,
    "video/x-matroska": VideoHandler,
    "application/pdf":  PdfHandler,
    "application/zip":  ArchiveHandler,
    "text/plain":       TextHandler,
    "application/json": TextHandler,
    ...
}
```

**Fallback strategy:**
1. Exact MIME match in registry
2. Prefix match (e.g., `video/*` → VideoHandler)
3. Default to TextHandler (safe: treats file as opaque text)

### 5.4 Image Handler

**Dependencies:** Pillow (required), piexif (optional, enables surgical tag removal)

```
Image File
    │
    ▼
┌───────────────────────────────────┐
│ Is piexif available?              │
│                                   │
│  YES → Surgical removal           │  NO → Pillow-only fallback
│        Load EXIF dict             │       Re-save without EXIF
│        Match tags against rules   │       (strips ALL metadata)
│        Delete matched tags        │
│        Re-insert cleaned EXIF     │
└───────────────────────────────────┘
```

**Surgical removal (piexif path):**
- Loads EXIF into IFD-structured dict
- Iterates tag names against `get_exif_strip_set(mode)`
- Deletes matched tags, preserves all others
- Detects oversized fields (>64 KB) as potential payload carriers
- Writes cleaned EXIF back into the image

**Fallback (Pillow-only path):**
- Opens image, copies pixel data
- Re-saves without EXIF data (preserves ICC profile)
- Less precise but works for any Pillow-supported format

### 5.5 PDF Handler

**Dependencies:** pikepdf (required for PDF sanitization)

```
PDF File
    │
    ▼
┌─────────────────────────────────┐
│  1. Strip catalog keys          │  /JavaScript, /OpenAction, /Launch,
│     (document-level)            │  /SubmitForm, /EmbeddedFiles, /XFA
│                                 │
│  2. Strip page actions          │  /AA on each page, dangerous
│     (per-page)                  │  annotation actions (/A with /S)
│                                 │
│  3. Clean DocInfo               │  In strip mode: clear all info
│     (metadata dict)             │  In selective: preserve safe keys
│                                 │
│  4. Scan streams                │  Regex patterns for JS, shellcode,
│     (decoded content)           │  heap spray, obfuscated payloads
└─────────────────────────────────┘
```

### 5.6 Video Handler

**Dependencies:** mutagen (required for video metadata manipulation)

Uses mutagen's format-agnostic interface to remove tags from MP4, MKV, OGG, FLAC, and other containers. Tag names are normalized (e.g., `\xa9xyz` → `xyz`) before matching against rule sets.

### 5.7 Archive Handler

**Dependencies:** None (Python stdlib `zipfile`, `tarfile`)

Archives are **inspected but not modified**. The handler reports:
- Path traversal attempts in archived filenames (`../`)
- Executable files within the archive
- Double extensions (`photo.jpg.exe`)
- Hidden files (`.filename`)
- Compression ratio anomalies (zip bomb detection: ratio > 100:1)

### 5.8 Text Handler

**Dependencies:** None (Python stdlib)

Normalizes encoding and detects embedded threats:
- Strips UTF-8 BOM, null bytes, control characters
- Normalizes line endings (CRLF → LF)
- Detects embedded scripts (`<script>`, shebang, eval/exec, SQL injection patterns)
- Validates JSON structure for telemetry files
- In strip mode: removes lines matching script patterns

---

## 6. Data Models

### 6.1 SanitizationMode (Enum)

| Value | Behavior | When Used |
|---|---|---|
| `strip` | Remove ALL non-essential metadata | T_S >= 0.7 or critical flags |
| `selective` | Remove known-dangerous fields only | Default; T_S between 0.3-0.7 |
| `audit_only` | Log findings, modify nothing | T_S <= 0.3 or forensics mode |

### 6.2 SanitizationChange (per-field record)

```json
{
    "field": "EXIF.GPSInfo",
    "action": "removed",
    "reason": "gps_data_policy",
    "severity": "medium",
    "original_value_preview": "12.97, 77.59...",
    "original_value_size": 48
}
```

**Actions:** `removed`, `redacted`, `normalized`, `truncated`, `flagged`

**Severities:** `info`, `low`, `medium`, `high`, `critical`

### 6.3 MetadataSnapshot (forensic hash)

```json
{
    "field_count": 24,
    "total_size_bytes": 12480,
    "hash_sha256": "a1b2c3d4..."
}
```

### 6.4 SanitizationResult (per-artifact output)

```json
{
    "artifact_id": "artifact://a1b2c3d4e5f6",
    "filename": "drn001_fpv_001.mp4",
    "file_type": "video",
    "mime_type": "video/mp4",
    "sanitized": true,
    "mode": "selective",
    "changes": [
        {"field": "Video.©xyz", "action": "removed", "reason": "gps_data_policy", "severity": "medium"},
        {"field": "Video.©cmt", "action": "removed", "reason": "potential_payload_in_comment", "severity": "low"}
    ],
    "warnings": [],
    "errors": [],
    "metadata_before_hash": "sha256:abc...",
    "metadata_after_hash": "sha256:def...",
    "file_valid_after_sanitization": true,
    "processing_time_ms": 45.2,
    "handler_used": "VideoHandler"
}
```

### 6.5 BatchSanitizationResult (aggregate output)

```json
{
    "summary": {
        "total_processed": 5,
        "total_sanitized": 3,
        "total_skipped": 1,
        "total_errors": 1,
        "total_changes": 12,
        "total_processing_time_ms": 234.5
    },
    "results": [ ... ]
}
```

---

## 7. API Specification

### 7.1 Primary API: `MetadataSanitizer`

```python
from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

config = SanitizerConfig(default_mode="selective", preserve_gps=False)
sanitizer = MetadataSanitizer(config)
```

#### `sanitize_file(artifact_id, file_path, mime_type, threat_score?, mode_override?, insecure_flags?) → SanitizationResult`

Direct file sanitization. Primary entry point for custom integrations.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `artifact_id` | `str` | Yes | Artifact ID from Ingestion Interceptor |
| `file_path` | `str` | Yes | Absolute path to the file on disk |
| `mime_type` | `str` | Yes | MIME type of the file |
| `threat_score` | `float` | No | T_S from Game-Theoretic Estimator (0.0-1.0) |
| `mode_override` | `str` | No | Explicit mode: "strip", "selective", "audit_only" |
| `insecure_flags` | `List[str]` | No | Security flags from ingestion |

#### `sanitize_artifact_record(artifact_record, storage_base_path?, threat_score?, mode_override?, insecure_flags?) → SanitizationResult`

Integration entry point. Accepts an `ArtifactRecord.to_dict()` from the Ingestion Interceptor.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `artifact_record` | `Dict` | Yes | ArtifactRecord dict (artifact_id, filename, mime, pointer_storage) |
| `storage_base_path` | `str` | No | Base path to resolve relative storage pointers |
| `threat_score` | `float` | No | T_S from estimator |
| `mode_override` | `str` | No | Explicit mode |
| `insecure_flags` | `List[str]` | No | Security flags |

#### `sanitize_batch(artifact_records, ...) → BatchSanitizationResult`

Process multiple artifacts sequentially.

#### `stats → Dict[str, int]`

Returns cumulative processing statistics.

### 7.2 Integration Example

```python
from ingestion_interceptor import IngestionInterceptor
from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

# Ingestion
interceptor = IngestionInterceptor(device_registry={...})
ingest_result = interceptor.process(drone_json)

# ... Game-Theoretic Estimator produces threat_score ...
threat_score = 0.65

# Sanitization
sanitizer = MetadataSanitizer(SanitizerConfig())
for artifact in ingest_result.artifact_records:
    san_result = sanitizer.sanitize_artifact_record(
        artifact_record=artifact.to_dict(),
        storage_base_path="drone_remote_store",
        threat_score=threat_score,
        insecure_flags=ingest_result.ingest_metadata.insecure_flags,
    )
    if san_result.errors:
        # Handle sanitization failure
        pass
```

---

## 8. Sequence Diagrams

### 8.1 Single File Sanitization Flow

```
Client              MetadataSanitizer        Handler            Rules          FileSystem
  │                       │                    │                  │                │
  │  sanitize_file(...)   │                    │                  │                │
  │──────────────────────>│                    │                  │                │
  │                       │                    │                  │                │
  │                       │  resolve_mode()    │                  │                │
  │                       │  (threat_score →   │                  │                │
  │                       │   mode selection)  │                  │                │
  │                       │                    │                  │                │
  │                       │  pre-checks        │                  │                │
  │                       │  (file exists?     │                  │                │
  │                       │   size OK?         │                  │                │
  │                       │   MIME excluded?)  │                  │                │
  │                       │                    │                  │                │
  │                       │  get_handler()     │                  │                │
  │                       │───────────────────>│                  │                │
  │                       │  <handler instance>│                  │                │
  │                       │<───────────────────│                  │                │
  │                       │                    │                  │                │
  │                       │  extract_metadata()│                  │                │
  │                       │───────────────────>│                  │                │
  │                       │                    │  read file       │                │
  │                       │                    │────────────────────────────────-->│
  │                       │                    │  <file bytes>    │                │
  │                       │                    │<─────────────────────────────────│
  │                       │  <before_snapshot> │                  │                │
  │                       │<───────────────────│                  │                │
  │                       │                    │                  │                │
  │                       │  preserve_original │                  │                │
  │                       │────────────────────────────────────────────────────-->│
  │                       │                    │                  │   copy → .orig │
  │                       │                    │                  │                │
  │                       │  sanitize()        │                  │                │
  │                       │───────────────────>│                  │                │
  │                       │                    │  get_strip_set() │                │
  │                       │                    │─────────────────>│                │
  │                       │                    │  <tag set>       │                │
  │                       │                    │<────────────────│                │
  │                       │                    │                  │                │
  │                       │                    │  write cleaned   │                │
  │                       │                    │────────────────────────────────-->│
  │                       │  <changes[]>       │                  │                │
  │                       │<───────────────────│                  │                │
  │                       │                    │                  │                │
  │                       │  verify()          │                  │                │
  │                       │───────────────────>│                  │                │
  │                       │                    │  re-parse file   │                │
  │                       │                    │────────────────────────────────-->│
  │                       │  <valid=true>      │                  │                │
  │                       │<───────────────────│                  │                │
  │                       │                    │                  │                │
  │  SanitizationResult   │                    │                  │                │
  │<──────────────────────│                    │                  │                │
  │                       │                    │                  │                │
```

### 8.2 Threat-Score-Driven Mode Selection

```
                    T_S (Threat Score)
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   T_S <= 0.3       0.3 < T_S < 0.7    T_S >= 0.7
        │                │                │
        ▼                ▼                ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐
  │AUDIT_ONLY│    │SELECTIVE │    │  STRIP   │
  │          │    │          │    │          │
  │ Log only │    │ Remove   │    │ Remove   │
  │ No mods  │    │ dangerous│    │ ALL non- │
  │          │    │ fields   │    │ essential│
  └──────────┘    └──────────┘    └──────────┘
        │                │                │
        ▼                ▼                ▼
  Low threat         Medium           High threat
  (routine           threat           (suspicious
   patrol)           (default)         device or
                                      flagged files)
```

---

## 9. Sanitization Rules

### 9.1 EXIF Rules (Images)

| Category | Fields | selective | strip | Rationale |
|---|---|---|---|---|
| **GPS / Location** | GPSInfo, GPSLatitude, GPSLongitude, GPSAltitude, GPS* | Strip | Strip | Exposes operating zones |
| **MakerNote** | MakerNote, MakerNote* (all vendors) | Strip | Strip | Arbitrary binary blob, covert channel |
| **User Text** | UserComment, ImageDescription, XPComment, XP* | Strip | Strip | Script injection vector |
| **Embedded Thumbnails** | JPEGInterchangeFormat, JPEGInterchangeFormatLength | Strip | Strip | Steganography vector |
| **Software** | ProcessingSoftware, Software, HostComputer | Strip | Strip | Pipeline fingerprinting |
| **Device Serial** | BodySerialNumber, CameraSerialNumber, LensSerialNumber | Keep | Strip | Device identification |
| **Camera Model** | Make, Model, LensModel, FirmwareVersion | Keep | Strip | Fingerprinting in high-sec |
| **Timestamps** | DateTimeOriginal, DateTimeDigitized, DateTime | Keep | Strip | Activity correlation |
| **Rendering** | Orientation, ImageWidth, ColorSpace, ExifVersion | Keep | Keep | Required for display |

### 9.2 PDF Rules

| Category | Keys | Action | Rationale |
|---|---|---|---|
| **JavaScript** | /JavaScript, /JS | Always strip | Code execution |
| **Auto-actions** | /OpenAction, /AA, /Launch | Always strip | Triggered without user interaction |
| **Data exfil** | /SubmitForm, /ImportData | Always strip | Sends/imports data automatically |
| **Navigation** | /URI, /GoToR, /GoToE | Always strip | Phishing, remote document loading |
| **Forms** | /AcroForm, /XFA | Always strip | Complex scripting surface |
| **Embedded** | /EmbeddedFiles, /Names | Always strip | Hidden file attachments |
| **Preservation** | /Title, /Pages, /MediaBox, /Contents | Always keep | Structural / display |

**Stream scanning patterns:** `eval(`, `app.alert`, `app.launchURL`, shellcode NOP sleds, heap spray, PowerShell commands, PE headers.

### 9.3 Video Rules

| Category | Atoms/Tags | selective | strip | Rationale |
|---|---|---|---|---|
| **GPS** | ©xyz, ©loc, GPS, location, ISO6709 | Strip | Strip | Location data |
| **Comments** | ©cmt, ©des, ©inf, COMMENT, DESCRIPTION | Strip | Strip | Payload carrier |
| **Cover art** | covr, APIC | Strip | Strip | Embedded image risk |
| **Custom/UUID** | uuid, XMP_ | Strip | Strip | Arbitrary data |
| **Encoder** | ©too, ©enc, ENCODER, WRITING_APP | Keep | Strip | Fingerprinting |
| **Timestamps** | ©day, creation_time, DATE_* | Keep | Strip | Correlation |
| **Structural** | moov, trak, stbl, mvhd, ftyp, mdat | Keep | Keep | Playback required |

### 9.4 Anomaly Detection (All Types)

| Check | Threshold | Severity | Action |
|---|---|---|---|
| EXIF field size | > 64 KB | High | Flag + strip in strip mode |
| Video metadata atom | > 1 MB | High | Flag + strip in strip mode |
| Archive compression ratio | > 100:1 | Critical | Flag (zip bomb) |
| Text null bytes | Any | Medium | Strip |
| Embedded script patterns | Regex match | Critical | Flag / strip lines |

---

## 10. Configuration Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `default_mode` | `str` | `"selective"` | Default sanitization mode |
| `high_threat_mode` | `str` | `"strip"` | Mode when T_S >= strip threshold |
| `low_threat_mode` | `str` | `"audit_only"` | Mode when T_S <= audit threshold |
| `threat_score_strip_threshold` | `float` | `0.7` | T_S above this → strip mode |
| `threat_score_audit_threshold` | `float` | `0.3` | T_S below this → audit mode |
| `preserve_gps` | `bool` | `False` | Keep GPS data in images/video |
| `max_file_size_bytes` | `int` | `500,000,000` | Skip files larger than 500 MB |
| `max_exif_field_bytes` | `int` | `65,536` | Individual EXIF/atom field size cap (used by `BaseHandler.check_field_size_anomaly`) |
| `verify_after_sanitize` | `bool` | `True` | Re-parse file after cleaning; rollback to `.orig` on failure |
| `preserve_originals` | `bool` | `True` | Keep `.orig` copy for forensics |
| `original_suffix` | `str` | `".orig"` | Suffix appended to the preserved-original copy |
| `compute_before_after_hash` | `bool` | `True` | SHA-256 of metadata before/after |
| `output_suffix` | `str` | `""` | Suffix for sanitized files (`""` = in-place) |
| `output_directory` | `str` | `""` | Separate output dir (empty = same as source) |
| `log_all_metadata` | `bool` | `True` | Log extracted metadata before sanitization |
| `log_level` | `str` | `"INFO"` | Logging level |
| `skip_mime_types` | `Set[str]` | executables | MIME types to skip entirely |

> **Reserved (Phase 3):** the following config knobs were stubbed in
> earlier drafts but never wired up. They have been removed from
> `SanitizerConfig` in v2.0 to keep the surface area honest, and will be
> reintroduced when the corresponding features land:
>
> - `sandboxed_execution`, `sandbox_timeout_seconds` — subprocess sandbox for handlers
> - `skip_already_sanitized`, `sanitization_marker_key`, `sanitization_marker_value` — idempotency marker
> - `preserve_camera_serial` — finer-grained EXIF preservation (currently camera serials are removed in `strip` mode along with other identifying tags via `EXIF_STRIP_IN_HIGH_SECURITY`)
> - `max_metadata_size_bytes` — global metadata-size flag (handlers currently use `max_exif_field_bytes` and per-handler constants)
> - `structured_logging` — JSON log format flag

---

## 11. Security Considerations

### 11.1 Threat Model

| Threat | Vector | Mitigation |
|---|---|---|
| **Covert data exfiltration** | GPS coordinates, operator info embedded in EXIF/video metadata | Strip GPS and identification tags |
| **Exploit delivery** | JavaScript in PDF, shellcode in MakerNote, encoded payloads in comments | Remove all executable content from metadata |
| **Steganography** | Thumbnail that differs from main image, oversized metadata fields | Strip thumbnails, flag oversized fields |
| **Pipeline fingerprinting** | Software version, encoder info leaks detection capabilities | Strip software/encoder tags in strip mode |
| **Parser exploitation** | Malformed metadata crafted to exploit Pillow/piexif/pikepdf | Use well-tested libraries, verify output, sandbox |
| **Zip bombs** | High compression ratio archives | Detect ratio > 100:1, flag as critical |
| **Path traversal** | `../../../etc/passwd` in archive entries | Detect and flag traversal patterns |

### 11.2 Defense-in-Depth Layers

```
Layer 1: Ingestion Interceptor
    └── JSON structure validation, filename sanitization, auth

Layer 2: Game-Theoretic Estimator
    └── Threat score determines inspection aggressiveness

Layer 3: Malware Detection Engine
    └── Signature scan, ML classifier, sandbox execution

Layer 4: METADATA SANITIZER  ◄── This module
    └── File-level metadata cleaning, script removal

Layer 5: Threat Intelligence Correlator
    └── Pattern matching against known IoCs from metadata findings

Layer 6: Response & Quarantine Manager
    └── Final disposition: forward, quarantine, or reject
```

### 11.3 Security Properties

| Property | Implementation |
|---|---|
| **Parser safety** | Use well-maintained libraries (Pillow, pikepdf, mutagen); no custom binary parsers |
| **Output validation** | Always verify file integrity after sanitization (re-parse, check rendering) |
| **Sandboxed execution** | *Planned (Phase 3)* — handlers will run in a restricted subprocess (no network, limited FS). Not implemented in v2.0. |
| **Idempotency marker** | *Planned (Phase 3)* — files will carry an `X-Sanitized-By` marker so re-runs short-circuit. Not implemented in v2.0; in practice, re-sanitizing an already-cleaned file is a no-op for SELECTIVE/STRIP mode because there is nothing left to strip. |
| **Forensic preservation** | Keep original file copy and full before/after metadata hash |
| **Graceful degradation** | Missing library → handler unavailable → skip with warning (not crash) |
| **Fail-safe restoration** | If verification fails after sanitization → restore original from `.orig` copy AND reset `result.sanitized=False` so the rollback is reflected in stats and the caller-facing report |

---

## 12. Performance Requirements

### 12.1 Latency Targets

| File Type | Typical Size | Target Latency | Notes |
|---|---|---|---|
| Image (JPEG) | 300 KB - 5 MB | < 100 ms | EXIF manipulation is fast |
| Video (MP4) | 5 MB - 500 MB | < 500 ms | Tag-level only; no transcoding |
| PDF | 100 KB - 50 MB | < 200 ms | Catalog/page scan; stream scan bounded |
| Archive (ZIP) | Variable | < 100 ms | Listing inspection only |
| Text (JSON/CSV) | 1 KB - 10 MB | < 50 ms | In-memory processing |

### 12.2 Resource Bounds

| Resource | Bound | Rationale |
|---|---|---|
| Memory per file | < 2x file size | File loaded once for parsing |
| PDF stream scan | Max 50 objects | Prevent DoS from PDFs with millions of objects |
| Text file read | Max 10 MB | Larger files skipped |
| Handler timeout | 30 seconds (configurable) | Prevent hanging on malformed files |

### 12.3 Throughput

The sanitizer processes files sequentially within a single submission. For high-throughput deployments, multiple sanitizer instances can run in parallel across different submissions (stateless design).

---

## 13. Dependencies

### 13.1 Required Dependencies

| Library | Purpose | License | Required By |
|---|---|---|---|
| Python 3.9+ | Runtime | PSF | All |
| Python stdlib | zipfile, tarfile, json, hashlib, re | PSF | ArchiveHandler, TextHandler |

### 13.2 Optional Dependencies

| Library | Purpose | License | Required By | Fallback |
|---|---|---|---|---|
| `Pillow` (PIL) | Image parsing and metadata extraction | MIT | ImageHandler | Handler unavailable |
| `piexif` | Surgical EXIF tag read/write for JPEG | MIT | ImageHandler | Pillow-only fallback (strips all EXIF) |
| `pikepdf` | PDF structure manipulation | MPL-2.0 | PdfHandler | Handler unavailable |
| `mutagen` | Video/audio metadata read/write | GPL-2.0 | VideoHandler | Handler unavailable |
| `python-magic` | File type detection via magic bytes | MIT | Future: magic-based type detection | MIME from ingestion |

### 13.3 Installation

```bash
# Core (stdlib only — archive + text handlers work immediately)
pip install .

# Full installation (all handlers)
pip install pillow piexif pikepdf mutagen

# Verify handler availability
python -c "from metadata_sanitizer import ImageHandler, PdfHandler, VideoHandler; \
    print(f'Image: {ImageHandler.is_available()}, PDF: {PdfHandler.is_available()}, Video: {VideoHandler.is_available()}')"
```

---

## 14. Testing Strategy

### 14.1 Test Coverage

| Test Class | Tests | What's Covered |
|---|---|---|
| `TestSanitizerConfig` | 4 | Default values, custom overrides, thresholds, skip sets |
| `TestModels` | 8 | Enum values, to_dict() serialization, snapshot creation |
| `TestExifRules` | 10 | Strip sets per mode, GPS preservation, no strip-preserve overlap |
| `TestPdfRules` | 4 | JavaScript/action presence, dangerous actions, no overlap |
| `TestVideoRules` | 4 | GPS/comment/structural tags, no strip-preserve overlap |
| `TestHandlerRegistry` | 10 | MIME routing, prefix fallback, unknown MIME default |
| `TestBaseHandler` | 5 | Snapshot creation, change recording, size anomaly detection |
| `TestTextHandler` | 13 | Encoding, null bytes, BOM, line endings, script detection, audit mode |
| `TestArchiveHandler` | 9 | ZIP metadata, path traversal, executables, double ext, zip bomb |
| `TestSanitizer` | 19 | Mode selection (threat/override/flags/default), pre-checks, text/archive/batch processing, stats, serialization, **verification rollback (with and without `.orig`)** |
| `TestHandlerAvailability` | 5 | `is_available()` for each handler |
| `TestStoragePointerResolution` | 5 | Absolute paths, file:/ URIs, S3 fallback, relative paths |

**Total: 96 unit tests**

### 14.2 Running Tests

```bash
# All tests
python -m unittest metadata_sanitizer.tests.test_sanitizer -v

# With pytest
python -m pytest metadata_sanitizer/tests/ -v

# Specific test class
python -m pytest metadata_sanitizer/tests/test_sanitizer.py::TestTextHandler -v
```

### 14.3 Demo Runner

```bash
python -m metadata_sanitizer.run_demo
```

Processes sample files from `drone_local_storage/` in three modes (audit, selective, threat-driven) and saves results to `sanitizer_demo_output.json`.

---

## 15. Deployment and Operations

### 15.1 Deployment Topology

```
┌─────────────────────────────────────────────────────┐
│                   Edge Node                          │
│                                                     │
│  ┌──────────────────┐  ┌────────────────────────┐   │
│  │    Ingestion     │  │  Metadata Sanitizer    │   │
│  │   Interceptor    │──│  (same process or      │   │
│  │                  │  │   separate container)   │   │
│  └──────────────────┘  └────────────────────────┘   │
│                                                     │
│  Shared filesystem: drone_remote_store/              │
└─────────────────────────────────────────────────────┘
```

### 15.2 Monitoring Checklist

| Metric | Source | Alert Threshold |
|---|---|---|
| Sanitization failures | `sanitizer.stats["total_errors"]` | > 5% of processed |
| Verification failures | Results with `file_valid_after_sanitization=false` | Any occurrence |
| Critical findings | Changes with `severity="critical"` | Any occurrence |
| Processing latency | `result.processing_time_ms` | > 1000 ms per file |
| Handler unavailability | Results with `skip_reason="handler_unavailable"` | Persistent |
| Disk usage (.orig files) | Filesystem monitoring | > 80% capacity |

### 15.3 Operational Procedures

| Procedure | Steps |
|---|---|
| **Enable GPS preservation** | Set `preserve_gps=True` in SanitizerConfig |
| **Switch to audit mode** | Set `default_mode="audit_only"` or pass `mode_override="audit_only"` |
| **Install missing handler** | `pip install pillow piexif` then restart |
| **Investigate sanitization failure** | Check result.errors[], examine .orig file, verify handler availability |
| **Forensic review** | Compare `.orig` file with sanitized version; check metadata_before/after hashes |

---

## 16. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Parser vulnerability in Pillow/pikepdf** | Medium | High | Pin library versions, monitor CVEs, sandbox handlers |
| **False positive: legitimate metadata stripped** | Medium | Medium | Audit-only mode for validation; preserve originals |
| **Performance degradation on large batches** | Low | Medium | Bound per-file processing time; skip oversized files |
| **Handler library not installed** | Medium | Low | Graceful degradation with warnings; stdlib handlers always work |
| **Corrupted output after sanitization** | Low | High | Post-sanitization verification; auto-restore from .orig |
| **Evolving exploit techniques bypass rules** | Medium | High | Rule sets are declarative and easily updated; stream scanning catches novel patterns |
| **GPL license concern (mutagen)** | Low | Medium | mutagen is optional; video handler disabled without it |

---

## 17. Implementation Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| **Phase 1** | Core framework: config, models, orchestrator, handler registry | Done |
| **Phase 1** | Text handler + Archive handler (stdlib only) | Done |
| **Phase 1** | Sanitization rules (EXIF, PDF, video) — declarative definitions | Done |
| **Phase 1** | Image handler (Pillow/piexif, with graceful fallback) | Done |
| **Phase 1** | PDF handler (pikepdf, with graceful fallback) | Done |
| **Phase 1** | Video handler (mutagen, with graceful fallback) | Done |
| **Phase 1** | Unit test suite (94 tests) | Done |
| **Phase 2** | Threat-score-driven mode selection | Done |
| **Phase 2** | Forensic preservation (.orig files, before/after hashing) | Done |
| **Phase 2** | Post-sanitization verification with auto-restore | Done |
| **Phase 2** | Batch processing API | Done |
| **Phase 3** | Sandboxed handler execution (subprocess isolation) | Planned |
| **Phase 3** | Magic-bytes-based file type detection (python-magic) | Planned |
| **Phase 3** | Integration with Threat Intelligence Correlator | Planned |
| **Phase 3** | Async processing (asyncio) for high-throughput | Planned |
| **Phase 3** | gRPC/REST API for microservice deployment | Planned |
| **Phase 3** | Prometheus metrics export | Planned |
| **Phase 3** | Custom rule engine (user-defined strip/keep rules) | Planned |

---

## 18. Glossary

| Term | Definition |
|---|---|
| **Artifact** | A single file (image, video, PDF, etc.) within a drone submission, cataloged by the Ingestion Interceptor |
| **ArtifactRecord** | Structured metadata about an artifact: ID, type, MIME, storage pointer, security flags |
| **EXIF** | Exchangeable Image File Format — metadata standard for images (GPS, camera info, etc.) |
| **IFD** | Image File Directory — a section within EXIF data (IFD0, ExifIFD, GPSIFD, etc.) |
| **IoC** | Indicator of Compromise — observable artifact suggesting a security breach |
| **MakerNote** | Vendor-specific EXIF field with arbitrary binary content; no standard schema |
| **Sanitization** | The process of removing or neutralizing potentially harmful metadata from a file |
| **T_S** | Threat Score — output of the Game-Theoretic Estimator (0.0-1.0) |
| **Stackelberg equilibrium** | Game theory concept used by the Threat Estimator to compute optimal inspection strategy |
| **moov/udta** | MP4 container atoms: moov (movie container), udta (user data with tags) |
| **Zip bomb** | A malicious archive with extreme compression ratio designed to exhaust resources when decompressed |
| **Defense-in-depth** | Security strategy using multiple independent layers so no single failure compromises the system |
