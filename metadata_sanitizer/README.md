# Metadata Sanitizer

File-level embedded-metadata cleaner for the Multi-Layered Malware
Detection and Threat Prevention System for drone/RPA data streams.
Strips potentially harmful EXIF tags, PDF JavaScript, video atoms,
text-encoding hazards, and inspects archive contents.

Runs **after** the Ingestion Interceptor and Malware Detection Engine
as a defence-in-depth layer. Files that passed signature/AI/sandbox
scans may still carry threats embedded in their metadata; this module
cleans them before they cross the operational boundary.

> **Not a wire entry point.** This module receives in-process Python
> objects (an `ArtifactRecord` dict + a file path) from upstream pipeline
> modules. It does NOT accept UDP packets — that's the Ingestion
> Interceptor's job (Module 1, Stage 0). Metadata Sanitizer runs inside
> the trust boundary that the Interceptor establishes. See
> [`docs/design_metadata_sanitizer.md`](../docs/design_metadata_sanitizer.md)
> §3.2.1 for the rationale.

Architecture, sanitization rules, security defenses, requirements, and
risk register live in [`docs/design_metadata_sanitizer.md`](../docs/design_metadata_sanitizer.md).

---

## Requirements

- Python 3.9 or later
- **Core (stdlib only):** `TextHandler` and `ArchiveHandler` work with
  zero dependencies — covers `.txt` / `.csv` / `.json` / `.zip` / `.tar`
- **Optional handlers:** install only what you need for the file types
  you actually process

| Library    | Enables                          | License |
|------------|----------------------------------|---------|
| `Pillow`   | `ImageHandler` (JPEG/PNG/TIFF/BMP) | MIT     |
| `piexif`   | Surgical EXIF tag removal (vs. all-or-nothing) | MIT |
| `pikepdf`  | `PdfHandler`                     | MPL-2.0 |
| `mutagen`  | `VideoHandler` (MP4/MKV/MP3/FLAC) | GPL-2.0 |

```bash
# Full install (all handlers)
pip install pillow piexif pikepdf mutagen

# Verify which handlers are live
python -c "
from metadata_sanitizer.handlers import (
    ImageHandler, PdfHandler, VideoHandler, TextHandler, ArchiveHandler
)
for h in (ImageHandler, PdfHandler, VideoHandler, TextHandler, ArchiveHandler):
    print(f'{h.__name__:18s} {\"available\" if h.is_available() else \"DISABLED (missing dep)\"}')"
```

Handlers that aren't available are skipped gracefully — the orchestrator
records `skip_reason="handler_unavailable"` in the `SanitizationResult`
and a warning telling you which library to install. Other handlers keep
working.

---

## Quick start

All commands are run from the project root: `/home/sangam/Desktop/BTP/`.

### 1. Run the built-in demo

```bash
python -m metadata_sanitizer.run_demo
```

Walks every file in `drone_local_storage/` (or generates synthetic
samples if none exist) through three flows:

1. **Audit-only mode** — log findings, modify nothing
2. **Selective mode** — strip known-dangerous fields (default mode)
3. **Threat-score-driven mode** — same file processed at three threat
   levels (`T_S=0.2`, `0.5`, `0.85`) to demonstrate adaptive aggressiveness

Output is written to `sanitizer_demo_output.json` in the project root.

### 2. Sanitize a single file from your own code

```python
from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

sanitizer = MetadataSanitizer(SanitizerConfig(default_mode="selective"))

result = sanitizer.sanitize_file(
    artifact_id="artifact://abc123",
    file_path="/data/drone_remote_store/DRN-001/photo.jpg",
    mime_type="image/jpeg",
    threat_score=0.5,           # optional — auto-selects mode
)

print(f"Sanitized={result.sanitized}, mode={result.mode}")
for change in result.changes:
    print(f"  [{change.severity}] {change.field}: {change.action} ({change.reason})")
```

### 3. Integrate with the Ingestion Interceptor pipeline

```python
from ingestion_interceptor import IngestionInterceptor
from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

interceptor = IngestionInterceptor(device_registry={...})
sanitizer = MetadataSanitizer(SanitizerConfig())

ingest_result = interceptor.process(drone_json)
if ingest_result.success:
    # ... Game-Theoretic Estimator computes threat_score from ingest_result ...
    threat_score = 0.65

    for artifact in ingest_result.artifact_records:
        san_result = sanitizer.sanitize_artifact_record(
            artifact_record=artifact.to_dict(),
            storage_base_path="drone_remote_store",
            threat_score=threat_score,
            insecure_flags=ingest_result.ingest_metadata.insecure_flags,
        )
        if san_result.errors:
            ...  # quarantine or alert
```

### 4. Batch sanitize an entire submission

```python
batch_result = sanitizer.sanitize_batch(
    artifact_records=[a.to_dict() for a in ingest_result.artifact_records],
    storage_base_path="drone_remote_store",
    threat_score=0.5,
)
print(batch_result.to_dict()["summary"])
# {'total_processed': 3, 'total_sanitized': 2, 'total_skipped': 0,
#  'total_errors': 0, 'total_changes': 11, 'total_processing_time_ms': 84.2}
```

---

## The three sanitization modes

| Mode | Behaviour | When auto-selected |
|---|---|---|
| `audit_only` | Log findings, **modify nothing**. Useful for forensic surveys and pre-deployment validation. | `T_S ≤ 0.3` |
| `selective` (default) | Remove **known-dangerous** fields only (GPS, MakerNote, JS, comments). Preserve operationally useful tags (camera model, timestamps). | `0.3 < T_S < 0.7` |
| `strip` | Aggressively remove **all non-essential** metadata, including device identifiers and timestamps. | `T_S ≥ 0.7` OR `insecure_flags` contains `executable_file` / `suspicious_mime` / `double_extension` |

Mode resolution priority:

```
1. mode_override (explicit caller argument)
2. threat_score thresholds (from Game-Theoretic Estimator)
3. insecure_flags escalation (critical flags → strip)
4. config.default_mode
```

---

## Running the test suite

```bash
# Just this package (96 tests, stdlib unittest)
python -m unittest discover -s metadata_sanitizer/tests -v

# A specific test class
python -m unittest metadata_sanitizer.tests.test_sanitizer.TestSanitizer -v

# A specific test
python -m unittest metadata_sanitizer.tests.test_sanitizer.TestSanitizer.test_verification_failure_resets_sanitized_when_no_rollback -v

# With pytest (if installed)
pytest metadata_sanitizer/tests/ -v
```

Expected output ends with:

```
Ran 96 tests in ~0.02s
OK
```

The tests are stdlib-only and don't require Pillow / pikepdf / mutagen
to pass. The image / PDF / video handlers have availability checks that
let the suite run on any machine.

---

## Module layout

```
metadata_sanitizer/
├── __init__.py              public API surface (re-exports)
├── config.py                SanitizerConfig dataclass
├── models.py                SanitizationResult, SanitizationChange,
│                            MetadataSnapshot, BatchSanitizationResult,
│                            SanitizationMode/ChangeAction/Severity enums
├── sanitizer.py             MetadataSanitizer orchestrator
├── handlers/
│   ├── __init__.py            handler registry + MIME routing
│   ├── base_handler.py        BaseHandler ABC + shared helpers
│   ├── image_handler.py       JPEG/PNG/TIFF/BMP — EXIF scrubbing
│   ├── pdf_handler.py         PDF — JS/auto-action removal
│   ├── video_handler.py       MP4/MKV/MP3/FLAC — atom cleaning
│   ├── archive_handler.py     ZIP/TAR — structure inspection
│   └── text_handler.py        TXT/CSV/JSON — encoding normalization
├── rules/
│   ├── exif_rules.py          EXIF tag strip/keep/flag lists
│   ├── pdf_rules.py           PDF dangerous keys + suspicious patterns
│   └── video_rules.py         Video atom strip/preserve lists
├── run_demo.py              Standalone demo runner
├── README.md                this file
└── tests/
    └── test_sanitizer.py    96 unit tests
```

---

## Key configuration knobs

`SanitizerConfig` defaults are field-deployment safe. Override anything
via the constructor. The full table is in §10 of the design doc.

| Knob | Default | What it does |
|---|---|---|
| `default_mode` | `"selective"` | Mode used when no threat_score / override is given |
| `high_threat_mode` | `"strip"` | Mode picked when `T_S ≥ threat_score_strip_threshold` |
| `low_threat_mode` | `"audit_only"` | Mode picked when `T_S ≤ threat_score_audit_threshold` |
| `threat_score_strip_threshold` | `0.7` | Above this → strip mode |
| `threat_score_audit_threshold` | `0.3` | At or below this → audit-only mode |
| `preserve_gps` | `False` | Keep GPS coordinates in images/video |
| `verify_after_sanitize` | `True` | Re-parse output; rollback to `.orig` if invalid |
| `preserve_originals` | `True` | Keep an `.orig` copy for forensics |
| `compute_before_after_hash` | `True` | SHA-256 of the metadata snapshot before/after |
| `max_file_size_bytes` | `500_000_000` | Skip files larger than 500 MB |
| `max_exif_field_bytes` | `65_536` | Flag individual fields larger than 64 KB |
| `output_suffix` / `output_directory` | `""` / `""` | Override in-place writes |
| `skip_mime_types` | `{exe types}` | MIME types to skip entirely |

---

## Operational stats and result shape

Live counters:

```python
sanitizer.stats
# {'total_processed': N,
#  'total_sanitized': N,    # files where at least one change was applied
#  'total_skipped': N,      # missing handler / oversized / excluded MIME
#  'total_errors': N,       # exceptions inside a handler
#  'total_changes': N}      # cumulative number of fields changed
```

Per-file `SanitizationResult` exposes (via `result.to_dict()`):

```python
{
  "artifact_id": "artifact://abc123",
  "filename": "photo.jpg",
  "file_type": "image",
  "mime_type": "image/jpeg",
  "sanitized": True,
  "mode": "selective",
  "changes": [
    {"field": "EXIF.GPSInfo", "action": "removed",
     "reason": "gps_data_policy", "severity": "medium",
     "original_value_preview": "12.97, 77.59...", "original_value_size": 48},
    {"field": "EXIF.MakerNote", "action": "removed",
     "reason": "arbitrary_vendor_data", "severity": "high"},
  ],
  "warnings": [],
  "errors": [],
  "metadata_before_hash": "sha256:abc...",
  "metadata_after_hash":  "sha256:def...",
  "file_valid_after_sanitization": True,
  "processing_time_ms": 45.2,
  "handler_used": "ImageHandler"
}
```

**Recommended production monitoring:**
- Alert on `total_errors` spike (handler crashes — possible parser exploit)
- Alert on any change with `severity=critical` (PDF JS detected, embedded EXE pattern, zip bomb)
- Alert on `file_valid_after_sanitization=False` (verification rollback fired)
- Track `total_processing_time_ms / total_processed` as throughput health

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `skip_reason="handler_unavailable"` for an image | `pip install pillow piexif` |
| `skip_reason="handler_unavailable"` for a PDF | `pip install pikepdf` |
| `skip_reason="handler_unavailable"` for a video | `pip install mutagen` |
| `skip_reason="file_too_large"` | Bump `max_file_size_bytes` in config |
| `skip_reason="file_not_found"` | Check `pointer_storage` URI resolution; pass `storage_base_path` to `sanitize_artifact_record()` |
| `skip_reason="mime_type_excluded"` | The MIME is in `skip_mime_types` (defaults to executables). Remove from config if you want it processed. |
| `result.sanitized=False` after processing | Check `result.warnings` — likely `file_invalid_after_sanitization` (the post-sanitize verify rolled back). Look at `errors[]` for handler exceptions. |
| GPS still present in cleaned image | Either `preserve_gps=True` is set, OR the handler is unavailable and the file was passed through unchanged. |
| `.orig` files piling up on disk | Set `preserve_originals=False` if you don't need the forensic copy, or run a periodic janitor. |
| Sanitization changes nothing | The file may not have any of the dangerous fields. Check `audit_only` mode first to see what's there. |

---

## See also

- [`docs/design_metadata_sanitizer.md`](../docs/design_metadata_sanitizer.md) — full architecture, sanitization rules, sequence diagrams, security considerations, requirements traceability, risk register
- [`ingestion_interceptor/README.md`](../ingestion_interceptor/README.md) — upstream module that produces the `ArtifactRecord` dicts this sanitizer consumes
- [`drone/README.md`](../drone/README.md) — drone simulator that produces the original files
