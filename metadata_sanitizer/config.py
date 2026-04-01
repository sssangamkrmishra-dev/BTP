"""
Configuration for the Metadata Sanitizer module.
All tuneable parameters are centralized here.
"""

from dataclasses import dataclass, field
from typing import Set


@dataclass
class SanitizerConfig:
    """
    Configuration for the Metadata Sanitizer.

    Controls sanitization behaviour, threat-score-driven mode selection,
    file handling limits, and forensic preservation settings.
    """

    # ── Sanitization mode ──────────────────────────────────────────────
    default_mode: str = "selective"       # "strip", "selective", "audit_only"
    high_threat_mode: str = "strip"       # mode when threat score exceeds upper threshold
    low_threat_mode: str = "audit_only"   # mode when threat score is below lower threshold

    # ── Threat-score thresholds for automatic mode selection ───────────
    # If a threat score (T_S) from the Game-Theoretic Estimator is provided,
    # the sanitizer picks the mode automatically:
    #   T_S >= strip_threshold       → "strip"
    #   T_S <= audit_threshold       → "audit_only"
    #   otherwise                    → "selective"
    threat_score_strip_threshold: float = 0.7
    threat_score_audit_threshold: float = 0.3

    # ── GPS / location handling ────────────────────────────────────────
    preserve_gps: bool = False            # keep GPS coordinates in image/video metadata
    preserve_camera_serial: bool = False  # keep camera serial numbers

    # ── Size limits ────────────────────────────────────────────────────
    max_metadata_size_bytes: int = 1_048_576   # 1 MB — flag fields exceeding this
    max_file_size_bytes: int = 500_000_000     # 500 MB — skip files larger than this
    max_exif_field_bytes: int = 65_536         # 64 KB — individual EXIF field size cap

    # ── Post-sanitization verification ─────────────────────────────────
    verify_after_sanitize: bool = True    # re-parse file after cleaning to confirm validity

    # ── Forensic preservation ──────────────────────────────────────────
    preserve_originals: bool = True       # keep un-modified copy before sanitization
    original_suffix: str = ".orig"        # suffix for preserved originals
    compute_before_after_hash: bool = True  # SHA-256 of metadata before and after

    # ── Output ─────────────────────────────────────────────────────────
    output_suffix: str = ""               # suffix for sanitized files ("" = in-place)
    output_directory: str = ""            # separate output dir (empty = same as source)

    # ── Logging ────────────────────────────────────────────────────────
    log_all_metadata: bool = True         # log extracted metadata before sanitization
    log_level: str = "INFO"
    structured_logging: bool = True

    # ── Sandbox ────────────────────────────────────────────────────────
    sandboxed_execution: bool = False     # run handlers in restricted subprocess
    sandbox_timeout_seconds: float = 30.0

    # ── Handler selection ──────────────────────────────────────────────
    # MIME types to skip entirely (already handled elsewhere or untrusted)
    skip_mime_types: Set[str] = field(default_factory=lambda: {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
    })

    # ── Idempotency ───────────────────────────────────────────────────
    skip_already_sanitized: bool = True   # skip files bearing a sanitization marker
    sanitization_marker_key: str = "X-Sanitized-By"
    sanitization_marker_value: str = "MetadataSanitizer/1.0"
