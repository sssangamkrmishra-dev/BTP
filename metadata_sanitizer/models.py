"""
Data models for the Metadata Sanitizer pipeline.
Uses dataclasses for structured, typed representations of all entities.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SanitizationMode(Enum):
    """Sanitization aggressiveness level."""
    STRIP = "strip"             # Remove all non-essential metadata
    SELECTIVE = "selective"     # Remove known-dangerous fields only
    AUDIT_ONLY = "audit_only"  # Log metadata without modification


class ChangeAction(Enum):
    """Type of modification applied to a metadata field."""
    REMOVED = "removed"
    REDACTED = "redacted"
    NORMALIZED = "normalized"
    TRUNCATED = "truncated"
    FLAGGED = "flagged"        # audit-only: field noted but not changed


class Severity(Enum):
    """Severity of a sanitization finding."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SanitizationChange:
    """
    Record of a single metadata modification.
    Provides full traceability for forensic audit trails.
    """
    field: str                              # e.g. "EXIF.GPSInfo", "PDF./JavaScript"
    action: str                             # ChangeAction value
    reason: str                             # human-readable reason
    severity: str = "info"                  # Severity value
    original_value_preview: Optional[str] = None  # first 200 chars of original (if safe)
    original_value_size: Optional[int] = None     # byte size of original value

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "field": self.field,
            "action": self.action,
            "reason": self.reason,
            "severity": self.severity,
        }
        if self.original_value_preview is not None:
            d["original_value_preview"] = self.original_value_preview
        if self.original_value_size is not None:
            d["original_value_size"] = self.original_value_size
        return d


@dataclass
class MetadataSnapshot:
    """
    Captured snapshot of metadata before or after sanitization.
    Used for forensic comparison and audit logging.
    """
    fields: Dict[str, Any]                 # extracted metadata key-value pairs
    total_size_bytes: int = 0              # total byte size of all metadata
    hash_sha256: Optional[str] = None      # SHA-256 hash of serialized metadata
    field_count: int = 0                   # number of metadata fields

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_count": self.field_count,
            "total_size_bytes": self.total_size_bytes,
            "hash_sha256": self.hash_sha256,
        }


@dataclass
class SanitizationResult:
    """
    Output of sanitizing a single artifact.
    Contains the full audit trail of what was found and what was changed.
    """
    artifact_id: str                                # artifact:// ID from ingestion interceptor
    filename: str                                   # original filename
    file_type: str                                  # detected file type (image, video, pdf, etc.)
    mime_type: str                                  # MIME type
    sanitized: bool                                 # whether any modifications were made
    mode: str                                       # SanitizationMode value used
    changes: List[SanitizationChange] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata_before: Optional[MetadataSnapshot] = None
    metadata_after: Optional[MetadataSnapshot] = None
    file_valid_after_sanitization: Optional[bool] = None
    processing_time_ms: float = 0.0
    handler_used: str = "none"
    skipped: bool = False
    skip_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "filename": self.filename,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "sanitized": self.sanitized,
            "mode": self.mode,
            "changes": [c.to_dict() for c in self.changes],
            "warnings": self.warnings,
            "errors": self.errors,
            "file_valid_after_sanitization": self.file_valid_after_sanitization,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "handler_used": self.handler_used,
        }
        if self.metadata_before:
            d["metadata_before_hash"] = self.metadata_before.hash_sha256
        if self.metadata_after:
            d["metadata_after_hash"] = self.metadata_after.hash_sha256
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class BatchSanitizationResult:
    """Aggregated result for batch sanitization of multiple artifacts."""
    results: List[SanitizationResult] = field(default_factory=list)
    total_processed: int = 0
    total_sanitized: int = 0
    total_skipped: int = 0
    total_errors: int = 0
    total_changes: int = 0
    total_processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_processed": self.total_processed,
                "total_sanitized": self.total_sanitized,
                "total_skipped": self.total_skipped,
                "total_errors": self.total_errors,
                "total_changes": self.total_changes,
                "total_processing_time_ms": round(self.total_processing_time_ms, 2),
            },
            "results": [r.to_dict() for r in self.results],
        }
