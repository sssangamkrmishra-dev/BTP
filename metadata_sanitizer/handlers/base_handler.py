"""
Abstract base class for all file-type metadata handlers.

Every handler must implement extract_metadata(), sanitize(), and verify().
The base class provides common utilities for hashing, size checks,
and change recording.
"""

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from ..config import SanitizerConfig
from ..models import MetadataSnapshot, SanitizationChange, SanitizationMode


class BaseHandler(ABC):
    """
    Abstract handler interface for file-type-specific metadata sanitization.

    Subclasses implement the three core methods for their file type.
    The base class provides shared helper utilities.
    """

    def __init__(self, config: SanitizerConfig):
        self.config = config
        self.logger = logging.getLogger(f"sanitizer.{self.__class__.__name__}")

    # ── Abstract interface ─────────────────────────────────────────────

    @abstractmethod
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract all embedded metadata from the file.

        Args:
            file_path: Absolute path to the file on disk.

        Returns:
            Dictionary of metadata field names to values.
            Values should be JSON-serializable where possible.
        """

    @abstractmethod
    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """
        Apply sanitization rules to the file, writing the result to output_path.

        In AUDIT_ONLY mode, no modifications are made but findings are still
        returned as SanitizationChange records with action="flagged".

        Args:
            file_path: Path to the source file.
            output_path: Path for the sanitized output.
                         May be same as file_path for in-place sanitization.
            mode: Sanitization aggressiveness level.

        Returns:
            List of changes made (or flagged in audit mode).
        """

    @abstractmethod
    def verify(self, file_path: str) -> bool:
        """
        Verify that a file is still valid after sanitization.

        Re-parses the file to confirm it can be opened and rendered
        correctly. Should catch corruption introduced by metadata removal.

        Args:
            file_path: Path to the sanitized file.

        Returns:
            True if the file is valid, False otherwise.
        """

    @abstractmethod
    def supported_mimes(self) -> Set[str]:
        """Return the set of MIME types this handler can process."""

    @classmethod
    def is_available(cls) -> bool:
        """
        Check whether the handler's required libraries are installed.

        Returns True if all dependencies are available, False otherwise.
        Handlers with missing deps return False here; the orchestrator
        will skip them with an appropriate warning.
        """
        return True

    @classmethod
    def handler_name(cls) -> str:
        """Human-readable handler name for logs and reports."""
        return cls.__name__

    # ── Shared helpers ─────────────────────────────────────────────────

    def create_metadata_snapshot(self, metadata: Dict[str, Any]) -> MetadataSnapshot:
        """Create a MetadataSnapshot with hash and size from a metadata dict."""
        serialized = json.dumps(metadata, sort_keys=True, default=str).encode("utf-8")
        return MetadataSnapshot(
            fields=metadata,
            total_size_bytes=len(serialized),
            hash_sha256=hashlib.sha256(serialized).hexdigest(),
            field_count=len(metadata),
        )

    def make_change(
        self,
        field_name: str,
        action: str,
        reason: str,
        severity: str = "info",
        original_value: Any = None,
    ) -> SanitizationChange:
        """Helper to construct a SanitizationChange record."""
        preview = None
        size = None
        if original_value is not None:
            val_str = str(original_value)
            preview = val_str[:200] + ("..." if len(val_str) > 200 else "")
            if isinstance(original_value, (bytes, bytearray)):
                size = len(original_value)
            elif isinstance(original_value, str):
                size = len(original_value.encode("utf-8", errors="replace"))
        return SanitizationChange(
            field=field_name,
            action=action,
            reason=reason,
            severity=severity,
            original_value_preview=preview,
            original_value_size=size,
        )

    def check_field_size_anomaly(
        self, field_name: str, value: Any, threshold: Optional[int] = None
    ) -> Optional[SanitizationChange]:
        """Flag a metadata field if its size exceeds the anomaly threshold."""
        threshold = threshold or self.config.max_exif_field_bytes
        size = 0
        if isinstance(value, (bytes, bytearray)):
            size = len(value)
        elif isinstance(value, str):
            size = len(value.encode("utf-8", errors="replace"))
        else:
            size = len(str(value))

        if size > threshold:
            return self.make_change(
                field_name=field_name,
                action="flagged",
                reason=f"field_size_anomaly:{size}_bytes_exceeds_{threshold}",
                severity="high",
                original_value=f"[{size} bytes]",
            )
        return None
