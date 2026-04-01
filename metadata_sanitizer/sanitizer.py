"""
Main Metadata Sanitizer orchestrator.

Routes artifact files to the appropriate handler based on MIME type,
manages sanitization modes (threat-score-driven or manual), and
produces structured SanitizationResult reports.
"""

import hashlib
import logging
import os
import shutil
import time
from typing import Any, Dict, List, Optional

from .config import SanitizerConfig
from .handlers import get_handler_for_mime
from .handlers.base_handler import BaseHandler
from .models import (
    BatchSanitizationResult,
    MetadataSnapshot,
    SanitizationChange,
    SanitizationMode,
    SanitizationResult,
)

logger = logging.getLogger(__name__)


class MetadataSanitizer:
    """
    Core orchestrator for file-level metadata sanitization.

    Sits in the detection pipeline after the Malware Detection Engine.
    Receives artifact records from the Ingestion Interceptor and threat
    scores from the Game-Theoretic Estimator to determine sanitization
    aggressiveness.

    Pipeline position:
        Ingestion Interceptor → Threat Estimator → Malware Detection
            → **Metadata Sanitizer** → Threat Intelligence Correlator

    Usage:
        from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

        config = SanitizerConfig(default_mode="selective")
        sanitizer = MetadataSanitizer(config)

        result = sanitizer.sanitize_file(
            artifact_id="artifact://abc123",
            file_path="/path/to/image.jpg",
            mime_type="image/jpeg",
            threat_score=0.45,
        )
    """

    def __init__(self, config: Optional[SanitizerConfig] = None):
        self.config = config or SanitizerConfig()
        self._setup_logging()

        # Cache handler instances (one per handler class)
        self._handler_cache: Dict[str, BaseHandler] = {}

        # Statistics
        self._stats = {
            "total_processed": 0,
            "total_sanitized": 0,
            "total_skipped": 0,
            "total_errors": 0,
            "total_changes": 0,
        }

    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.config.log_level, logging.INFO),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

    # ── Public API ─────────────────────────────────────────────────────

    def sanitize_file(
        self,
        artifact_id: str,
        file_path: str,
        mime_type: str,
        threat_score: Optional[float] = None,
        mode_override: Optional[str] = None,
        insecure_flags: Optional[List[str]] = None,
    ) -> SanitizationResult:
        """
        Sanitize metadata for a single file.

        Args:
            artifact_id: Artifact ID from the Ingestion Interceptor.
            file_path: Absolute path to the file on disk.
            mime_type: MIME type of the file.
            threat_score: Threat score (0.0-1.0) from Game-Theoretic Estimator.
                          Used to auto-select sanitization mode if mode_override
                          is not provided.
            mode_override: Explicit sanitization mode ("strip", "selective",
                           "audit_only"). Overrides threat-score-based selection.
            insecure_flags: Security flags from the Ingestion Interceptor.
                            Used as additional signal for mode selection.

        Returns:
            SanitizationResult with full audit trail.
        """
        start_time = time.time()
        filename = os.path.basename(file_path)

        # Determine sanitization mode
        mode = self._resolve_mode(threat_score, mode_override, insecure_flags)

        # Build base result
        result = SanitizationResult(
            artifact_id=artifact_id,
            filename=filename,
            file_type=self._file_type_from_mime(mime_type),
            mime_type=mime_type,
            sanitized=False,
            mode=mode.value,
        )

        # ── Pre-checks ────────────────────────────────────────────────

        # File existence
        if not os.path.isfile(file_path):
            result.skipped = True
            result.skip_reason = "file_not_found"
            result.errors.append(f"file_not_found:{file_path}")
            self._stats["total_skipped"] += 1
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result

        # File size check
        file_size = os.path.getsize(file_path)
        if file_size > self.config.max_file_size_bytes:
            result.skipped = True
            result.skip_reason = f"file_too_large:{file_size}_bytes"
            result.warnings.append(f"file_exceeds_max_size:{file_size}")
            self._stats["total_skipped"] += 1
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result

        # Skip MIME types marked as untouchable
        if mime_type.lower() in self.config.skip_mime_types:
            result.skipped = True
            result.skip_reason = f"mime_type_excluded:{mime_type}"
            self._stats["total_skipped"] += 1
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result

        # ── Get handler ───────────────────────────────────────────────

        handler_class = get_handler_for_mime(mime_type)
        handler = self._get_handler(handler_class)
        result.handler_used = handler_class.handler_name()

        if not handler_class.is_available():
            result.skipped = True
            result.skip_reason = f"handler_unavailable:{handler_class.handler_name()}"
            result.warnings.append(
                f"Required library not installed for {handler_class.handler_name()}. "
                f"Install dependencies to enable {result.file_type} sanitization."
            )
            self._stats["total_skipped"] += 1
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result

        # ── Extract metadata (before snapshot) ────────────────────────

        if self.config.log_all_metadata or self.config.compute_before_after_hash:
            try:
                before_meta = handler.extract_metadata(file_path)
                result.metadata_before = handler.create_metadata_snapshot(before_meta)
                if self.config.log_all_metadata:
                    logger.info(
                        "Metadata before sanitization [%s]: %d fields, %d bytes",
                        artifact_id,
                        result.metadata_before.field_count,
                        result.metadata_before.total_size_bytes,
                    )
            except Exception as e:
                result.warnings.append(f"metadata_extraction_before_failed:{e}")

        # ── Preserve original (forensics) ─────────────────────────────

        output_path = self._compute_output_path(file_path)

        if self.config.preserve_originals and mode != SanitizationMode.AUDIT_ONLY:
            orig_path = file_path + self.config.original_suffix
            if not os.path.exists(orig_path):
                try:
                    shutil.copy2(file_path, orig_path)
                except Exception as e:
                    result.warnings.append(f"original_preservation_failed:{e}")

        # ── Sanitize ──────────────────────────────────────────────────

        try:
            changes = handler.sanitize(file_path, output_path, mode)
            result.changes = changes
            result.sanitized = any(
                c.action != "flagged" for c in changes
            )
        except Exception as e:
            logger.error("Sanitization failed for %s: %s", artifact_id, e)
            result.errors.append(f"sanitization_error:{e}")
            self._stats["total_errors"] += 1
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result

        # ── Verify output ─────────────────────────────────────────────

        if self.config.verify_after_sanitize and result.sanitized:
            verify_path = output_path if output_path != file_path else file_path
            try:
                result.file_valid_after_sanitization = handler.verify(verify_path)
                if not result.file_valid_after_sanitization:
                    result.warnings.append("file_invalid_after_sanitization")
                    # Restore original if verification fails
                    orig_path = file_path + self.config.original_suffix
                    if os.path.exists(orig_path):
                        shutil.copy2(orig_path, output_path)
                        result.warnings.append("original_restored_after_verification_failure")
            except Exception as e:
                result.warnings.append(f"verification_failed:{e}")

        # ── Extract metadata (after snapshot) ─────────────────────────

        if self.config.compute_before_after_hash and result.sanitized:
            try:
                after_path = output_path if output_path != file_path else file_path
                after_meta = handler.extract_metadata(after_path)
                result.metadata_after = handler.create_metadata_snapshot(after_meta)
            except Exception as e:
                result.warnings.append(f"metadata_extraction_after_failed:{e}")

        # ── Update stats ──────────────────────────────────────────────

        self._stats["total_processed"] += 1
        if result.sanitized:
            self._stats["total_sanitized"] += 1
        self._stats["total_changes"] += len(result.changes)

        elapsed = time.time() - start_time
        result.processing_time_ms = elapsed * 1000

        logger.info(
            "Sanitized %s [%s] mode=%s changes=%d sanitized=%s in %.1fms",
            artifact_id, mime_type, mode.value,
            len(result.changes), result.sanitized, result.processing_time_ms,
        )

        return result

    def sanitize_artifact_record(
        self,
        artifact_record: Dict[str, Any],
        storage_base_path: str = "",
        threat_score: Optional[float] = None,
        mode_override: Optional[str] = None,
        insecure_flags: Optional[List[str]] = None,
    ) -> SanitizationResult:
        """
        Sanitize using an ArtifactRecord dict from the Ingestion Interceptor.

        Resolves the file path from pointer_storage and delegates to
        sanitize_file(). This is the primary integration point with the
        Ingestion Interceptor output.

        Args:
            artifact_record: ArtifactRecord.to_dict() output.
            storage_base_path: Base path to resolve relative storage pointers.
            threat_score: T_S from Game-Theoretic Estimator.
            mode_override: Explicit mode override.
            insecure_flags: Security flags from ingest_metadata.

        Returns:
            SanitizationResult for this artifact.
        """
        artifact_id = artifact_record.get("artifact_id", "unknown")
        filename = artifact_record.get("filename", "unknown")
        mime_type = artifact_record.get("mime", "application/octet-stream")
        pointer = artifact_record.get("pointer_storage", "")

        # Resolve file path from storage pointer
        file_path = self._resolve_storage_pointer(pointer, storage_base_path, filename)

        return self.sanitize_file(
            artifact_id=artifact_id,
            file_path=file_path,
            mime_type=mime_type,
            threat_score=threat_score,
            mode_override=mode_override,
            insecure_flags=insecure_flags or artifact_record.get("security_flags", []),
        )

    def sanitize_batch(
        self,
        artifact_records: List[Dict[str, Any]],
        storage_base_path: str = "",
        threat_score: Optional[float] = None,
        mode_override: Optional[str] = None,
    ) -> BatchSanitizationResult:
        """
        Sanitize multiple artifacts in sequence.

        Args:
            artifact_records: List of ArtifactRecord dicts.
            storage_base_path: Base path for storage resolution.
            threat_score: Shared threat score for all artifacts.
            mode_override: Explicit mode override for all artifacts.

        Returns:
            BatchSanitizationResult with individual and aggregate results.
        """
        batch_result = BatchSanitizationResult()

        for record in artifact_records:
            result = self.sanitize_artifact_record(
                artifact_record=record,
                storage_base_path=storage_base_path,
                threat_score=threat_score,
                mode_override=mode_override,
            )
            batch_result.results.append(result)
            batch_result.total_processed += 1
            batch_result.total_processing_time_ms += result.processing_time_ms
            batch_result.total_changes += len(result.changes)

            if result.sanitized:
                batch_result.total_sanitized += 1
            if result.skipped:
                batch_result.total_skipped += 1
            if result.errors:
                batch_result.total_errors += 1

        return batch_result

    @property
    def stats(self) -> Dict[str, int]:
        """Return current processing statistics."""
        return dict(self._stats)

    # ── Private methods ────────────────────────────────────────────────

    def _resolve_mode(
        self,
        threat_score: Optional[float],
        mode_override: Optional[str],
        insecure_flags: Optional[List[str]],
    ) -> SanitizationMode:
        """
        Determine sanitization mode from threat score and/or explicit override.

        Priority:
            1. Explicit mode_override
            2. Threat-score-driven selection
            3. Insecure flags escalation
            4. Default config mode
        """
        # 1. Explicit override
        if mode_override:
            try:
                return SanitizationMode(mode_override)
            except ValueError:
                logger.warning("Invalid mode_override '%s', using default", mode_override)

        # 2. Threat-score-driven
        if threat_score is not None:
            if threat_score >= self.config.threat_score_strip_threshold:
                return SanitizationMode(self.config.high_threat_mode)
            elif threat_score <= self.config.threat_score_audit_threshold:
                return SanitizationMode(self.config.low_threat_mode)
            else:
                return SanitizationMode.SELECTIVE

        # 3. Insecure flags escalation
        if insecure_flags:
            critical_flags = {"executable_file", "suspicious_mime", "double_extension"}
            if critical_flags & set(insecure_flags):
                return SanitizationMode.STRIP

        # 4. Default
        return SanitizationMode(self.config.default_mode)

    def _get_handler(self, handler_class: type) -> BaseHandler:
        """Get or create a cached handler instance."""
        name = handler_class.__name__
        if name not in self._handler_cache:
            self._handler_cache[name] = handler_class(self.config)
        return self._handler_cache[name]

    def _compute_output_path(self, file_path: str) -> str:
        """Compute the output file path based on config."""
        if self.config.output_suffix:
            base, ext = os.path.splitext(file_path)
            return f"{base}{self.config.output_suffix}{ext}"
        if self.config.output_directory:
            os.makedirs(self.config.output_directory, exist_ok=True)
            return os.path.join(self.config.output_directory, os.path.basename(file_path))
        return file_path  # In-place

    def _resolve_storage_pointer(
        self, pointer: str, base_path: str, filename: str
    ) -> str:
        """
        Resolve a storage pointer URI to a local file path.

        Supports:
            - Filesystem paths (relative or absolute)
            - file:/ URIs
            - Falls back to base_path + filename
        """
        if not pointer:
            if base_path and filename:
                return os.path.join(base_path, filename)
            return ""

        # file:/ URI
        if pointer.startswith("file:/"):
            return pointer.replace("file:/", "/", 1)

        # S3/MinIO URIs — not directly accessible
        if pointer.startswith("s3://") or pointer.startswith("minio://"):
            # Fall back to local path
            if base_path and filename:
                return os.path.join(base_path, filename)
            return ""

        # Assume filesystem path
        if os.path.isabs(pointer):
            return pointer

        # Relative path
        if base_path:
            return os.path.join(base_path, pointer)

        return pointer

    @staticmethod
    def _file_type_from_mime(mime_type: str) -> str:
        """Map MIME type to a broad file type category."""
        mime_lower = mime_type.lower()
        if mime_lower.startswith("image/"):
            return "image"
        if mime_lower.startswith("video/"):
            return "video"
        if mime_lower.startswith("audio/"):
            return "audio"
        if mime_lower == "application/pdf":
            return "pdf"
        if mime_lower in ("application/zip", "application/x-tar", "application/gzip"):
            return "archive"
        if mime_lower.startswith("text/") or mime_lower == "application/json":
            return "text"
        return "unknown"
