"""
Video/audio metadata sanitization handler.

Handles metadata in MP4, MKV, AVI, WebM, and audio containers.
Uses mutagen for metadata manipulation when available.

When mutagen is not installed, the handler reports itself as unavailable.
"""

import logging
import os
import shutil
from typing import Any, Dict, List, Set

from ..config import SanitizerConfig
from ..models import SanitizationChange, SanitizationMode
from ..rules.video_rules import (
    VIDEO_ALWAYS_PRESERVE,
    VIDEO_ALWAYS_STRIP_ATOMS,
    VIDEO_SIZE_ANOMALY_THRESHOLD,
    VIDEO_STRIP_IN_HIGH_SECURITY,
)
from .base_handler import BaseHandler

logger = logging.getLogger(__name__)

# ── Optional dependency ────────────────────────────────────────────────

_MUTAGEN_AVAILABLE = False

try:
    import mutagen
    from mutagen.mp4 import MP4
    from mutagen.oggvorbis import OggVorbis
    from mutagen.flac import FLAC
    _MUTAGEN_AVAILABLE = True
except ImportError:
    mutagen = None  # type: ignore[assignment]
    MP4 = None  # type: ignore[assignment, misc]


class VideoHandler(BaseHandler):
    """
    Sanitizer handler for video and audio files.

    Capabilities:
        - Extract metadata tags from MP4, MKV, OGG, FLAC containers
        - Strip GPS, comments, encoder info, custom atoms
        - Detect oversized metadata atoms (potential embedded payloads)
        - Verify container integrity after sanitization
    """

    def __init__(self, config: SanitizerConfig):
        super().__init__(config)

    @classmethod
    def is_available(cls) -> bool:
        return _MUTAGEN_AVAILABLE

    def supported_mimes(self) -> Set[str]:
        return {
            "video/mp4", "video/x-matroska", "video/avi", "video/x-msvideo",
            "video/quicktime", "video/webm",
            "audio/mpeg", "audio/mp4", "audio/x-flac", "audio/ogg",
        }

    # ── Core interface ─────────────────────────────────────────────────

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata tags from a video/audio file."""
        if not _MUTAGEN_AVAILABLE:
            return {"_error": "mutagen not installed"}

        metadata: Dict[str, Any] = {}
        try:
            media = mutagen.File(file_path)
            if media is None:
                return {"_error": "unrecognized_format"}

            # Basic container info
            if media.info:
                metadata["_duration_seconds"] = getattr(media.info, "length", None)
                metadata["_bitrate"] = getattr(media.info, "bitrate", None)
                metadata["_sample_rate"] = getattr(media.info, "sample_rate", None)
                metadata["_channels"] = getattr(media.info, "channels", None)

            # Tags
            if media.tags:
                for key in media.tags.keys():
                    value = media.tags[key]
                    if isinstance(value, bytes):
                        metadata[str(key)] = f"[bytes:{len(value)}]"
                    elif isinstance(value, list):
                        metadata[str(key)] = [str(v)[:200] for v in value[:5]]
                    else:
                        metadata[str(key)] = str(value)[:500]

        except Exception as e:
            metadata["_error"] = f"extraction_failed:{e}"
            self.logger.warning("Failed to extract video metadata from %s: %s", file_path, e)

        return metadata

    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """Sanitize video/audio metadata tags."""
        changes: List[SanitizationChange] = []

        if mode == SanitizationMode.AUDIT_ONLY:
            return self._audit_only(file_path, changes)

        if not _MUTAGEN_AVAILABLE:
            changes.append(self.make_change(
                "_handler", "flagged",
                "mutagen_not_installed:cannot_sanitize_video", "high"
            ))
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            return changes

        # Copy to output first, then modify in place
        if file_path != output_path:
            shutil.copy2(file_path, output_path)

        try:
            media = mutagen.File(output_path)
            if media is None or media.tags is None:
                return changes

            strip_set = self._get_strip_set(mode)
            keys_to_remove = []

            for key in list(media.tags.keys()):
                key_str = str(key)
                tag_name = self._normalize_tag_name(key_str)

                if tag_name in VIDEO_ALWAYS_PRESERVE:
                    continue

                should_strip = False
                reason = "metadata_policy"

                if tag_name in strip_set or key_str in strip_set:
                    should_strip = True
                    reason = self._reason_for_tag(tag_name)
                elif mode == SanitizationMode.STRIP and tag_name not in VIDEO_ALWAYS_PRESERVE:
                    # In strip mode, remove everything not explicitly preserved
                    should_strip = True
                    reason = "strip_mode_non_essential"

                if should_strip:
                    value = media.tags[key]
                    changes.append(self.make_change(
                        f"Video.{key_str}", "removed", reason,
                        self._severity_for_tag(tag_name),
                        original_value=value,
                    ))
                    keys_to_remove.append(key)

                # Check for oversized tags
                value = media.tags[key]
                anomaly = self.check_field_size_anomaly(
                    f"Video.{key_str}", value, VIDEO_SIZE_ANOMALY_THRESHOLD
                )
                if anomaly:
                    changes.append(anomaly)
                    if mode == SanitizationMode.STRIP and key not in keys_to_remove:
                        keys_to_remove.append(key)

            # Remove tags
            for key in keys_to_remove:
                try:
                    del media.tags[key]
                except (KeyError, TypeError):
                    pass

            media.save()

        except Exception as e:
            self.logger.error("Video sanitization failed for %s: %s", file_path, e)
            changes.append(self.make_change(
                "_handler", "flagged",
                f"sanitization_failed:{e}", "critical"
            ))

        return changes

    def verify(self, file_path: str) -> bool:
        """Verify the video file can still be parsed after sanitization."""
        if not _MUTAGEN_AVAILABLE:
            return True

        try:
            media = mutagen.File(file_path)
            return media is not None
        except Exception as e:
            self.logger.error("Video verification failed for %s: %s", file_path, e)
            return False

    # ── Private methods ────────────────────────────────────────────────

    def _audit_only(
        self, file_path: str, changes: List[SanitizationChange]
    ) -> List[SanitizationChange]:
        """Flag metadata without modifying."""
        metadata = self.extract_metadata(file_path)
        strip_set = self._get_strip_set(SanitizationMode.SELECTIVE)

        for field_name, value in metadata.items():
            if field_name.startswith("_"):
                continue
            tag_name = self._normalize_tag_name(field_name)
            if tag_name in strip_set or field_name in strip_set:
                changes.append(self.make_change(
                    f"Video.{field_name}", "flagged",
                    "would_be_stripped_in_selective_mode", "medium",
                    original_value=value,
                ))

        return changes

    def _get_strip_set(self, mode: SanitizationMode) -> Set[str]:
        """Get the combined set of tags to strip for the given mode."""
        strip_set = set(VIDEO_ALWAYS_STRIP_ATOMS)
        if mode == SanitizationMode.STRIP:
            strip_set |= VIDEO_STRIP_IN_HIGH_SECURITY
        if self.config.preserve_gps:
            gps_tags = {t for t in strip_set
                        if any(g in t.lower() for g in ("gps", "xyz", "loc", "location"))}
            strip_set -= gps_tags
        return strip_set

    @staticmethod
    def _normalize_tag_name(key: str) -> str:
        """Normalize a mutagen tag key to match our rule sets."""
        # Remove leading copyright symbol used by Apple atoms
        cleaned = key.lstrip("\xa9").lstrip("©")
        return cleaned

    @staticmethod
    def _reason_for_tag(tag_name: str) -> str:
        """Return reason string for stripping a video tag."""
        lower = tag_name.lower()
        if any(g in lower for g in ("gps", "xyz", "loc", "location")):
            return "gps_data_policy"
        if any(c in lower for c in ("cmt", "comment", "des", "description")):
            return "potential_payload_in_comment"
        if any(e in lower for e in ("enc", "tool", "swr", "software")):
            return "encoder_fingerprinting"
        if any(a in lower for a in ("art", "aut", "dir", "own", "prf", "pub")):
            return "attribution_data"
        if "covr" in lower or "apic" in lower:
            return "embedded_image_risk"
        return "metadata_policy"

    @staticmethod
    def _severity_for_tag(tag_name: str) -> str:
        lower = tag_name.lower()
        if any(g in lower for g in ("gps", "xyz", "location")):
            return "medium"
        if "uuid" in lower:
            return "high"
        return "low"
