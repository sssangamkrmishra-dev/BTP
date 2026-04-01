"""
Image metadata sanitization handler.

Handles EXIF, IPTC, and XMP metadata in JPEG, PNG, TIFF, and BMP files.
Uses Pillow (PIL) for image parsing and piexif for EXIF manipulation.

When Pillow/piexif are not installed, the handler reports itself as
unavailable and the orchestrator skips image sanitization with a warning.
"""

import logging
import os
import shutil
from typing import Any, Dict, List, Set

from ..config import SanitizerConfig
from ..models import SanitizationChange, SanitizationMode
from ..rules.exif_rules import (
    EXIF_ALWAYS_PRESERVE,
    EXIF_SIZE_ANOMALY_THRESHOLD,
    get_exif_strip_set,
)
from .base_handler import BaseHandler

logger = logging.getLogger(__name__)

# ── Optional dependency imports ────────────────────────────────────────
# These are heavy libraries; the handler gracefully degrades without them.

_PIL_AVAILABLE = False
_PIEXIF_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS as PIL_EXIF_TAGS
    _PIL_AVAILABLE = True
except ImportError:
    PIL_EXIF_TAGS = {}

try:
    import piexif
    _PIEXIF_AVAILABLE = True
except ImportError:
    piexif = None  # type: ignore[assignment]


# ── PIEXIF IFD name mapping ───────────────────────────────────────────
# piexif organises EXIF data into IFD groups

_PIEXIF_IFD_NAMES = {
    "0th": "IFD0",
    "Exif": "Exif",
    "GPS": "GPS",
    "1st": "IFD1",
    "Interop": "Interop",
}


class ImageHandler(BaseHandler):
    """
    Sanitizer handler for image files (JPEG, PNG, TIFF, BMP).

    Capabilities:
        - Extract EXIF/IPTC/XMP metadata
        - Strip dangerous tags (GPS, MakerNote, UserComment, etc.)
        - Detect oversized metadata fields (potential payload carriers)
        - Verify image integrity after sanitization
    """

    def __init__(self, config: SanitizerConfig):
        super().__init__(config)

    @classmethod
    def is_available(cls) -> bool:
        return _PIL_AVAILABLE

    def supported_mimes(self) -> Set[str]:
        return {"image/jpeg", "image/png", "image/tiff", "image/bmp"}

    # ── Core interface ─────────────────────────────────────────────────

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF metadata from an image file using Pillow."""
        if not _PIL_AVAILABLE:
            return {"_error": "Pillow not installed"}

        metadata: Dict[str, Any] = {}
        try:
            with Image.open(file_path) as img:
                # Basic image info (always available)
                metadata["_format"] = img.format or "unknown"
                metadata["_size"] = list(img.size)
                metadata["_mode"] = img.mode

                # EXIF data
                exif_data = img.getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = PIL_EXIF_TAGS.get(tag_id, f"Tag_{tag_id}")
                        # Convert bytes to hex preview for serialization
                        if isinstance(value, bytes):
                            metadata[tag_name] = f"[bytes:{len(value)}]"
                        else:
                            metadata[tag_name] = value

                # Info dict (PNG text chunks, etc.)
                if hasattr(img, "info") and img.info:
                    for key, value in img.info.items():
                        if key not in ("exif", "icc_profile") and isinstance(key, str):
                            meta_key = f"info.{key}"
                            if isinstance(value, bytes):
                                metadata[meta_key] = f"[bytes:{len(value)}]"
                            else:
                                metadata[meta_key] = value

        except Exception as e:
            metadata["_error"] = f"extraction_failed:{e}"
            self.logger.warning("Failed to extract metadata from %s: %s", file_path, e)

        return metadata

    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """
        Sanitize image metadata according to the given mode.

        Strategy:
            1. If piexif is available: surgically remove specific EXIF tags
            2. If only Pillow is available: strip all EXIF by re-saving without it
            3. In audit_only mode: report findings without modifying
        """
        changes: List[SanitizationChange] = []

        if mode == SanitizationMode.AUDIT_ONLY:
            return self._audit_only(file_path, changes)

        if not _PIL_AVAILABLE:
            changes.append(self.make_change(
                "_handler", "flagged",
                "pillow_not_installed:cannot_sanitize_image", "high"
            ))
            # Copy file unchanged
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            return changes

        if _PIEXIF_AVAILABLE:
            return self._sanitize_with_piexif(file_path, output_path, mode, changes)
        else:
            return self._sanitize_with_pillow_only(file_path, output_path, mode, changes)

    def verify(self, file_path: str) -> bool:
        """Verify the sanitized image can be opened and read."""
        if not _PIL_AVAILABLE:
            return True  # Cannot verify without Pillow; assume OK

        try:
            with Image.open(file_path) as img:
                img.verify()
            # verify() may not catch all issues; re-open and load pixels
            with Image.open(file_path) as img:
                img.load()
            return True
        except Exception as e:
            self.logger.error("Image verification failed for %s: %s", file_path, e)
            return False

    # ── Private methods ────────────────────────────────────────────────

    def _audit_only(
        self, file_path: str, changes: List[SanitizationChange]
    ) -> List[SanitizationChange]:
        """Audit mode: extract and flag metadata without modifying."""
        metadata = self.extract_metadata(file_path)
        strip_set = get_exif_strip_set("selective", self.config.preserve_gps)

        for field_name, value in metadata.items():
            if field_name.startswith("_"):
                continue

            if field_name in strip_set:
                changes.append(self.make_change(
                    f"EXIF.{field_name}", "flagged",
                    "would_be_stripped_in_selective_mode", "medium",
                    original_value=value,
                ))

            # Check for oversized fields
            anomaly = self.check_field_size_anomaly(
                f"EXIF.{field_name}", value, EXIF_SIZE_ANOMALY_THRESHOLD
            )
            if anomaly:
                changes.append(anomaly)

        return changes

    def _sanitize_with_piexif(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
        changes: List[SanitizationChange],
    ) -> List[SanitizationChange]:
        """Precise EXIF tag removal using piexif."""
        try:
            exif_dict = piexif.load(file_path)
        except Exception as e:
            self.logger.warning("piexif.load failed for %s: %s", file_path, e)
            return self._sanitize_with_pillow_only(file_path, output_path, mode, changes)

        strip_set = get_exif_strip_set(mode.value, self.config.preserve_gps)

        # Build a reverse lookup: tag_name → (ifd_key, tag_id)
        tag_lookup = self._build_piexif_tag_lookup()

        stripped_any = False
        for tag_name in strip_set:
            matches = tag_lookup.get(tag_name, [])
            for ifd_key, tag_id in matches:
                if ifd_key in exif_dict and tag_id in exif_dict[ifd_key]:
                    original = exif_dict[ifd_key][tag_id]
                    del exif_dict[ifd_key][tag_id]
                    stripped_any = True
                    changes.append(self.make_change(
                        f"EXIF.{tag_name}",
                        "removed",
                        self._reason_for_tag(tag_name),
                        self._severity_for_tag(tag_name),
                        original_value=original,
                    ))

        # Check for oversized remaining fields
        for ifd_key in ("0th", "Exif", "GPS", "1st", "Interop"):
            ifd = exif_dict.get(ifd_key, {})
            if not isinstance(ifd, dict):
                continue
            for tag_id, value in list(ifd.items()):
                anomaly = self.check_field_size_anomaly(
                    f"EXIF.{ifd_key}.{tag_id}", value, EXIF_SIZE_ANOMALY_THRESHOLD
                )
                if anomaly:
                    changes.append(anomaly)
                    # In strip mode, remove oversized fields
                    if mode == SanitizationMode.STRIP:
                        del ifd[tag_id]
                        stripped_any = True

        # Write sanitized file
        try:
            exif_bytes = piexif.dump(exif_dict)
            if file_path.lower().endswith((".jpg", ".jpeg")):
                piexif.insert(exif_bytes, file_path, output_path)
            else:
                # For non-JPEG, fall back to Pillow re-save
                with Image.open(file_path) as img:
                    img.save(output_path, exif=exif_bytes)
        except Exception as e:
            self.logger.warning("piexif write failed, falling back to Pillow: %s", e)
            return self._sanitize_with_pillow_only(file_path, output_path, mode, changes)

        return changes

    def _sanitize_with_pillow_only(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
        changes: List[SanitizationChange],
    ) -> List[SanitizationChange]:
        """
        Fallback: strip ALL EXIF by re-saving without metadata.
        Less precise than piexif but works for any Pillow-supported format.
        """
        try:
            with Image.open(file_path) as img:
                # Preserve essential rendering data
                icc = img.info.get("icc_profile")
                clean = img.copy()

                save_kwargs: Dict[str, Any] = {}
                if icc:
                    save_kwargs["icc_profile"] = icc

                fmt = img.format or "JPEG"
                if fmt.upper() == "JPEG":
                    save_kwargs["quality"] = 95
                    save_kwargs["optimize"] = True

                clean.save(output_path, format=fmt, **save_kwargs)

            changes.append(self.make_change(
                "EXIF.*", "removed",
                "all_exif_stripped_pillow_fallback", "medium",
            ))

        except Exception as e:
            self.logger.error("Pillow sanitization failed for %s: %s", file_path, e)
            # Copy original unchanged as safe fallback
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            changes.append(self.make_change(
                "_handler", "flagged",
                f"sanitization_failed:{e}", "critical",
            ))

        return changes

    @staticmethod
    def _build_piexif_tag_lookup() -> Dict[str, List]:
        """Build name → [(ifd, tag_id)] lookup from piexif's tag tables."""
        if not _PIEXIF_AVAILABLE:
            return {}

        lookup: Dict[str, List] = {}
        ifd_tables = {
            "0th": piexif.ImageIFD.__dict__,
            "Exif": piexif.ExifIFD.__dict__,
            "GPS": piexif.GPSIFD.__dict__,
            "1st": piexif.ImageIFD.__dict__,
        }
        for ifd_key, table in ifd_tables.items():
            for attr_name, tag_id in table.items():
                if attr_name.startswith("_") or not isinstance(tag_id, int):
                    continue
                lookup.setdefault(attr_name, []).append((ifd_key, tag_id))

        return lookup

    @staticmethod
    def _reason_for_tag(tag_name: str) -> str:
        """Return a human-readable reason for stripping a tag."""
        if tag_name.startswith("GPS"):
            return "gps_data_policy"
        if "MakerNote" in tag_name:
            return "arbitrary_vendor_data"
        if tag_name in ("UserComment", "ImageDescription", "XPComment"):
            return "potential_script_injection"
        if tag_name in ("Software", "HostComputer", "ProcessingSoftware"):
            return "pipeline_fingerprinting"
        if "Serial" in tag_name or "Owner" in tag_name:
            return "device_identification"
        if tag_name.startswith("JPEG"):
            return "embedded_thumbnail_mismatch_risk"
        return "metadata_policy"

    @staticmethod
    def _severity_for_tag(tag_name: str) -> str:
        """Return severity level for stripping a specific tag."""
        if "MakerNote" in tag_name:
            return "high"
        if tag_name.startswith("GPS"):
            return "medium"
        if tag_name in ("UserComment", "ImageDescription"):
            return "medium"
        return "low"
