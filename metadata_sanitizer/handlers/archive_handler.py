"""
Archive metadata sanitization handler.

Handles ZIP, TAR, and GZIP container metadata inspection.
Uses Python stdlib (zipfile, tarfile) — no external dependencies required.

Archives are NOT sanitized in the traditional sense. Instead, the handler
inspects archive-level metadata and file listings for suspicious entries.
Actual archive content analysis is delegated to the Malware Detection Engine.
"""

import logging
import os
import shutil
import tarfile
import zipfile
from typing import Any, Dict, List, Set

from ..config import SanitizerConfig
from ..models import SanitizationChange, SanitizationMode
from .base_handler import BaseHandler

logger = logging.getLogger(__name__)

# Suspicious patterns in archived filenames
_SUSPICIOUS_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "ps1", "sh", "vbs", "js",
    "msi", "scr", "com", "pif", "hta", "wsf",
}

_PATH_TRAVERSAL_PATTERNS = ("../", "..\\", "/etc/", "/tmp/", "C:\\")


class ArchiveHandler(BaseHandler):
    """
    Sanitizer handler for archive files (ZIP, TAR, GZIP).

    Unlike other handlers, archives are inspected but not modified.
    The handler reports findings about the archive structure and
    file listing for downstream decision-making.

    Capabilities:
        - Inspect archive file listings for suspicious entries
        - Detect path traversal attempts in archived filenames
        - Flag executables and double extensions within archives
        - Report archive-level metadata (comments, compression info)
    """

    def __init__(self, config: SanitizerConfig):
        super().__init__(config)

    @classmethod
    def is_available(cls) -> bool:
        return True  # Uses stdlib only

    def supported_mimes(self) -> Set[str]:
        return {
            "application/zip", "application/x-tar", "application/gzip",
            "application/x-7z-compressed", "application/x-rar-compressed",
        }

    # ── Core interface ─────────────────────────────────────────────────

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract archive-level metadata and file listing."""
        metadata: Dict[str, Any] = {}

        if zipfile.is_zipfile(file_path):
            metadata.update(self._extract_zip_metadata(file_path))
        elif tarfile.is_tarfile(file_path):
            metadata.update(self._extract_tar_metadata(file_path))
        else:
            metadata["_error"] = "unsupported_or_corrupt_archive"

        return metadata

    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """
        Inspect archive metadata and flag suspicious content.

        Archives are NOT modified (content sanitization is delegated to
        the Malware Detection Engine). The handler only reports findings.
        """
        changes: List[SanitizationChange] = []

        # Copy archive unchanged
        if file_path != output_path:
            shutil.copy2(file_path, output_path)

        metadata = self.extract_metadata(file_path)

        # Check archive comment
        comment = metadata.get("_comment")
        if comment and len(str(comment)) > 0:
            changes.append(self.make_change(
                "Archive.comment", "flagged",
                "archive_comment_present", "low",
                original_value=comment,
            ))

        # Inspect file listing
        entries = metadata.get("_entries", [])
        for entry in entries:
            filename = entry.get("name", "")

            # Path traversal
            if any(p in filename for p in _PATH_TRAVERSAL_PATTERNS):
                changes.append(self.make_change(
                    f"Archive.entry.{filename}", "flagged",
                    "path_traversal_in_archive", "critical",
                ))

            # Suspicious extensions
            if "." in filename:
                ext = filename.rsplit(".", 1)[-1].lower()
                if ext in _SUSPICIOUS_EXTENSIONS:
                    changes.append(self.make_change(
                        f"Archive.entry.{filename}", "flagged",
                        f"executable_in_archive:{ext}", "high",
                    ))

                # Double extension
                if filename.count(".") >= 2:
                    parts = filename.rsplit(".", 2)
                    if len(parts) == 3 and parts[2].lower() in _SUSPICIOUS_EXTENSIONS:
                        changes.append(self.make_change(
                            f"Archive.entry.{filename}", "flagged",
                            "double_extension_in_archive", "high",
                        ))

            # Hidden files
            basename = os.path.basename(filename)
            if basename.startswith(".") and len(basename) > 1:
                changes.append(self.make_change(
                    f"Archive.entry.{filename}", "flagged",
                    "hidden_file_in_archive", "medium",
                ))

            # Oversized entries
            size = entry.get("size", 0)
            if size > self.config.max_file_size_bytes:
                changes.append(self.make_change(
                    f"Archive.entry.{filename}", "flagged",
                    f"oversized_entry:{size}_bytes", "high",
                ))

        # Zip bomb detection: compression ratio
        total_compressed = metadata.get("_total_compressed", 0)
        total_uncompressed = metadata.get("_total_uncompressed", 0)
        if total_compressed > 0 and total_uncompressed > 0:
            ratio = total_uncompressed / total_compressed
            if ratio > 100:
                changes.append(self.make_change(
                    "Archive.compression_ratio", "flagged",
                    f"potential_zip_bomb:ratio_{ratio:.1f}", "critical",
                ))

        return changes

    def verify(self, file_path: str) -> bool:
        """Verify the archive is not corrupt."""
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zf:
                    result = zf.testzip()
                    return result is None
            elif tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, "r:*") as tf:
                    tf.getmembers()
                return True
        except Exception as e:
            self.logger.error("Archive verification failed for %s: %s", file_path, e)
            return False
        return True

    # ── Private methods ────────────────────────────────────────────────

    def _extract_zip_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from a ZIP archive."""
        metadata: Dict[str, Any] = {"_format": "zip"}
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                metadata["_comment"] = zf.comment.decode("utf-8", errors="replace") if zf.comment else ""
                entries = []
                total_compressed = 0
                total_uncompressed = 0
                for info in zf.infolist():
                    entries.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "is_dir": info.is_dir(),
                    })
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size
                metadata["_entries"] = entries
                metadata["_entry_count"] = len(entries)
                metadata["_total_compressed"] = total_compressed
                metadata["_total_uncompressed"] = total_uncompressed
        except Exception as e:
            metadata["_error"] = f"zip_read_failed:{e}"
        return metadata

    def _extract_tar_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from a TAR archive."""
        metadata: Dict[str, Any] = {"_format": "tar"}
        try:
            with tarfile.open(file_path, "r:*") as tf:
                entries = []
                total_size = 0
                for member in tf.getmembers():
                    entries.append({
                        "name": member.name,
                        "size": member.size,
                        "is_dir": member.isdir(),
                        "uid": member.uid,
                        "gid": member.gid,
                        "mode": oct(member.mode),
                    })
                    total_size += member.size
                metadata["_entries"] = entries
                metadata["_entry_count"] = len(entries)
                metadata["_total_uncompressed"] = total_size
                metadata["_total_compressed"] = os.path.getsize(file_path)
        except Exception as e:
            metadata["_error"] = f"tar_read_failed:{e}"
        return metadata
