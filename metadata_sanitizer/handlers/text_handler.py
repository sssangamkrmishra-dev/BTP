"""
Text/telemetry file sanitization handler.

Handles plain text, CSV, and JSON files. Uses Python stdlib only.
Focuses on encoding normalization, embedded script detection, and
JSON schema validation for telemetry files.
"""

import json
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Set

from ..config import SanitizerConfig
from ..models import SanitizationChange, SanitizationMode
from .base_handler import BaseHandler

logger = logging.getLogger(__name__)

# Patterns indicating embedded scripts or commands
_SCRIPT_PATTERNS = {
    "html_script": re.compile(r"<script[\s>]", re.IGNORECASE),
    "shell_shebang": re.compile(r"^#!\s*/(?:bin|usr)", re.MULTILINE),
    "powershell_cmd": re.compile(r"(?:powershell|cmd\.exe|/bin/(?:sh|bash))", re.IGNORECASE),
    "eval_exec": re.compile(r"\b(?:eval|exec|system|subprocess|os\.(?:system|popen))\s*\("),
    "sql_injection": re.compile(
        r"(?:DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|UNION\s+SELECT)",
        re.IGNORECASE,
    ),
    "xml_entity": re.compile(r"<!ENTITY\s+", re.IGNORECASE),
    "base64_block": re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"),
}

# Maximum file size we'll fully read into memory for text inspection
_MAX_TEXT_READ_BYTES = 10_000_000  # 10 MB


class TextHandler(BaseHandler):
    """
    Sanitizer handler for text and telemetry files.

    Capabilities:
        - Detect embedded scripts in plain text
        - Normalize character encoding to UTF-8
        - Normalize line endings (CRLF → LF)
        - Validate JSON structure for telemetry files
        - Strip null bytes and control characters
    """

    def __init__(self, config: SanitizerConfig):
        super().__init__(config)

    @classmethod
    def is_available(cls) -> bool:
        return True  # stdlib only

    def supported_mimes(self) -> Set[str]:
        return {"text/plain", "text/csv", "application/json"}

    # ── Core interface ─────────────────────────────────────────────────

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract text file metadata: encoding, size, line count, patterns."""
        metadata: Dict[str, Any] = {}

        try:
            file_size = os.path.getsize(file_path)
            metadata["_size_bytes"] = file_size

            if file_size > _MAX_TEXT_READ_BYTES:
                metadata["_warning"] = "file_too_large_for_full_inspection"
                return metadata

            # Detect encoding by trying UTF-8 first, then latin-1
            raw = b""
            with open(file_path, "rb") as f:
                raw = f.read()

            encoding = "utf-8"
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                encoding = "latin-1"

            metadata["_encoding"] = encoding
            metadata["_byte_size"] = len(raw)
            metadata["_has_bom"] = raw.startswith(b"\xef\xbb\xbf")
            metadata["_has_null_bytes"] = b"\x00" in raw
            metadata["_line_ending"] = (
                "crlf" if b"\r\n" in raw else "cr" if b"\r" in raw else "lf"
            )

            text = raw.decode(encoding, errors="replace")
            metadata["_line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)

            # Check if valid JSON
            if file_path.lower().endswith(".json"):
                try:
                    json.loads(text)
                    metadata["_valid_json"] = True
                except json.JSONDecodeError as je:
                    metadata["_valid_json"] = False
                    metadata["_json_error"] = str(je)[:200]

            # Detect script patterns
            patterns_found = []
            for name, pattern in _SCRIPT_PATTERNS.items():
                if pattern.search(text):
                    patterns_found.append(name)
            if patterns_found:
                metadata["_script_patterns"] = patterns_found

        except Exception as e:
            metadata["_error"] = f"extraction_failed:{e}"

        return metadata

    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """Sanitize text file content."""
        changes: List[SanitizationChange] = []

        if mode == SanitizationMode.AUDIT_ONLY:
            return self._audit_only(file_path, changes)

        try:
            file_size = os.path.getsize(file_path)
            if file_size > _MAX_TEXT_READ_BYTES:
                if file_path != output_path:
                    shutil.copy2(file_path, output_path)
                changes.append(self.make_change(
                    "Text._file", "flagged",
                    "file_too_large_for_sanitization", "medium",
                ))
                return changes

            with open(file_path, "rb") as f:
                raw = f.read()

            # Detect encoding
            encoding = "utf-8"
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                encoding = "latin-1"

            text = raw.decode(encoding, errors="replace")
            modified = False

            # 1. Strip BOM
            if text.startswith("\ufeff"):
                text = text[1:]
                changes.append(self.make_change(
                    "Text.BOM", "removed", "bom_stripped", "info"
                ))
                modified = True

            # 2. Strip null bytes
            if "\x00" in text:
                null_count = text.count("\x00")
                text = text.replace("\x00", "")
                changes.append(self.make_change(
                    "Text.null_bytes", "removed",
                    f"null_bytes_stripped:count={null_count}", "medium",
                ))
                modified = True

            # 3. Normalize line endings to LF
            if "\r\n" in text or "\r" in text:
                text = text.replace("\r\n", "\n").replace("\r", "\n")
                changes.append(self.make_change(
                    "Text.line_endings", "normalized",
                    "line_endings_normalized_to_lf", "info",
                ))
                modified = True

            # 4. Strip control characters (except newline, tab, carriage return)
            control_chars = set()
            clean_chars = []
            for ch in text:
                if ord(ch) < 32 and ch not in ("\n", "\t"):
                    control_chars.add(hex(ord(ch)))
                else:
                    clean_chars.append(ch)
            if control_chars:
                text = "".join(clean_chars)
                changes.append(self.make_change(
                    "Text.control_chars", "removed",
                    f"control_characters_stripped:{','.join(sorted(control_chars))}",
                    "medium",
                ))
                modified = True

            # 5. Detect and flag embedded scripts
            for name, pattern in _SCRIPT_PATTERNS.items():
                matches = pattern.findall(text)
                if matches:
                    severity = "critical" if name in ("html_script", "shell_shebang") else "high"
                    changes.append(self.make_change(
                        f"Text.pattern.{name}", "flagged",
                        f"suspicious_pattern_detected:{name}:count={len(matches)}",
                        severity,
                        original_value=matches[0] if matches else None,
                    ))

            # 6. In strip mode, remove lines matching script patterns
            if mode == SanitizationMode.STRIP:
                lines = text.split("\n")
                clean_lines = []
                removed_count = 0
                for line in lines:
                    is_suspicious = any(
                        p.search(line) for p in _SCRIPT_PATTERNS.values()
                    )
                    if is_suspicious:
                        removed_count += 1
                    else:
                        clean_lines.append(line)
                if removed_count > 0:
                    text = "\n".join(clean_lines)
                    changes.append(self.make_change(
                        "Text.suspicious_lines", "removed",
                        f"suspicious_lines_removed:count={removed_count}",
                        "high",
                    ))
                    modified = True

            # Write output
            if modified or file_path != output_path:
                with open(output_path, "w", encoding="utf-8", newline="") as f:
                    f.write(text)
            elif not modified and file_path == output_path:
                pass  # No changes needed

        except Exception as e:
            self.logger.error("Text sanitization failed for %s: %s", file_path, e)
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            changes.append(self.make_change(
                "_handler", "flagged",
                f"sanitization_failed:{e}", "critical",
            ))

        return changes

    def verify(self, file_path: str) -> bool:
        """Verify the text file can be read as valid UTF-8."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(1024)  # Read first 1KB to verify
            return True
        except Exception:
            return False

    # ── Private methods ────────────────────────────────────────────────

    def _audit_only(
        self, file_path: str, changes: List[SanitizationChange]
    ) -> List[SanitizationChange]:
        """Audit mode: flag issues without modifying."""
        metadata = self.extract_metadata(file_path)

        if metadata.get("_has_null_bytes"):
            changes.append(self.make_change(
                "Text.null_bytes", "flagged",
                "null_bytes_present", "medium",
            ))

        if metadata.get("_encoding") != "utf-8":
            changes.append(self.make_change(
                "Text.encoding", "flagged",
                f"non_utf8_encoding:{metadata.get('_encoding')}", "low",
            ))

        for pattern_name in metadata.get("_script_patterns", []):
            changes.append(self.make_change(
                f"Text.pattern.{pattern_name}", "flagged",
                f"suspicious_pattern_detected:{pattern_name}", "high",
            ))

        if metadata.get("_valid_json") is False:
            changes.append(self.make_change(
                "Text.json", "flagged",
                f"invalid_json:{metadata.get('_json_error', 'unknown')}", "medium",
            ))

        return changes
