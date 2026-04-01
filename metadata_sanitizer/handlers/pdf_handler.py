"""
PDF metadata sanitization handler.

Handles document properties, JavaScript, auto-actions, and embedded
objects in PDF files. Uses pikepdf for PDF manipulation when available.

When pikepdf is not installed, the handler reports itself as unavailable.
"""

import logging
import re
import shutil
from typing import Any, Dict, List, Set

from ..config import SanitizerConfig
from ..models import SanitizationChange, SanitizationMode
from ..rules.pdf_rules import (
    PDF_ALWAYS_STRIP_KEYS,
    PDF_DANGEROUS_ACTIONS,
    PDF_PRESERVE_KEYS,
    PDF_STRIP_IN_HIGH_SECURITY,
    PDF_SUSPICIOUS_PATTERNS,
)
from .base_handler import BaseHandler

logger = logging.getLogger(__name__)

# ── Optional dependency ────────────────────────────────────────────────

_PIKEPDF_AVAILABLE = False

try:
    import pikepdf
    _PIKEPDF_AVAILABLE = True
except ImportError:
    pikepdf = None  # type: ignore[assignment]


class PdfHandler(BaseHandler):
    """
    Sanitizer handler for PDF documents.

    Capabilities:
        - Extract document metadata and catalog entries
        - Remove JavaScript, auto-actions, launch commands
        - Strip embedded files and form actions
        - Detect suspicious patterns in decoded streams
        - Verify PDF integrity after sanitization
    """

    def __init__(self, config: SanitizerConfig):
        super().__init__(config)

    @classmethod
    def is_available(cls) -> bool:
        return _PIKEPDF_AVAILABLE

    def supported_mimes(self) -> Set[str]:
        return {"application/pdf"}

    # ── Core interface ─────────────────────────────────────────────────

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract PDF metadata and catalog information."""
        if not _PIKEPDF_AVAILABLE:
            return {"_error": "pikepdf not installed"}

        metadata: Dict[str, Any] = {}
        try:
            with pikepdf.open(file_path) as pdf:
                # Document info
                if pdf.docinfo:
                    for key in pdf.docinfo.keys():
                        value = pdf.docinfo[key]
                        metadata[f"DocInfo.{key}"] = str(value)[:500]

                # Page count
                metadata["_page_count"] = len(pdf.pages)

                # Catalog keys (detect dangerous entries)
                root = pdf.Root
                if root:
                    for key in root.keys():
                        key_str = str(key)
                        if key_str in PDF_ALWAYS_STRIP_KEYS:
                            metadata[f"Catalog.{key_str}"] = "[DANGEROUS_KEY_PRESENT]"
                        elif key_str in PDF_PRESERVE_KEYS:
                            metadata[f"Catalog.{key_str}"] = "[structural]"
                        else:
                            metadata[f"Catalog.{key_str}"] = "[present]"

                # Check for encrypted content
                if pdf.is_encrypted:
                    metadata["_encrypted"] = True

        except Exception as e:
            metadata["_error"] = f"extraction_failed:{e}"
            self.logger.warning("Failed to extract PDF metadata from %s: %s", file_path, e)

        return metadata

    def sanitize(
        self,
        file_path: str,
        output_path: str,
        mode: SanitizationMode,
    ) -> List[SanitizationChange]:
        """Sanitize PDF metadata and dangerous structures."""
        changes: List[SanitizationChange] = []

        if mode == SanitizationMode.AUDIT_ONLY:
            return self._audit_only(file_path, changes)

        if not _PIKEPDF_AVAILABLE:
            changes.append(self.make_change(
                "_handler", "flagged",
                "pikepdf_not_installed:cannot_sanitize_pdf", "high"
            ))
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            return changes

        try:
            with pikepdf.open(file_path, allow_overwriting_input=True) as pdf:
                # 1. Strip dangerous catalog keys
                changes.extend(self._strip_catalog_keys(pdf, mode))

                # 2. Strip dangerous actions from pages
                changes.extend(self._strip_page_actions(pdf, mode))

                # 3. Clean document info
                changes.extend(self._clean_docinfo(pdf, mode))

                # 4. Scan streams for suspicious patterns
                changes.extend(self._scan_streams(pdf))

                # Save sanitized PDF
                pdf.save(output_path)

        except Exception as e:
            self.logger.error("PDF sanitization failed for %s: %s", file_path, e)
            if file_path != output_path:
                shutil.copy2(file_path, output_path)
            changes.append(self.make_change(
                "_handler", "flagged",
                f"sanitization_failed:{e}", "critical"
            ))

        return changes

    def verify(self, file_path: str) -> bool:
        """Verify the PDF can be opened and pages accessed."""
        if not _PIKEPDF_AVAILABLE:
            return True

        try:
            with pikepdf.open(file_path) as pdf:
                _ = len(pdf.pages)
                # Try to access first page
                if len(pdf.pages) > 0:
                    _ = pdf.pages[0]
            return True
        except Exception as e:
            self.logger.error("PDF verification failed for %s: %s", file_path, e)
            return False

    # ── Private methods ────────────────────────────────────────────────

    def _audit_only(
        self, file_path: str, changes: List[SanitizationChange]
    ) -> List[SanitizationChange]:
        """Audit mode: flag dangerous entries without modifying."""
        metadata = self.extract_metadata(file_path)

        for field_name, value in metadata.items():
            if field_name.startswith("_"):
                continue
            # Check if the key would be stripped
            raw_key = field_name.split(".")[-1] if "." in field_name else field_name
            if raw_key in PDF_ALWAYS_STRIP_KEYS:
                changes.append(self.make_change(
                    f"PDF.{field_name}", "flagged",
                    "dangerous_key_present", "critical" if raw_key in ("/JavaScript", "/JS") else "high",
                    original_value=value,
                ))

        return changes

    def _strip_catalog_keys(
        self, pdf: Any, mode: SanitizationMode
    ) -> List[SanitizationChange]:
        """Remove dangerous keys from the PDF catalog (root object)."""
        changes: List[SanitizationChange] = []
        root = pdf.Root
        if not root:
            return changes

        strip_keys = set(PDF_ALWAYS_STRIP_KEYS)
        if mode == SanitizationMode.STRIP:
            strip_keys |= PDF_STRIP_IN_HIGH_SECURITY

        for key in list(root.keys()):
            key_str = str(key)
            if key_str in strip_keys:
                severity = "critical" if key_str in ("/JavaScript", "/JS", "/OpenAction") else "high"
                changes.append(self.make_change(
                    f"PDF.Catalog.{key_str}", "removed",
                    self._reason_for_key(key_str), severity,
                ))
                del root[key]

        return changes

    def _strip_page_actions(
        self, pdf: Any, mode: SanitizationMode
    ) -> List[SanitizationChange]:
        """Remove dangerous actions from individual pages."""
        changes: List[SanitizationChange] = []

        for page_num, page in enumerate(pdf.pages):
            # Page-level additional actions
            if "/AA" in page:
                changes.append(self.make_change(
                    f"PDF.Page[{page_num}]./AA", "removed",
                    "page_auto_action", "high",
                ))
                del page["/AA"]

            # Annotations with actions
            if "/Annots" in page:
                annots = page["/Annots"]
                try:
                    for i, annot in enumerate(annots):
                        annot_obj = annot if not hasattr(annot, 'resolve') else annot
                        if "/A" in annot_obj:
                            action = annot_obj["/A"]
                            action_type = str(action.get("/S", ""))
                            if action_type in PDF_DANGEROUS_ACTIONS:
                                changes.append(self.make_change(
                                    f"PDF.Page[{page_num}].Annot[{i}]./A",
                                    "removed",
                                    f"dangerous_annotation_action:{action_type}",
                                    "high",
                                ))
                                del annot_obj["/A"]
                except (TypeError, AttributeError):
                    pass  # Some annotation structures may not be iterable

        return changes

    def _clean_docinfo(
        self, pdf: Any, mode: SanitizationMode
    ) -> List[SanitizationChange]:
        """Clean document info dictionary."""
        changes: List[SanitizationChange] = []

        if not pdf.docinfo:
            return changes

        if mode == SanitizationMode.STRIP:
            # In strip mode, remove all docinfo
            for key in list(pdf.docinfo.keys()):
                changes.append(self.make_change(
                    f"PDF.DocInfo.{key}", "removed",
                    "strip_mode_docinfo", "low",
                    original_value=str(pdf.docinfo[key])[:200],
                ))
            pdf.docinfo.clear()

        return changes

    def _scan_streams(self, pdf: Any) -> List[SanitizationChange]:
        """Scan decoded PDF streams for suspicious patterns."""
        changes: List[SanitizationChange] = []

        # Only scan first 50 objects to bound processing time
        scanned = 0
        try:
            for obj in pdf.objects:
                if scanned >= 50:
                    break
                try:
                    if hasattr(obj, 'read_bytes'):
                        data = obj.read_bytes()
                        if len(data) > 0:
                            decoded = data.decode("latin-1", errors="replace")
                            for pattern_name, pattern in PDF_SUSPICIOUS_PATTERNS.items():
                                if re.search(pattern, decoded):
                                    changes.append(self.make_change(
                                        f"PDF.Stream.{pattern_name}", "flagged",
                                        f"suspicious_pattern_detected:{pattern_name}",
                                        "critical",
                                    ))
                                    break  # One finding per stream is enough
                            scanned += 1
                except Exception:
                    continue
        except Exception:
            pass  # Not all PDFs support object iteration

        return changes

    @staticmethod
    def _reason_for_key(key: str) -> str:
        """Return reason string for stripping a PDF key."""
        if key in ("/JavaScript", "/JS"):
            return "javascript_execution"
        if key in ("/OpenAction", "/AA"):
            return "auto_action_trigger"
        if key in ("/Launch",):
            return "external_application_launch"
        if key in ("/SubmitForm", "/ImportData"):
            return "data_exfiltration_risk"
        if key in ("/URI", "/GoToR", "/GoToE"):
            return "external_navigation"
        if key in ("/EmbeddedFiles", "/Names"):
            return "embedded_content"
        if key in ("/AcroForm", "/XFA"):
            return "form_scripting_risk"
        return "dangerous_pdf_key"
