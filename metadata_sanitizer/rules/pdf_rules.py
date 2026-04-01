"""
PDF sanitization rules.

Defines dangerous PDF dictionary keys, JavaScript patterns, and
auto-action triggers that must be removed or neutralized.

References:
    - PDF 2.0 specification (ISO 32000-2:2020)
    - Adobe JavaScript for Acrobat API Reference
    - Common PDF exploit techniques (CVE database)
"""

from typing import Dict, Set


# ════════════════════════════════════════════════════════════════════════
# ALWAYS STRIP KEYS — removed from the PDF catalog / page tree
# ════════════════════════════════════════════════════════════════════════
# These keys enable code execution, data exfiltration, or auto-actions
# that can trigger without user interaction.

PDF_ALWAYS_STRIP_KEYS: Set[str] = {
    # ── JavaScript execution ──────────────────────────────────────────
    "/JavaScript",          # Document-level JavaScript
    "/JS",                  # Inline JavaScript action
    "/RichMedia",           # Embedded Flash / rich media

    # ── Auto-actions (fire without user interaction) ──────────────────
    "/OpenAction",          # Action on document open
    "/AA",                  # Additional actions (page-level triggers)
    "/Launch",              # Launch external application
    "/URI",                 # Auto-navigate to URI (phishing / beacon)
    "/SubmitForm",          # Auto-submit form data to remote server
    "/ImportData",          # Auto-import external data
    "/GoTo",                # Navigate within document (can chain exploits)
    "/GoToR",               # Open remote PDF
    "/GoToE",               # Open embedded file
    "/GoTo3DView",          # 3D JavaScript execution context

    # ── Form manipulation ─────────────────────────────────────────────
    "/AcroForm",            # Interactive form (can contain JS)
    "/XFA",                 # XML Forms Architecture (complex attack surface)

    # ── Embedded content ──────────────────────────────────────────────
    "/EmbeddedFiles",       # Embedded file attachments
    "/Names",               # Name tree (can reference JS, embedded files)
    "/OPI",                 # Open Prepress Interface (external references)

    # ── Encryption / DRM that may hide content ────────────────────────
    "/Encrypt",             # Document encryption dictionary
}


# ════════════════════════════════════════════════════════════════════════
# DANGEROUS ACTION TYPES — PDF action dictionaries to neutralize
# ════════════════════════════════════════════════════════════════════════
# These are /Type /Action entries whose /S (subtype) indicates danger.

PDF_DANGEROUS_ACTIONS: Set[str] = {
    "/JavaScript",          # S=JavaScript: execute JS
    "/Launch",              # S=Launch: run external program
    "/URI",                 # S=URI: open URL
    "/SubmitForm",          # S=SubmitForm: send data to server
    "/ImportData",          # S=ImportData: load external data
    "/Rendition",           # S=Rendition: media playback (Flash)
    "/Sound",               # S=Sound: can trigger audio exploits
    "/Movie",               # S=Movie: embedded media playback
    "/RichMediaExecute",    # S=RichMediaExecute: Flash/3D execution
    "/GoToR",               # S=GoToR: open remote document
    "/GoToE",               # S=GoToE: open embedded document
    "/Named",               # S=Named: execute named action
    "/SetOCGState",         # S=SetOCGState: modify layer visibility
    "/Trans",               # S=Trans: transition (can be chained)
}


# ════════════════════════════════════════════════════════════════════════
# SUSPICIOUS PATTERNS — regex patterns to detect in PDF streams
# ════════════════════════════════════════════════════════════════════════
# These patterns may appear in decoded PDF streams and indicate
# obfuscated code execution or exploit payloads.

PDF_SUSPICIOUS_PATTERNS: Dict[str, str] = {
    "js_eval": r"eval\s*\(",
    "js_function": r"function\s+\w+\s*\(",
    "js_app_alert": r"app\.(alert|launchURL|exec|openDoc)",
    "js_this_getfield": r"this\.(getField|submitForm|getURL|exportDataObject)",
    "shellcode_nop_sled": r"(%u9090|\\x90\\x90|\x90{4,})",
    "heap_spray": r"(unescape|String\.fromCharCode)\s*\(",
    "obfuscated_hex": r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",
    "base64_payload": r"atob\s*\(",
    "embedded_exe": r"(MZ|TVqQ)",  # PE header magic bytes in stream
    "powershell": r"(powershell|cmd\.exe|/bin/sh)",
}


# ════════════════════════════════════════════════════════════════════════
# PRESERVE KEYS — PDF metadata fields that should be kept
# ════════════════════════════════════════════════════════════════════════

PDF_PRESERVE_KEYS: Set[str] = {
    "/Title",               # Document title (if non-executable)
    "/Author",              # Author name (stripped in strip mode)
    "/CreationDate",        # When the document was created
    "/ModDate",             # Last modification date
    "/Producer",            # PDF producer software
    "/Creator",             # Original application
    "/Pages",               # Page tree (structural)
    "/Type",                # Object type (structural)
    "/MediaBox",            # Page dimensions
    "/CropBox",             # Visible area
    "/Resources",           # Font/image resources
    "/Contents",            # Page content streams
    "/Count",               # Page count
}


# ════════════════════════════════════════════════════════════════════════
# STRIP IN HIGH SECURITY — additional fields removed in "strip" mode
# ════════════════════════════════════════════════════════════════════════

PDF_STRIP_IN_HIGH_SECURITY: Set[str] = {
    "/Author",
    "/Producer",
    "/Creator",
    "/Subject",
    "/Keywords",
    "/CreationDate",
    "/ModDate",
    "/Metadata",            # XMP metadata stream
    "/MarkInfo",            # Accessibility markup
    "/StructTreeRoot",      # Document structure tree
    "/Outlines",            # Bookmarks / table of contents
    "/Annots",              # Annotations (can contain actions)
}
