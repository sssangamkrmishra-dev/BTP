"""
Security heuristic analysis for individual payloads.
Flags suspicious attributes that feed into the threat estimation pipeline.
"""

from typing import Any, Dict, List

from .config import InterceptorConfig
from .models import PayloadEntry


# Severity levels for flags
FLAG_SEVERITY = {
    "encrypted_payload": "medium",
    "nested_archive": "medium",
    "large_binary": "low",
    "suspicious_mime": "high",
    "executable_file": "critical",
    "double_extension": "high",
    "hidden_file": "medium",
    "zero_size_file": "medium",
    "mime_extension_mismatch": "medium",
}

# Known MIME-to-extension mappings for mismatch detection
MIME_EXTENSION_MAP = {
    "image/jpeg": {"jpg", "jpeg"},
    "image/png": {"png"},
    "image/tiff": {"tif", "tiff"},
    "video/mp4": {"mp4"},
    "video/x-matroska": {"mkv"},
    "application/json": {"json"},
    "text/plain": {"txt", "log", "csv"},
    "application/zip": {"zip"},
    "application/gzip": {"gz", "gzip"},
}


def analyze_payload(payload: PayloadEntry, config: InterceptorConfig) -> List[str]:
    """
    Analyze a single payload for security flags.

    Checks:
    1. Encrypted content
    2. Nested archive / container
    3. Large binary (over threshold)
    4. Suspicious MIME type
    5. Executable file extension
    6. Double extension (e.g., photo.jpg.exe)
    7. Hidden file (starts with .)
    8. Zero-size file
    9. MIME-extension mismatch
    """
    flags: List[str] = []

    # 1. Encrypted payload
    if payload.encryption:
        flags.append("encrypted_payload")

    # 2. Nested archive
    if payload.container:
        flags.append("nested_archive")

    # 3. Large binary
    if isinstance(payload.size_bytes, int) and payload.size_bytes >= config.large_binary_threshold:
        flags.append("large_binary")

    # 4. Suspicious MIME type
    mime_lower = (payload.mime or "").lower()
    if mime_lower in config.suspicious_mime_types:
        flags.append("suspicious_mime")

    # 5. Executable file extension
    fname = payload.filename or ""
    if "." in fname:
        ext = fname.rsplit(".", 1)[1].lower()
        if ext in config.suspicious_extensions:
            flags.append("executable_file")

    # 6. Double extension detection (e.g., "report.pdf.exe")
    if fname.count(".") >= 2:
        parts = fname.rsplit(".", 2)
        if len(parts) == 3:
            inner_ext = parts[1].lower()
            outer_ext = parts[2].lower()
            if outer_ext in config.suspicious_extensions:
                flags.append("double_extension")

    # 7. Hidden file (Unix convention)
    basename = fname.split("/")[-1].split("\\")[-1]
    if basename.startswith(".") and len(basename) > 1:
        flags.append("hidden_file")

    # 8. Zero-size file (suspicious for videos/images)
    if payload.size_bytes == 0 and payload.type in ("video", "image", "archive"):
        flags.append("zero_size_file")

    # 9. MIME-extension mismatch
    if mime_lower in MIME_EXTENSION_MAP and "." in fname:
        ext = fname.rsplit(".", 1)[1].lower()
        expected_exts = MIME_EXTENSION_MAP[mime_lower]
        if ext not in expected_exts:
            flags.append("mime_extension_mismatch")

    return flags


def compute_payload_risk_score(flags: List[str]) -> float:
    """
    Compute a normalized risk score (0.0 - 1.0) from security flags.
    Used for quick triage before game-theoretic analysis.
    """
    severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    if not flags:
        return 0.0
    total = sum(severity_weights.get(FLAG_SEVERITY.get(f, "low"), 0.1) for f in flags)
    return min(1.0, total / 3.0)  # Normalize: 3.0 weight = max risk


def generate_threat_notes(flags: List[str], auth_status: str) -> str:
    """Generate human-readable threat notes from flags and auth status."""
    if not flags and auth_status in ("authenticated",):
        return "normal feed"

    notes_parts = []

    if auth_status in ("unknown", "untrusted"):
        notes_parts.append(f"device {auth_status}")

    critical_flags = [f for f in flags if FLAG_SEVERITY.get(f) == "critical"]
    high_flags = [f for f in flags if FLAG_SEVERITY.get(f) == "high"]
    medium_flags = [f for f in flags if FLAG_SEVERITY.get(f) == "medium"]

    if critical_flags:
        notes_parts.append(f"CRITICAL: {', '.join(critical_flags)}")
    if high_flags:
        notes_parts.append(f"high-risk: {', '.join(high_flags)}")
    if "encrypted_payload" in flags or "nested_archive" in flags:
        notes_parts.append("defer analysis: encrypted or nested contents")
    if "large_binary" in flags and "encrypted_payload" not in flags:
        notes_parts.append("large binary - consider selective sampling")

    return "; ".join(notes_parts) if notes_parts else "normal feed"
