"""
Sanitization rules for different file types.
Each rule module defines which metadata fields to strip, keep, or flag.
"""

from .exif_rules import (
    EXIF_ALWAYS_STRIP,
    EXIF_STRIP_IN_HIGH_SECURITY,
    EXIF_ALWAYS_PRESERVE,
    EXIF_SIZE_ANOMALY_THRESHOLD,
    get_exif_strip_set,
)
from .pdf_rules import (
    PDF_ALWAYS_STRIP_KEYS,
    PDF_DANGEROUS_ACTIONS,
    PDF_SUSPICIOUS_PATTERNS,
    PDF_PRESERVE_KEYS,
)
from .video_rules import (
    VIDEO_ALWAYS_STRIP_ATOMS,
    VIDEO_STRIP_IN_HIGH_SECURITY,
    VIDEO_ALWAYS_PRESERVE,
    VIDEO_SIZE_ANOMALY_THRESHOLD,
)

__all__ = [
    "EXIF_ALWAYS_STRIP",
    "EXIF_STRIP_IN_HIGH_SECURITY",
    "EXIF_ALWAYS_PRESERVE",
    "EXIF_SIZE_ANOMALY_THRESHOLD",
    "get_exif_strip_set",
    "PDF_ALWAYS_STRIP_KEYS",
    "PDF_DANGEROUS_ACTIONS",
    "PDF_SUSPICIOUS_PATTERNS",
    "PDF_PRESERVE_KEYS",
    "VIDEO_ALWAYS_STRIP_ATOMS",
    "VIDEO_STRIP_IN_HIGH_SECURITY",
    "VIDEO_ALWAYS_PRESERVE",
    "VIDEO_SIZE_ANOMALY_THRESHOLD",
]
