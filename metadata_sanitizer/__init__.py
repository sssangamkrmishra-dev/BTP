"""
Metadata Sanitizer Package
===========================

Dedicated security module for inspecting and cleaning embedded metadata
within drone/RPA payload files. Removes potentially harmful fields from
EXIF data in images, JavaScript in PDFs, tracking tags in video, and
malformed metadata entries that could serve as covert channels or
malware delivery vectors.

Pipeline Position:
    Ingestion Interceptor → Game-Theoretic Threat Estimator
        → Malware Detection Engine → **Metadata Sanitizer**
        → Threat Intelligence Correlator → Response Manager

Main entry points:
    - MetadataSanitizer: Class-based API with full configuration
    - sanitize_file():   Functional API for single-file sanitization

Usage:
    from metadata_sanitizer import MetadataSanitizer, SanitizerConfig

    config = SanitizerConfig(default_mode="selective")
    sanitizer = MetadataSanitizer(config)

    # From artifact record (integration with Ingestion Interceptor)
    result = sanitizer.sanitize_artifact_record(
        artifact_record=artifact.to_dict(),
        storage_base_path="/data/drone_store",
        threat_score=0.45,
    )

    # Direct file sanitization
    result = sanitizer.sanitize_file(
        artifact_id="artifact://abc123",
        file_path="/path/to/image.jpg",
        mime_type="image/jpeg",
        threat_score=0.45,
    )
"""

from .config import SanitizerConfig
from .models import (
    BatchSanitizationResult,
    ChangeAction,
    MetadataSnapshot,
    SanitizationChange,
    SanitizationMode,
    SanitizationResult,
    Severity,
)
from .sanitizer import MetadataSanitizer
from .handlers import (
    BaseHandler,
    ImageHandler,
    PdfHandler,
    VideoHandler,
    ArchiveHandler,
    TextHandler,
    get_handler_for_mime,
)

__all__ = [
    # Core
    "MetadataSanitizer",
    "SanitizerConfig",
    # Models
    "SanitizationResult",
    "BatchSanitizationResult",
    "SanitizationChange",
    "SanitizationMode",
    "MetadataSnapshot",
    "ChangeAction",
    "Severity",
    # Handlers
    "BaseHandler",
    "ImageHandler",
    "PdfHandler",
    "VideoHandler",
    "ArchiveHandler",
    "TextHandler",
    "get_handler_for_mime",
]
