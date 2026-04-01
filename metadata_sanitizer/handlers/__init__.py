"""
File-type specific metadata sanitization handlers.

Each handler implements the BaseHandler interface and is responsible
for extracting, sanitizing, and verifying metadata for its supported
file types. Handlers gracefully degrade when optional dependencies
(Pillow, pikepdf, mutagen) are not installed.
"""

from .base_handler import BaseHandler
from .image_handler import ImageHandler
from .pdf_handler import PdfHandler
from .video_handler import VideoHandler
from .archive_handler import ArchiveHandler
from .text_handler import TextHandler

# Registry mapping MIME type prefixes/exact matches to handler classes.
# The sanitizer orchestrator uses this to route files to the right handler.
HANDLER_REGISTRY = {
    # Images
    "image/jpeg": ImageHandler,
    "image/png": ImageHandler,
    "image/tiff": ImageHandler,
    "image/bmp": ImageHandler,
    # Video / Audio
    "video/mp4": VideoHandler,
    "video/x-matroska": VideoHandler,
    "video/avi": VideoHandler,
    "video/x-msvideo": VideoHandler,
    "video/quicktime": VideoHandler,
    "video/webm": VideoHandler,
    "audio/mpeg": VideoHandler,
    "audio/mp4": VideoHandler,
    # PDF
    "application/pdf": PdfHandler,
    # Archives
    "application/zip": ArchiveHandler,
    "application/x-tar": ArchiveHandler,
    "application/gzip": ArchiveHandler,
    "application/x-7z-compressed": ArchiveHandler,
    "application/x-rar-compressed": ArchiveHandler,
    # Text / Telemetry
    "text/plain": TextHandler,
    "text/csv": TextHandler,
    "application/json": TextHandler,
}


def get_handler_for_mime(mime_type: str) -> type:
    """
    Look up the handler class for a given MIME type.

    Falls back to TextHandler for unrecognized types.
    """
    mime_lower = mime_type.lower().strip()

    # Exact match
    if mime_lower in HANDLER_REGISTRY:
        return HANDLER_REGISTRY[mime_lower]

    # Prefix match (e.g. "image/*" → ImageHandler)
    prefix = mime_lower.split("/")[0] if "/" in mime_lower else ""
    prefix_map = {
        "image": ImageHandler,
        "video": VideoHandler,
        "audio": VideoHandler,
    }
    if prefix in prefix_map:
        return prefix_map[prefix]

    return TextHandler


__all__ = [
    "BaseHandler",
    "ImageHandler",
    "PdfHandler",
    "VideoHandler",
    "ArchiveHandler",
    "TextHandler",
    "HANDLER_REGISTRY",
    "get_handler_for_mime",
]
