"""
Stage 1 — File Router.

Identifies the true file type of an incoming artifact using magic-byte
inspection with an extension-based fallback. Produces a `RoutingDecision`
that tells the orchestrator which stage to run next (archive handler,
execution, skip, or flag).

Magic-byte sources: https://en.wikipedia.org/wiki/List_of_file_signatures
"""

import logging
from pathlib import Path
from typing import Dict, Optional

from .models import FileCategory, RoutingDecision

logger = logging.getLogger(__name__)


# First bytes that identify a file format regardless of extension.
MAGIC_BYTES: Dict[bytes, FileCategory] = {
    b"PK\x03\x04":      FileCategory.ARCHIVE,     # ZIP (most common)
    b"PK\x05\x06":      FileCategory.ARCHIVE,     # ZIP (empty archive)
    b"PK\x07\x08":      FileCategory.ARCHIVE,     # ZIP (spanned archive)
    b"\x7fELF":         FileCategory.EXECUTABLE,  # Linux ELF binary
    b"\xff\xd8\xff":    FileCategory.IMAGE,       # JPEG image
    b"\x89PNG":         FileCategory.IMAGE,       # PNG image
    b"GIF8":            FileCategory.IMAGE,       # GIF image
    b"%PDF":            FileCategory.DOCUMENT,    # PDF document
    b"MZ":              FileCategory.WINDOWS,     # Windows PE (.exe, .dll)
    b"#!":              FileCategory.SCRIPT,      # Unix shebang
}

# Fallback mapping when magic bytes did not match.
EXTENSION_MAP: Dict[str, FileCategory] = {
    ".py":  FileCategory.SCRIPT,   ".sh":  FileCategory.SCRIPT,
    ".rb":  FileCategory.SCRIPT,   ".pl":  FileCategory.SCRIPT,
    ".zip": FileCategory.ARCHIVE,  ".tar": FileCategory.ARCHIVE,
    ".gz":  FileCategory.ARCHIVE,  ".tgz": FileCategory.ARCHIVE,
    ".jpg": FileCategory.IMAGE,    ".jpeg": FileCategory.IMAGE,
    ".png": FileCategory.IMAGE,    ".gif": FileCategory.IMAGE,
    ".pdf": FileCategory.DOCUMENT,
    ".txt": FileCategory.SAFE,     ".csv": FileCategory.SAFE,
    ".json": FileCategory.SAFE,    ".log": FileCategory.SAFE,
    ".exe": FileCategory.WINDOWS,  ".dll": FileCategory.WINDOWS,
    ".ps1": FileCategory.WINDOWS,  ".bat": FileCategory.WINDOWS,
    ".elf": FileCategory.EXECUTABLE,
}

# Interpreter for each known script extension.
INTERPRETER_MAP: Dict[str, str] = {
    ".py": "python3",
    ".sh": "bash",
    ".rb": "ruby",
    ".pl": "perl",
}

_REASON = {
    FileCategory.EXECUTABLE: "Linux ELF binary — will execute directly",
    FileCategory.SCRIPT:     "Script — run with declared interpreter",
    FileCategory.ARCHIVE:    "Archive — will be extracted and each file sandboxed",
    FileCategory.IMAGE:      "Image — will be inspected for embedded payloads",
    FileCategory.DOCUMENT:   "Document — will be inspected in sandboxed environment",
    FileCategory.SAFE:       "Plain data file — skipping deep analysis",
    FileCategory.WINDOWS:    "Windows executable — flagged for manual review; not executed on Linux",
    FileCategory.UNKNOWN:    "Unknown type — treating as suspicious",
}


def route_file(
    file_path: str,
    skip_safe_files: bool = True,
) -> RoutingDecision:
    """
    Classify a file by magic bytes first, extension second.

    Args:
        file_path: Absolute path to the file.
        skip_safe_files: When True, SAFE files return with `should_skip=True`.

    Returns:
        RoutingDecision with category, interpreter, skip flag, and a
        human-readable justification.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    # Step 1 — magic bytes.
    magic_category: Optional[FileCategory] = None
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for magic, cat in MAGIC_BYTES.items():
            if header.startswith(magic):
                magic_category = cat
                break
    except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
        logger.warning("router: cannot read %s: %s", file_path, exc)

    if magic_category is not None:
        category = magic_category
        magic_match = True
    else:
        category = EXTENSION_MAP.get(ext, FileCategory.UNKNOWN)
        magic_match = False

    interpreter = INTERPRETER_MAP.get(ext) if category == FileCategory.SCRIPT else None
    should_skip = bool(skip_safe_files and category == FileCategory.SAFE)

    return RoutingDecision(
        category=category,
        interpreter=interpreter,
        should_skip=should_skip,
        magic_match=magic_match,
        details=_REASON.get(category, "No routing explanation available"),
    )
