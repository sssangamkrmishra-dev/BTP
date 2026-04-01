"""
Checksum verification for payload integrity.
Computes and compares checksums to detect tampered files.
"""

import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def compute_file_checksum(filepath: str, algorithm: str = "sha256", chunk_size: int = 65536) -> Optional[str]:
    """
    Compute the checksum of a file on disk.
    Returns hex digest string or None if file is not accessible.
    """
    hash_func = _get_hash_func(algorithm)
    if hash_func is None:
        logger.error("Unsupported checksum algorithm: %s", algorithm)
        return None

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.warning("Cannot compute checksum for %s: %s", filepath, e)
        return None


def compute_bytes_checksum(data: bytes, algorithm: str = "sha256") -> Optional[str]:
    """Compute checksum of raw bytes."""
    hash_func = _get_hash_func(algorithm)
    if hash_func is None:
        return None
    hash_func.update(data)
    return hash_func.hexdigest()


def verify_checksum(
    filepath: str,
    expected_checksum: Optional[str],
    algorithm: str = "sha256",
) -> Optional[bool]:
    """
    Verify a file's checksum against an expected value.

    Returns:
        True  - checksum matches
        False - checksum mismatch (possible tampering)
        None  - verification skipped (no expected checksum, file not found, etc.)
    """
    if not expected_checksum:
        return None

    # Skip stub checksums like "a1b2c3d4..."
    if expected_checksum.endswith("..."):
        logger.debug("Skipping stub checksum: %s", expected_checksum)
        return None

    actual = compute_file_checksum(filepath, algorithm)
    if actual is None:
        return None

    match = actual.lower() == expected_checksum.lower()
    if not match:
        logger.warning(
            "Checksum mismatch for %s: expected=%s, actual=%s",
            filepath, expected_checksum, actual,
        )
    return match


def resolve_file_path(uri: Optional[str], storage_base: str = "") -> Optional[str]:
    """
    Resolve a file URI to a local filesystem path.
    Supports: file:/ URIs and relative paths.
    """
    if not uri:
        return None

    if uri.startswith("file:/"):
        # Handle file:/ URIs (single or triple slash)
        path = uri.replace("file:///", "/").replace("file:/", "/")
        # Handle Windows-style paths embedded in URIs
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]  # Remove leading / for Windows paths like /C:\...
        return path

    if uri.startswith("s3://") or uri.startswith("minio://"):
        # Remote storage - not locally resolvable
        return None

    # Treat as relative path
    if storage_base:
        return os.path.join(storage_base, uri)
    return uri


def _get_hash_func(algorithm: str):
    """Get a hashlib hash function by name."""
    algo_map = {
        "sha256": hashlib.sha256,
        "sha1": hashlib.sha1,
        "md5": hashlib.md5,
        "sha512": hashlib.sha512,
    }
    factory = algo_map.get(algorithm.lower())
    return factory() if factory else None
