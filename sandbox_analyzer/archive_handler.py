"""
Stage 2 — Archive Handler.

Extracts ZIP archives into a sandboxed temp directory with three explicit
safety measures:

1. **No password cracking.** If an archive is encrypted and the caller
   has not supplied a key from feed metadata, the archive is flagged as
   suspicious and extraction is skipped. Legitimate drone feeds do not
   arrive padlocked.
2. **ZIP-bomb detection.** Compression ratios below a configured bound
   are rejected *before* extraction based on the file listing.
3. **Double-extension detection.** Files whose outer extension is a
   script/binary type but whose inner extension masquerades as an image
   / document contribute risk points.

The handler recurses into nested archives up to a configurable depth.
"""

import os
import zipfile
from typing import List, Optional

from .config import SandboxConfig
from .models import ArchiveResult


# Classic disguise: "<benign>.<dangerous>" where dangerous is the real
# extension (because Linux / Windows execute by the trailing extension).
_DANGEROUS_FINAL_EXTS = {".exe", ".sh", ".py", ".bat", ".ps1", ".dll",
                         ".vbs", ".rb", ".pl", ".cmd", ".scr"}
_BENIGN_MIDDLE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".pdf",
                       ".doc", ".docx", ".txt", ".csv", ".mp4", ".mov"}


def is_encrypted_zip(zip_path: str) -> bool:
    """Return True if any member of the archive has the encryption bit set."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    return True
        return False
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return False


def check_double_extension(filename: str) -> bool:
    """Classic disguise: `photo.jpg.sh` — benign middle, dangerous final."""
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    middle = "." + parts[-2]
    final = "." + parts[-1]
    return middle in _BENIGN_MIDDLE_EXTS and final in _DANGEROUS_FINAL_EXTS


def handle_archive(
    zip_path: str,
    output_dir: str,
    config: SandboxConfig,
    provided_password: Optional[str] = None,
    depth: int = 0,
) -> ArchiveResult:
    """
    Safely extract a ZIP archive into `output_dir`.

    Args:
        zip_path: Path to the archive on disk.
        output_dir: Destination directory (created if absent).
        config: SandboxConfig holding ratio thresholds and risk deltas.
        provided_password: Key from feed metadata; None means "not declared".
        depth: Current recursion depth (0 = top level).

    Returns:
        ArchiveResult with extraction status, findings, and risk deltas.
    """
    result = ArchiveResult(depth_reached=depth)

    if depth > config.max_extract_depth:
        result.error = f"Max extraction depth ({config.max_extract_depth}) reached"
        return result

    encrypted = is_encrypted_zip(zip_path)
    result.was_encrypted = encrypted

    pwd_bytes: Optional[bytes] = None
    if encrypted:
        if provided_password:
            pwd_bytes = provided_password.encode()
            result.decryption_source = "metadata_key"
        else:
            # Encrypted archive with no declared key → suspicious.
            # We do NOT attempt dictionary attacks (see design doc §7).
            result.extra_risk_score += config.encrypted_no_key_score
            result.suspicious_flags.append(
                f"Encrypted archive with no declared decryption key "
                f"(+{config.encrypted_no_key_score} risk). Extraction skipped."
            )
            result.error = "Encrypted — no key provided. Flagged as suspicious."
            return result

    # Inspect file listing BEFORE extracting.
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            if pwd_bytes:
                zf.setpassword(pwd_bytes)

            for info in zf.infolist():
                fname = info.filename

                if check_double_extension(fname):
                    result.double_extensions.append(fname)
                    result.extra_risk_score += config.double_extension_score
                    result.suspicious_flags.append(
                        f"Double extension disguise: {fname} "
                        f"(+{config.double_extension_score} risk)"
                    )

                # ZIP-bomb heuristic: uncompressed size > threshold AND
                # compression ratio < bound. Ignore entries with
                # compress_size=0 (directories, trivial files).
                if (
                    info.file_size > config.zip_bomb_min_size_bytes
                    and info.compress_size > 0
                    and (info.compress_size / info.file_size) < config.zip_bomb_ratio
                ):
                    result.zip_bomb_detected = True
                    result.suspicious_flags.append(
                        f"ZIP bomb suspected: {fname} "
                        f"({info.compress_size:,} bytes compressed → "
                        f"{info.file_size:,} bytes uncompressed)"
                    )

            if result.zip_bomb_detected:
                result.error = "ZIP bomb detected — extraction aborted"
                return result

            os.makedirs(output_dir, exist_ok=True)
            zf.extractall(output_dir)

    except zipfile.BadZipFile as exc:
        result.error = f"Corrupt archive: {exc}"
        return result
    except RuntimeError as exc:   # raised by zipfile on wrong/missing password
        result.error = f"Extraction failed: {exc}"
        return result
    except OSError as exc:
        result.error = f"Extraction I/O error: {exc}"
        return result

    # Recurse into nested archives.
    extracted: List[str] = []
    for fname in os.listdir(output_dir):
        fpath = os.path.join(output_dir, fname)
        if fname.lower().endswith(".zip") and os.path.isfile(fpath):
            sub_dir = fpath + "_extracted"
            sub = handle_archive(
                fpath, sub_dir, config, provided_password, depth + 1
            )
            extracted.extend(sub.extracted_files)
            result.suspicious_flags.extend(sub.suspicious_flags)
            result.double_extensions.extend(sub.double_extensions)
            result.extra_risk_score += sub.extra_risk_score
            if sub.zip_bomb_detected:
                result.zip_bomb_detected = True
            if sub.depth_reached > result.depth_reached:
                result.depth_reached = sub.depth_reached
        else:
            extracted.append(fpath)

    result.extracted_files = extracted
    result.success = True
    return result
