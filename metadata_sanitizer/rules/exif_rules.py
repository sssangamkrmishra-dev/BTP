"""
EXIF sanitization rules for image files (JPEG, PNG, TIFF).

Defines which EXIF/IPTC/XMP tags to strip, preserve, or flag based on
sanitization mode. Tag IDs follow the EXIF 2.32 specification and
common vendor extensions.

References:
    - EXIF 2.32 spec (CIPA DC-008-2019)
    - IPTC IIM standard (IPTC-NAA Information Interchange Model)
    - XMP specification (ISO 16684-1:2019)
"""

from typing import Set


# ════════════════════════════════════════════════════════════════════════
# ALWAYS STRIP — removed in both "selective" and "strip" modes
# ════════════════════════════════════════════════════════════════════════
# These fields can carry hidden payloads, enable tracking, or leak
# operationally sensitive information.

EXIF_ALWAYS_STRIP: Set[str] = {
    # ── GPS / Location ────────────────────────────────────────────────
    # GPS coordinates can expose drone operating zones, base locations,
    # and flight corridors. Stripped unless config.preserve_gps is True.
    "GPSInfo",
    "GPSLatitude",
    "GPSLatitudeRef",
    "GPSLongitude",
    "GPSLongitudeRef",
    "GPSAltitude",
    "GPSAltitudeRef",
    "GPSTimeStamp",
    "GPSDateStamp",
    "GPSSpeed",
    "GPSSpeedRef",
    "GPSTrack",
    "GPSTrackRef",
    "GPSImgDirection",
    "GPSImgDirectionRef",
    "GPSDestLatitude",
    "GPSDestLatitudeRef",
    "GPSDestLongitude",
    "GPSDestLongitudeRef",
    "GPSMapDatum",
    "GPSAreaInformation",
    "GPSProcessingMethod",

    # ── MakerNote ─────────────────────────────────────────────────────
    # Vendor-specific binary blob that can be arbitrarily large and has
    # been used as a covert data channel. No standard schema.
    "MakerNote",
    "MakerNoteApple",
    "MakerNoteSamsung",
    "MakerNoteSony",
    "MakerNoteNikon",
    "MakerNoteCanon",
    "MakerNoteFuji",
    "MakerNotePentax",
    "MakerNoteOlympus",
    "MakerNoteMinolta",
    "MakerNotePanasonic",

    # ── UserComment / Description fields ──────────────────────────────
    # Free-text fields that can contain scripts or encoded payloads.
    "UserComment",
    "ImageDescription",
    "XPComment",
    "XPSubject",
    "XPKeywords",
    "XPTitle",
    "XPAuthor",

    # ── Embedded thumbnails ───────────────────────────────────────────
    # Thumbnails can differ from the main image (steganography vector)
    # or carry separate EXIF data with different GPS.
    "JPEGInterchangeFormat",
    "JPEGInterchangeFormatLength",

    # ── Software / processing history ─────────────────────────────────
    # Can fingerprint the processing pipeline.
    "ProcessingSoftware",
    "Software",
    "HostComputer",

    # ── XMP extension fields ──────────────────────────────────────────
    "XMP",
    "XMPToolkit",

    # ── IPTC fields with potential PII ────────────────────────────────
    "IPTC:Caption-Abstract",
    "IPTC:Writer-Editor",
    "IPTC:Contact",
    "IPTC:SpecialInstructions",
}


# ════════════════════════════════════════════════════════════════════════
# STRIP IN HIGH SECURITY — additional fields removed only in "strip" mode
# ════════════════════════════════════════════════════════════════════════
# These fields are operationally useful but present a risk surface in
# high-security deployments.

EXIF_STRIP_IN_HIGH_SECURITY: Set[str] = {
    # ── Device identification ─────────────────────────────────────────
    "BodySerialNumber",
    "CameraSerialNumber",
    "SerialNumber",
    "LensSerialNumber",
    "InternalSerialNumber",
    "CameraOwnerName",
    "Artist",
    "Copyright",

    # ── Detailed capture parameters (fingerprinting risk) ─────────────
    "LensModel",
    "LensMake",
    "LensSpecification",
    "Make",
    "Model",
    "UniqueCameraModel",
    "LocalizedCameraModel",
    "FirmwareVersion",

    # ── Timestamps (can correlate activity patterns) ──────────────────
    "DateTimeOriginal",
    "DateTimeDigitized",
    "DateTime",
    "CreateDate",
    "ModifyDate",
    "SubSecTime",
    "SubSecTimeOriginal",
    "SubSecTimeDigitized",
    "OffsetTime",
    "OffsetTimeOriginal",

    # ── All custom / vendor tags ──────────────────────────────────────
    "CustomRendered",
    "OwnerName",
    "PrintImageMatching",
}


# ════════════════════════════════════════════════════════════════════════
# ALWAYS PRESERVE — never stripped, needed for correct image rendering
# ════════════════════════════════════════════════════════════════════════

EXIF_ALWAYS_PRESERVE: Set[str] = {
    "ImageWidth",
    "ImageHeight",
    "ImageLength",
    "BitsPerSample",
    "Compression",
    "PhotometricInterpretation",
    "Orientation",
    "SamplesPerPixel",
    "XResolution",
    "YResolution",
    "ResolutionUnit",
    "ColorSpace",
    "PixelXDimension",
    "PixelYDimension",
    "ExifImageWidth",
    "ExifImageHeight",
    "ComponentsConfiguration",
    "YCbCrSubSampling",
    "YCbCrPositioning",
    "ExifVersion",
    "FlashpixVersion",
}


# ════════════════════════════════════════════════════════════════════════
# SIZE ANOMALY THRESHOLD
# ════════════════════════════════════════════════════════════════════════
# Individual EXIF fields exceeding this byte count are flagged as
# potential payload carriers, regardless of tag name.

EXIF_SIZE_ANOMALY_THRESHOLD: int = 65_536  # 64 KB


def get_exif_strip_set(mode: str, preserve_gps: bool = False) -> Set[str]:
    """
    Return the combined set of EXIF tags to strip for the given mode.

    Args:
        mode: "strip", "selective", or "audit_only"
        preserve_gps: If True, GPS tags are kept even in strip mode.

    Returns:
        Set of EXIF tag names to remove.
    """
    if mode == "audit_only":
        return set()  # audit-only never modifies

    strip_set = set(EXIF_ALWAYS_STRIP)

    if mode == "strip":
        strip_set |= EXIF_STRIP_IN_HIGH_SECURITY

    if preserve_gps:
        gps_tags = {t for t in strip_set if t.startswith("GPS")}
        strip_set -= gps_tags

    return strip_set
