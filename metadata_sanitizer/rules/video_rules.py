"""
Video/audio metadata sanitization rules.

Defines which metadata atoms/tags to strip from MP4, MKV, AVI,
and audio containers. Covers MP4 atom hierarchy, Matroska tags,
and common vendor extensions.

References:
    - ISO 14496-12 (ISO Base Media File Format / MP4)
    - Matroska specification (matroska.org)
    - ID3v2 tag specification (id3.org)
"""

from typing import Dict, Set


# ════════════════════════════════════════════════════════════════════════
# ALWAYS STRIP ATOMS — removed in both "selective" and "strip" modes
# ════════════════════════════════════════════════════════════════════════

VIDEO_ALWAYS_STRIP_ATOMS: Set[str] = {
    # ── GPS / Location (MP4) ──────────────────────────────────────────
    # Geolocation embedded in MP4 user data atoms or GPS tracks.
    "©xyz",                 # Apple-style GPS coordinates in udta
    "©loc",                 # Location string
    "GPS ",                 # GPS data atom
    "GPSCoordinates",       # GPS coordinate tag (Matroska)
    "location",             # Android-style location tag
    "location-eng",         # Localized location
    "com.apple.quicktime.location.ISO6709",  # Apple full GPS

    # ── User data that can carry payloads ─────────────────────────────
    "udta",                 # User data container (stripped contents, not box)
    "©cmt",                 # Comment (free text)
    "©des",                 # Description
    "©inf",                 # Information
    "©req",                 # Special playback requirements
    "©wrn",                 # Warning text
    "©hst",                 # Host computer
    "©mak",                 # Make (manufacturer)
    "©mod",                 # Model
    "©swr",                 # Software

    # ── Matroska custom tags ──────────────────────────────────────────
    "COMMENT",
    "DESCRIPTION",
    "ENCODED_BY",
    "ENCODER_SETTINGS",

    # ── Embedded thumbnails / cover art ───────────────────────────────
    "covr",                 # Cover art (can differ from content)
    "APIC",                 # ID3 attached picture

    # ── Vendor-specific / custom ──────────────────────────────────────
    "XMP_",                 # XMP metadata in video
    "uuid",                 # UUID extension boxes (can carry arbitrary data)
}


# ════════════════════════════════════════════════════════════════════════
# STRIP IN HIGH SECURITY — additional atoms removed in "strip" mode
# ════════════════════════════════════════════════════════════════════════

VIDEO_STRIP_IN_HIGH_SECURITY: Set[str] = {
    # ── Encoder identification (fingerprinting) ───────────────────────
    "©too",                 # Encoding tool
    "©enc",                 # Encoded by
    "encoder",              # Encoder name
    "encoding_tool",        # Matroska encoder
    "ENCODER",              # Matroska
    "WRITING_APP",          # Matroska writing application
    "MUXING_APP",           # Matroska muxing application

    # ── Timestamps (correlation risk) ─────────────────────────────────
    "©day",                 # Creation date
    "creation_time",        # MP4 creation timestamp
    "DATE_RELEASED",        # Matroska
    "DATE_ENCODED",         # Matroska
    "DATE_TAGGED",          # Matroska

    # ── Attribution ───────────────────────────────────────────────────
    "©ART",                 # Artist
    "©aut",                 # Author
    "©dir",                 # Director
    "©prd",                 # Producer
    "aART",                 # Album artist
    "©own",                 # Owner
    "©prf",                 # Performer
    "©pub",                 # Publisher
    "cprt",                 # Copyright notice

    # ── Chapter / navigation (can be abused for scripting in MKV) ────
    "chpl",                 # Chapter list (MP4)
    "Chapters",             # Matroska chapters
}


# ════════════════════════════════════════════════════════════════════════
# ALWAYS PRESERVE — needed for correct playback
# ════════════════════════════════════════════════════════════════════════

VIDEO_ALWAYS_PRESERVE: Set[str] = {
    # ── MP4 structural atoms ──────────────────────────────────────────
    "moov",                 # Movie container (structural)
    "trak",                 # Track container
    "mdia",                 # Media container
    "minf",                 # Media information
    "stbl",                 # Sample table
    "stts",                 # Time-to-sample
    "stsc",                 # Sample-to-chunk
    "stsz",                 # Sample sizes
    "stco",                 # Chunk offsets
    "co64",                 # 64-bit chunk offsets
    "stsd",                 # Sample descriptions (codec info)
    "mvhd",                 # Movie header (duration, timescale)
    "tkhd",                 # Track header (dimensions, duration)
    "mdhd",                 # Media header (timescale, language)
    "hdlr",                 # Handler reference (track type)
    "ftyp",                 # File type
    "mdat",                 # Media data (actual content)

    # ── Codec / format info ───────────────────────────────────────────
    "avcC",                 # AVC (H.264) decoder configuration
    "hvcC",                 # HEVC (H.265) decoder configuration
    "av1C",                 # AV1 decoder configuration
    "esds",                 # ES descriptor (AAC config)
    "dOps",                 # Opus decoder configuration
    "vpcC",                 # VP codec configuration

    # ── Matroska structural ───────────────────────────────────────────
    "TrackNumber",
    "TrackType",
    "CodecID",
    "CodecPrivate",
    "Duration",
    "PixelWidth",
    "PixelHeight",
    "SamplingFrequency",
    "Channels",
    "BitDepth",
}


# ════════════════════════════════════════════════════════════════════════
# SIZE ANOMALY THRESHOLD
# ════════════════════════════════════════════════════════════════════════
# Metadata atoms exceeding this byte count are flagged as suspicious
# (potential embedded payloads).

VIDEO_SIZE_ANOMALY_THRESHOLD: int = 1_048_576  # 1 MB


# ════════════════════════════════════════════════════════════════════════
# MIME TYPE → HANDLER HINT MAPPING
# ════════════════════════════════════════════════════════════════════════

VIDEO_MIME_TYPES: Dict[str, str] = {
    "video/mp4": "mp4",
    "video/x-matroska": "mkv",
    "video/avi": "avi",
    "video/x-msvideo": "avi",
    "video/quicktime": "mp4",
    "video/webm": "mkv",
    "audio/mpeg": "mp3",
    "audio/mp4": "mp4",
    "audio/x-flac": "flac",
    "audio/ogg": "ogg",
}
