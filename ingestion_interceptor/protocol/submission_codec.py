"""
Binary marshaller for the DroneSubmission application payload.

This is the bytes that flow inside the CHUNK packets after the drone
fragments them. Modelled on MAVLink's spirit: typed binary fields, fixed
numeric tags, length-prefixed values, optional fields drop out naturally.

Wire format (all big-endian):

    Submission envelope:
    ────────────────────────────────────────────────────────────
    Magic         4 bytes   "DSUB"
    Version       1 byte    0x01
    Reserved      3 bytes   0x000000
    Field count   2 bytes   uint16 — number of TLV records following
    ────────────────────────────────────────────────────────────
    For each field — TLV record:
      Tag       1 byte    (FIELD_DRONE_ID, etc.)
      Length    2 bytes   uint16 — length of value
      Value     N bytes
    ────────────────────────────────────────────────────────────

    Top-level field tags:
      0x01 drone_id              utf-8 string
      0x02 timestamp             utf-8 string
      0x03 mission_id            utf-8 string         (optional)
      0x04 mission_zone          utf-8 string         (optional)
      0x05 geo                   24 B (3x float64)    (optional)
      0x06 telemetry             40 B fixed struct    (optional)
      0x07 signature             utf-8 string         (optional)
      0x08 firmware_version      utf-8 string         (optional)
      0x09 operator_id           utf-8 string         (optional)
      0x0A additional_metadata   TLV substream of (key,value) string pairs
      0x0B payload               TLV substream (repeats per payload entry)

    Telemetry substruct (40 B fixed):
      speed           float64
      heading         float64
      battery         float64
      signal_strength float64
      vertical_speed  float32
      temperature     float32

    Payload substream (one TLV substream per payload):
      0x01 type        1 byte enum (1=video, 2=image, 3=archive, 4=telemetry, 5=text)
      0x02 filename    utf-8 string
      0x03 mime        utf-8 string
      0x04 size_bytes  8 B uint64
      0x05 encryption  1 byte (0/1)
      0x06 container   1 byte (0/1)
      0x07 checksum    utf-8 string  (optional)
      0x08 uri         utf-8 string  (optional)

    additional_metadata substream:
      Each kv pair:
        Key length    1 byte
        Key bytes     N bytes (utf-8)
        Value length  2 bytes
        Value bytes   N bytes (utf-8, coerced from any scalar)
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .errors import MalformedSubmission, SubmissionCodecError

# ── Constants ──────────────────────────────────────────────────────────

SUBMISSION_MAGIC: bytes = b"DSUB"
SUBMISSION_VERSION: int = 0x01
_ENVELOPE_HEADER = struct.Struct("!4sB3sH")  # magic, version, reserved, field_count
assert _ENVELOPE_HEADER.size == 10

# Top-level field tags
TAG_DRONE_ID = 0x01
TAG_TIMESTAMP = 0x02
TAG_MISSION_ID = 0x03
TAG_MISSION_ZONE = 0x04
TAG_GEO = 0x05
TAG_TELEMETRY = 0x06
TAG_SIGNATURE = 0x07
TAG_FIRMWARE_VERSION = 0x08
TAG_OPERATOR_ID = 0x09
TAG_ADDITIONAL_METADATA = 0x0A
TAG_PAYLOAD = 0x0B

# Payload substream tags
PTAG_TYPE = 0x01
PTAG_FILENAME = 0x02
PTAG_MIME = 0x03
PTAG_SIZE_BYTES = 0x04
PTAG_ENCRYPTION = 0x05
PTAG_CONTAINER = 0x06
PTAG_CHECKSUM = 0x07
PTAG_URI = 0x08

# Payload type enum (matches DroneSubmission "type" field strings)
_PAYLOAD_TYPE_TO_INT = {
    "video": 1,
    "image": 2,
    "archive": 3,
    "telemetry": 4,
    "text": 5,
}
_INT_TO_PAYLOAD_TYPE = {v: k for k, v in _PAYLOAD_TYPE_TO_INT.items()}

# Struct formats for fixed-size substructures
_GEO_STRUCT = struct.Struct("!ddd")  # lat, lon, alt — 24 bytes
assert _GEO_STRUCT.size == 24

_TELEMETRY_STRUCT = struct.Struct("!ddddff")  # speed, heading, battery, signal, vspeed, temp
assert _TELEMETRY_STRUCT.size == 40

_TLV_HEADER = struct.Struct("!BH")  # tag, length — 3 bytes
assert _TLV_HEADER.size == 3


# ── Helpers ────────────────────────────────────────────────────────────

def _encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a single tag-length-value record."""
    if len(value) > 0xFFFF:
        raise SubmissionCodecError(
            f"TLV value too large for tag 0x{tag:02x}: {len(value)} bytes"
        )
    return _TLV_HEADER.pack(tag, len(value)) + value


def _encode_string_field(tag: int, value: Optional[str]) -> bytes:
    """Encode an optional string field, or return empty bytes if value is None."""
    if value is None:
        return b""
    return _encode_tlv(tag, value.encode("utf-8"))


def _encode_geo(geo: Optional[Dict[str, float]]) -> bytes:
    """Encode geo as a 24-byte struct, or empty if None."""
    if not geo:
        return b""
    try:
        body = _GEO_STRUCT.pack(
            float(geo.get("lat", 0.0)),
            float(geo.get("lon", 0.0)),
            float(geo.get("alt", 0.0)),
        )
    except (TypeError, ValueError) as e:
        raise SubmissionCodecError(f"invalid geo: {e}") from e
    return _encode_tlv(TAG_GEO, body)


def _encode_telemetry(tel: Optional[Dict[str, Any]]) -> bytes:
    """Encode telemetry into the 40-byte fixed substruct."""
    if not tel:
        return b""
    try:
        body = _TELEMETRY_STRUCT.pack(
            float(tel.get("speed", 0.0)),
            float(tel.get("heading", 0.0)),
            float(tel.get("battery", 0.0)),
            float(tel.get("signal_strength", 0.0)),
            float(tel.get("vertical_speed", 0.0)),
            float(tel.get("temperature", 0.0)),
        )
    except (TypeError, ValueError) as e:
        raise SubmissionCodecError(f"invalid telemetry: {e}") from e
    return _encode_tlv(TAG_TELEMETRY, body)


def _encode_additional_metadata(meta: Optional[Dict[str, Any]]) -> bytes:
    """
    Encode additional_metadata as a TLV substream of (key, value) string
    pairs. Non-string values are coerced via str(). Keys longer than 255
    bytes are truncated; values longer than 65535 bytes are truncated.
    """
    if not meta:
        return b""
    body = bytearray()
    for k, v in meta.items():
        key_bytes = str(k).encode("utf-8")[:255]
        val_bytes = str(v).encode("utf-8")[:65535]
        body += struct.pack("!B", len(key_bytes)) + key_bytes
        body += struct.pack("!H", len(val_bytes)) + val_bytes
    return _encode_tlv(TAG_ADDITIONAL_METADATA, bytes(body))


def _encode_payload(p: Dict[str, Any]) -> bytes:
    """Encode a single payload entry as a TLV substream."""
    type_str = p.get("type", "text")
    type_int = _PAYLOAD_TYPE_TO_INT.get(type_str, 5)  # default to text(5)

    body = bytearray()
    body += _encode_tlv(PTAG_TYPE, struct.pack("!B", type_int))
    body += _encode_tlv(PTAG_FILENAME, str(p.get("filename", "")).encode("utf-8"))
    body += _encode_tlv(PTAG_MIME, str(p.get("mime", "")).encode("utf-8"))
    body += _encode_tlv(PTAG_SIZE_BYTES, struct.pack("!Q", int(p.get("size_bytes", 0))))
    body += _encode_tlv(PTAG_ENCRYPTION, struct.pack("!B", 1 if p.get("encryption") else 0))
    body += _encode_tlv(PTAG_CONTAINER, struct.pack("!B", 1 if p.get("container") else 0))
    if p.get("checksum"):
        body += _encode_tlv(PTAG_CHECKSUM, str(p["checksum"]).encode("utf-8"))
    if p.get("uri"):
        body += _encode_tlv(PTAG_URI, str(p["uri"]).encode("utf-8"))
    return _encode_tlv(TAG_PAYLOAD, bytes(body))


# ── Public API: encode ─────────────────────────────────────────────────

def encode_submission(submission: Dict[str, Any]) -> bytes:
    """
    Marshal a DroneSubmission dict to its binary wire form.

    Args:
        submission: A dict in the IngestionInterceptor input format.

    Returns:
        A bytes object containing envelope header + TLV records.

    Raises:
        SubmissionCodecError on malformed input.
    """
    if not isinstance(submission, dict):
        raise SubmissionCodecError("submission must be a dict")

    if "drone_id" not in submission or "timestamp" not in submission:
        raise SubmissionCodecError("submission missing required drone_id/timestamp")

    fields = bytearray()
    field_count = 0

    # Required string fields
    fields += _encode_string_field(TAG_DRONE_ID, submission["drone_id"])
    field_count += 1
    fields += _encode_string_field(TAG_TIMESTAMP, submission["timestamp"])
    field_count += 1

    # Optional string fields
    for tag, key in (
        (TAG_MISSION_ID, "mission_id"),
        (TAG_MISSION_ZONE, "mission_zone"),
        (TAG_SIGNATURE, "signature"),
        (TAG_FIRMWARE_VERSION, "firmware_version"),
        (TAG_OPERATOR_ID, "operator_id"),
    ):
        val = submission.get(key)
        if val:
            fields += _encode_string_field(tag, val)
            field_count += 1

    # Geo
    geo = submission.get("geo")
    if geo:
        fields += _encode_geo(geo)
        field_count += 1

    # Telemetry
    tel = submission.get("telemetry")
    if tel:
        fields += _encode_telemetry(tel)
        field_count += 1

    # Additional metadata
    meta = submission.get("additional_metadata")
    if meta:
        fields += _encode_additional_metadata(meta)
        field_count += 1

    # Payloads
    payloads = submission.get("payloads", [])
    if not isinstance(payloads, list):
        raise SubmissionCodecError("payloads must be a list")
    for p in payloads:
        if not isinstance(p, dict):
            raise SubmissionCodecError("each payload must be a dict")
        fields += _encode_payload(p)
        field_count += 1

    if field_count > 0xFFFF:
        raise SubmissionCodecError(f"too many fields: {field_count}")

    envelope = _ENVELOPE_HEADER.pack(
        SUBMISSION_MAGIC, SUBMISSION_VERSION, b"\x00\x00\x00", field_count
    )
    return envelope + bytes(fields)


# ── Public API: decode ─────────────────────────────────────────────────

def _read_tlv(buf: bytes, offset: int) -> Tuple[int, int, bytes, int]:
    """
    Read a single TLV record at offset. Returns (tag, length, value_bytes,
    new_offset). Raises MalformedSubmission on truncation.
    """
    if offset + _TLV_HEADER.size > len(buf):
        raise MalformedSubmission(f"truncated TLV header at offset {offset}")
    tag, length = _TLV_HEADER.unpack(buf[offset : offset + _TLV_HEADER.size])
    value_start = offset + _TLV_HEADER.size
    value_end = value_start + length
    if value_end > len(buf):
        raise MalformedSubmission(
            f"truncated TLV value: tag=0x{tag:02x} length={length} at offset {offset}"
        )
    return tag, length, buf[value_start:value_end], value_end


def _decode_payload(body: bytes) -> Dict[str, Any]:
    """Decode a payload substream into a dict."""
    out: Dict[str, Any] = {
        "type": "text",
        "filename": "",
        "mime": "",
        "size_bytes": 0,
        "encryption": False,
        "container": False,
    }
    offset = 0
    while offset < len(body):
        tag, _, value, offset = _read_tlv(body, offset)
        if tag == PTAG_TYPE:
            type_int = struct.unpack("!B", value)[0]
            out["type"] = _INT_TO_PAYLOAD_TYPE.get(type_int, "text")
        elif tag == PTAG_FILENAME:
            out["filename"] = value.decode("utf-8", errors="replace")
        elif tag == PTAG_MIME:
            out["mime"] = value.decode("utf-8", errors="replace")
        elif tag == PTAG_SIZE_BYTES:
            out["size_bytes"] = struct.unpack("!Q", value)[0]
        elif tag == PTAG_ENCRYPTION:
            out["encryption"] = bool(struct.unpack("!B", value)[0])
        elif tag == PTAG_CONTAINER:
            out["container"] = bool(struct.unpack("!B", value)[0])
        elif tag == PTAG_CHECKSUM:
            out["checksum"] = value.decode("utf-8", errors="replace")
        elif tag == PTAG_URI:
            out["uri"] = value.decode("utf-8", errors="replace")
        # Unknown sub-tags are ignored for forward compatibility
    return out


def _decode_additional_metadata(body: bytes) -> Dict[str, str]:
    """Decode the additional_metadata substream into a dict of strings."""
    out: Dict[str, str] = {}
    offset = 0
    while offset < len(body):
        if offset + 1 > len(body):
            raise MalformedSubmission("truncated additional_metadata key length")
        key_len = body[offset]
        offset += 1
        if offset + key_len > len(body):
            raise MalformedSubmission("truncated additional_metadata key")
        key = body[offset : offset + key_len].decode("utf-8", errors="replace")
        offset += key_len
        if offset + 2 > len(body):
            raise MalformedSubmission("truncated additional_metadata value length")
        val_len = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
        if offset + val_len > len(body):
            raise MalformedSubmission("truncated additional_metadata value")
        val = body[offset : offset + val_len].decode("utf-8", errors="replace")
        offset += val_len
        out[key] = val
    return out


def decode_submission(buf: bytes) -> Dict[str, Any]:
    """
    Decode a binary submission back into a dict compatible with
    IngestionInterceptor.process().

    Args:
        buf: The reassembled bytes from a session's CHUNK payloads.

    Returns:
        A dict in the same shape as the original submission.

    Raises:
        MalformedSubmission on bad magic, version, or truncated TLV records.
    """
    if len(buf) < _ENVELOPE_HEADER.size:
        raise MalformedSubmission(
            f"submission too short: {len(buf)} < {_ENVELOPE_HEADER.size}"
        )

    magic, version, _reserved, field_count = _ENVELOPE_HEADER.unpack(
        buf[: _ENVELOPE_HEADER.size]
    )
    if magic != SUBMISSION_MAGIC:
        raise MalformedSubmission(f"bad submission magic: {magic!r}")
    if version != SUBMISSION_VERSION:
        raise MalformedSubmission(f"unsupported submission version: {version}")

    out: Dict[str, Any] = {"payloads": []}
    offset = _ENVELOPE_HEADER.size
    fields_seen = 0

    while fields_seen < field_count:
        tag, _, value, offset = _read_tlv(buf, offset)
        fields_seen += 1

        if tag == TAG_DRONE_ID:
            out["drone_id"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_TIMESTAMP:
            out["timestamp"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_MISSION_ID:
            out["mission_id"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_MISSION_ZONE:
            out["mission_zone"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_SIGNATURE:
            out["signature"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_FIRMWARE_VERSION:
            out["firmware_version"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_OPERATOR_ID:
            out["operator_id"] = value.decode("utf-8", errors="replace")
        elif tag == TAG_GEO:
            if len(value) != _GEO_STRUCT.size:
                raise MalformedSubmission(
                    f"geo wrong size: {len(value)} != {_GEO_STRUCT.size}"
                )
            lat, lon, alt = _GEO_STRUCT.unpack(value)
            out["geo"] = {"lat": lat, "lon": lon, "alt": alt}
        elif tag == TAG_TELEMETRY:
            if len(value) != _TELEMETRY_STRUCT.size:
                raise MalformedSubmission(
                    f"telemetry wrong size: {len(value)} != {_TELEMETRY_STRUCT.size}"
                )
            (
                speed, heading, battery, signal_strength, vertical_speed, temperature,
            ) = _TELEMETRY_STRUCT.unpack(value)
            out["telemetry"] = {
                "speed": speed,
                "heading": heading,
                "battery": battery,
                "signal_strength": signal_strength,
                "vertical_speed": vertical_speed,
                "temperature": temperature,
            }
        elif tag == TAG_ADDITIONAL_METADATA:
            out["additional_metadata"] = _decode_additional_metadata(value)
        elif tag == TAG_PAYLOAD:
            out["payloads"].append(_decode_payload(value))
        # Unknown tags are skipped for forward compatibility

    if "drone_id" not in out or "timestamp" not in out:
        raise MalformedSubmission("decoded submission missing drone_id/timestamp")

    return out
