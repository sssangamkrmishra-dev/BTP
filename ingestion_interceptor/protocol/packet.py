"""
Packet header and message types for the wire protocol.

Wire layout (big-endian, 32-byte fixed header):

    Offset  Field           Size  Notes
    ──────  ─────────────   ────  ────────────────────────────────────────
      0     magic            4    0x52504144 ("RPAD")
      4     version          1    0x01
      5     packet_type      1    1=SESSION_START, 2=CHUNK, 3=SESSION_END
      6     flags            2    reserved for future protocol extensions
      8     session_id       8    random 64-bit per submission
     16     seq              4    monotonic uint32 within session
     20     total_chunks     4    set in SESSION_START; 0 elsewhere
     24     payload_len      2    length of bytes following the header
     26     reserved         6    zeroed; future use
    ─────────────────────────────────────────────────────────────────────
     32     payload          ≤1024 bytes
      +     hmac_tag         32   HMAC-SHA256 over (header || payload)
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

# ── Constants ──────────────────────────────────────────────────────────

MAGIC: int = 0x52504144  # "RPAD" — RPA Defence
PROTOCOL_VERSION: int = 0x01
HEADER_SIZE: int = 32
HMAC_TAG_SIZE: int = 32  # SHA-256 digest size
MAX_PAYLOAD_LEN: int = 1024  # bytes per chunk's app-data
MAX_PACKET_SIZE: int = HEADER_SIZE + MAX_PAYLOAD_LEN + HMAC_TAG_SIZE  # 1088 bytes

# struct format for the 32-byte header
#   ! = network byte order (big-endian, no padding)
#   I = magic (uint32)
#   B = version (uint8)
#   B = packet_type (uint8)
#   H = flags (uint16)
#   Q = session_id (uint64)
#   I = seq (uint32)
#   I = total_chunks (uint32)
#   H = payload_len (uint16)
#   6s = reserved (6 bytes)
_HEADER_STRUCT = struct.Struct("!IBBHQIIH6s")
assert _HEADER_STRUCT.size == HEADER_SIZE, "header struct must be 32 bytes"

# ── Packet types ───────────────────────────────────────────────────────

class PacketType(IntEnum):
    SESSION_START = 1
    CHUNK = 2
    SESSION_END = 3


# ── Packet header dataclass ────────────────────────────────────────────

@dataclass
class PacketHeader:
    """Parsed representation of a 32-byte wire header."""

    packet_type: PacketType
    session_id: int
    seq: int
    total_chunks: int = 0
    payload_len: int = 0
    # `flags` is reserved on the wire for future protocol extensions; it
    # is serialized as a uint16 field in the 32-byte header but currently
    # has no bits defined. Always sent as 0.
    flags: int = 0
    version: int = PROTOCOL_VERSION

    def pack(self) -> bytes:
        """Serialize this header to its 32-byte wire form."""
        return _HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            int(self.packet_type),
            self.flags,
            self.session_id,
            self.seq,
            self.total_chunks,
            self.payload_len,
            b"\x00" * 6,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "PacketHeader":
        """
        Parse a 32-byte header. Raises MalformedPacket on bad magic or
        truncation. Does NOT validate version (caller should).
        """
        from .errors import MalformedPacket  # local import to avoid cycle

        if len(raw) < HEADER_SIZE:
            raise MalformedPacket(
                f"header too short: got {len(raw)} bytes, need {HEADER_SIZE}"
            )

        try:
            (
                magic,
                version,
                packet_type_int,
                flags,
                session_id,
                seq,
                total_chunks,
                payload_len,
                _reserved,
            ) = _HEADER_STRUCT.unpack(raw[:HEADER_SIZE])
        except struct.error as e:
            raise MalformedPacket(f"header unpack failed: {e}") from e

        if magic != MAGIC:
            raise MalformedPacket(f"bad magic: 0x{magic:08x}")

        try:
            packet_type = PacketType(packet_type_int)
        except ValueError as e:
            raise MalformedPacket(f"unknown packet_type: {packet_type_int}") from e

        return cls(
            packet_type=packet_type,
            session_id=session_id,
            seq=seq,
            total_chunks=total_chunks,
            payload_len=payload_len,
            flags=flags,
            version=version,
        )
