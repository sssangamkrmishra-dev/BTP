"""
Wire protocol for the Ingestion Interceptor.

Defines the binary packet format used between drone platforms and the
edge interceptor. Two layers:

  1. Packet framing (codec.py + packet.py)
     32-byte fixed header + variable payload + 32-byte HMAC-SHA256 tag.
     Carries SESSION_START / CHUNK / SESSION_END message types over UDP.

  2. Submission marshalling (submission_codec.py)
     TLV (Type-Length-Value) binary encoding of a DroneSubmission. The
     application payload that flows inside CHUNK packets after fragmentation.

Both the drone (sender) and the interceptor (receiver) import from this
package, so the wire contract has a single source of truth.
"""

from .errors import (
    HmacMismatch,
    MalformedPacket,
    PacketCodecError,
    SubmissionCodecError,
    UnsupportedVersion,
)
from .packet import (
    HEADER_SIZE,
    HMAC_TAG_SIZE,
    MAGIC,
    MAX_PAYLOAD_LEN,
    PROTOCOL_VERSION,
    PacketHeader,
    PacketType,
)
from .codec import decode_packet, encode_packet
from .submission_codec import (
    SUBMISSION_MAGIC,
    SUBMISSION_VERSION,
    decode_submission,
    encode_submission,
)

__all__ = [
    # packet framing
    "PacketHeader",
    "PacketType",
    "encode_packet",
    "decode_packet",
    "HEADER_SIZE",
    "HMAC_TAG_SIZE",
    "MAX_PAYLOAD_LEN",
    "MAGIC",
    "PROTOCOL_VERSION",
    # submission marshalling
    "encode_submission",
    "decode_submission",
    "SUBMISSION_MAGIC",
    "SUBMISSION_VERSION",
    # errors
    "PacketCodecError",
    "MalformedPacket",
    "HmacMismatch",
    "UnsupportedVersion",
    "SubmissionCodecError",
]
