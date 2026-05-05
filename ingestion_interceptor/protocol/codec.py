"""
Packet framing codec.

encode_packet:  PacketHeader + payload bytes + key  ─►  wire bytes
decode_packet:  wire bytes + key                    ─►  (PacketHeader, payload)

The HMAC-SHA256 tag is computed over (header || payload) and appended after
the payload. The receiver recomputes it before trusting any header field.

Threat model:
  * The header itself is not encrypted. The drone_id is not in the header
    (it travels in the SESSION_START payload), so the receiver must look
    up the key from the SESSION_START payload BEFORE it can verify CHUNK
    HMACs. The codec therefore offers two decode modes:
      - decode_packet(raw, hmac_key)            verifies HMAC immediately
      - decode_packet_unverified(raw)           returns header+payload+tag
                                                without verification, so
                                                the receiver can fish out
                                                the drone_id and look up
                                                the key.
"""

import hmac
import hashlib
from typing import Tuple

from .errors import HmacMismatch, MalformedPacket, UnsupportedVersion
from .packet import (
    HEADER_SIZE,
    HMAC_TAG_SIZE,
    MAX_PACKET_SIZE,
    MAX_PAYLOAD_LEN,
    PROTOCOL_VERSION,
    PacketHeader,
)


def _compute_hmac(header_bytes: bytes, payload: bytes, key: bytes) -> bytes:
    """HMAC-SHA256 over the concatenation of header and payload bytes."""
    mac = hmac.new(key, header_bytes + payload, hashlib.sha256)
    return mac.digest()


def encode_packet(header: PacketHeader, payload: bytes, hmac_key: bytes) -> bytes:
    """
    Serialize a packet to its wire form.

    Args:
        header:    A PacketHeader. payload_len is overridden to match payload.
        payload:   Application bytes (≤ MAX_PAYLOAD_LEN).
        hmac_key:  Per-drone shared secret used to compute the HMAC tag.

    Returns:
        Bytes ready for socket.sendto(). Length is HEADER_SIZE + len(payload)
        + HMAC_TAG_SIZE.

    Raises:
        ValueError if payload exceeds MAX_PAYLOAD_LEN or hmac_key is empty.
    """
    if len(payload) > MAX_PAYLOAD_LEN:
        raise ValueError(
            f"payload too large: {len(payload)} > {MAX_PAYLOAD_LEN}"
        )
    if not hmac_key:
        raise ValueError("hmac_key must not be empty")

    header.payload_len = len(payload)
    header_bytes = header.pack()
    tag = _compute_hmac(header_bytes, payload, hmac_key)
    return header_bytes + payload + tag


def decode_packet_unverified(raw: bytes) -> Tuple[PacketHeader, bytes, bytes]:
    """
    Parse the header, slice out the payload and the HMAC tag, but DO NOT
    verify the HMAC. Used by the receiver during SESSION_START dispatch
    when the key has not yet been resolved.

    Returns:
        (header, payload, hmac_tag)

    Raises:
        MalformedPacket on length/magic/struct errors.
        UnsupportedVersion if the version byte is unknown.
    """
    if len(raw) > MAX_PACKET_SIZE:
        raise MalformedPacket(
            f"packet too large: {len(raw)} > {MAX_PACKET_SIZE}"
        )
    if len(raw) < HEADER_SIZE + HMAC_TAG_SIZE:
        raise MalformedPacket(
            f"packet too small: {len(raw)} < {HEADER_SIZE + HMAC_TAG_SIZE}"
        )

    header = PacketHeader.unpack(raw)

    if header.version != PROTOCOL_VERSION:
        raise UnsupportedVersion(
            f"protocol version {header.version} not supported "
            f"(this codec speaks v{PROTOCOL_VERSION})"
        )

    declared_total = HEADER_SIZE + header.payload_len + HMAC_TAG_SIZE
    if declared_total != len(raw):
        raise MalformedPacket(
            f"declared length {declared_total} != actual {len(raw)}"
        )

    if header.payload_len > MAX_PAYLOAD_LEN:
        raise MalformedPacket(
            f"payload_len {header.payload_len} exceeds max {MAX_PAYLOAD_LEN}"
        )

    payload = raw[HEADER_SIZE : HEADER_SIZE + header.payload_len]
    tag = raw[HEADER_SIZE + header.payload_len :]
    return header, payload, tag


def verify_hmac(
    header: PacketHeader,
    payload: bytes,
    tag: bytes,
    hmac_key: bytes,
) -> None:
    """
    Verify a packet's HMAC tag in constant time. Raises HmacMismatch on
    failure. Returns None on success.
    """
    if not hmac_key:
        raise HmacMismatch("no key available for verification")

    expected = _compute_hmac(header.pack(), payload, hmac_key)
    if not hmac.compare_digest(expected, tag):
        raise HmacMismatch("HMAC tag does not match")


def decode_packet(raw: bytes, hmac_key: bytes) -> Tuple[PacketHeader, bytes]:
    """
    Parse and HMAC-verify a packet in one step.

    Args:
        raw:       Bytes from socket.recvfrom().
        hmac_key:  Per-drone shared secret.

    Returns:
        (header, payload) — both trusted to be intact and authenticated.

    Raises:
        MalformedPacket, UnsupportedVersion, HmacMismatch.
    """
    header, payload, tag = decode_packet_unverified(raw)
    verify_hmac(header, payload, tag, hmac_key)
    return header, payload
