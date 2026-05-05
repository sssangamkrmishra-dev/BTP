"""
Tests for the packet framing codec (ingestion_interceptor.protocol.codec).
Run with: python -m unittest ingestion_interceptor.tests.test_packet_codec -v
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ingestion_interceptor.protocol import (
    HEADER_SIZE,
    HMAC_TAG_SIZE,
    MAGIC,
    MAX_PAYLOAD_LEN,
    PROTOCOL_VERSION,
    HmacMismatch,
    MalformedPacket,
    PacketHeader,
    PacketType,
    UnsupportedVersion,
    decode_packet,
    encode_packet,
)
from ingestion_interceptor.protocol.codec import decode_packet_unverified, verify_hmac

KEY = b"shared_secret_001"


def _make_header(packet_type=PacketType.CHUNK, **kwargs):
    defaults = dict(packet_type=packet_type, session_id=0xDEADBEEFCAFEBABE, seq=0)
    defaults.update(kwargs)
    return PacketHeader(**defaults)


class TestPacketCodec(unittest.TestCase):

    def test_round_trip_chunk(self):
        h = _make_header(seq=42)
        wire = encode_packet(h, b"hello world", KEY)
        h2, payload2 = decode_packet(wire, KEY)
        self.assertEqual(h2.session_id, h.session_id)
        self.assertEqual(h2.seq, 42)
        self.assertEqual(payload2, b"hello world")
        self.assertEqual(h2.packet_type, PacketType.CHUNK)

    def test_round_trip_session_start(self):
        h = _make_header(packet_type=PacketType.SESSION_START, total_chunks=5)
        wire = encode_packet(h, b"DRN-001", KEY)
        h2, payload2 = decode_packet(wire, KEY)
        self.assertEqual(h2.packet_type, PacketType.SESSION_START)
        self.assertEqual(h2.total_chunks, 5)
        self.assertEqual(payload2, b"DRN-001")

    def test_round_trip_session_end(self):
        h = _make_header(packet_type=PacketType.SESSION_END, seq=99)
        wire = encode_packet(h, b"", KEY)
        h2, payload2 = decode_packet(wire, KEY)
        self.assertEqual(h2.packet_type, PacketType.SESSION_END)
        self.assertEqual(h2.seq, 99)
        self.assertEqual(payload2, b"")

    def test_max_payload_size(self):
        h = _make_header()
        big = b"A" * MAX_PAYLOAD_LEN
        wire = encode_packet(h, big, KEY)
        h2, payload2 = decode_packet(wire, KEY)
        self.assertEqual(payload2, big)
        self.assertEqual(len(wire), HEADER_SIZE + MAX_PAYLOAD_LEN + HMAC_TAG_SIZE)

    def test_oversize_payload_rejected_at_encode(self):
        h = _make_header()
        with self.assertRaises(ValueError):
            encode_packet(h, b"A" * (MAX_PAYLOAD_LEN + 1), KEY)

    def test_empty_key_rejected_at_encode(self):
        h = _make_header()
        with self.assertRaises(ValueError):
            encode_packet(h, b"x", b"")

    def test_bad_magic_rejected(self):
        h = _make_header()
        wire = bytearray(encode_packet(h, b"x", KEY))
        wire[0:4] = b"XXXX"  # corrupt the magic
        with self.assertRaises(MalformedPacket):
            decode_packet(bytes(wire), KEY)

    def test_unsupported_version_rejected(self):
        h = _make_header(version=99)
        wire = encode_packet(h, b"x", KEY)
        with self.assertRaises(UnsupportedVersion):
            decode_packet(wire, KEY)

    def test_truncated_header_rejected(self):
        h = _make_header()
        wire = encode_packet(h, b"hello", KEY)
        with self.assertRaises(MalformedPacket):
            decode_packet(wire[:10], KEY)

    def test_truncated_payload_rejected(self):
        h = _make_header()
        wire = encode_packet(h, b"hello world", KEY)
        # Drop the HMAC tag and one byte of payload
        with self.assertRaises(MalformedPacket):
            decode_packet(wire[:-(HMAC_TAG_SIZE + 1)], KEY)

    def test_payload_len_lie_rejected(self):
        # Hand-craft a header that lies about payload_len
        bad_header = struct.pack(
            "!IBBHQIIH6s",
            MAGIC, PROTOCOL_VERSION, int(PacketType.CHUNK), 0x0001,
            0x1234567890ABCDEF, 0, 0,
            9999,  # absurd payload_len
            b"\x00" * 6,
        )
        wire = bad_header + b"x" * 16 + b"\x00" * HMAC_TAG_SIZE
        with self.assertRaises(MalformedPacket):
            decode_packet(wire, KEY)

    def test_hmac_mismatch_rejected(self):
        h = _make_header()
        wire = encode_packet(h, b"hello", KEY)
        # Tamper with the payload byte
        tampered = bytearray(wire)
        tampered[HEADER_SIZE] ^= 0xFF
        with self.assertRaises(HmacMismatch):
            decode_packet(bytes(tampered), KEY)

    def test_wrong_key_rejected(self):
        h = _make_header()
        wire = encode_packet(h, b"hello", KEY)
        with self.assertRaises(HmacMismatch):
            decode_packet(wire, b"wrong_key")

    def test_decode_unverified_returns_tag(self):
        h = _make_header(packet_type=PacketType.SESSION_START, total_chunks=3)
        wire = encode_packet(h, b"DRN-001", KEY)
        h2, payload2, tag2 = decode_packet_unverified(wire)
        self.assertEqual(payload2, b"DRN-001")
        self.assertEqual(len(tag2), HMAC_TAG_SIZE)
        # Manual verification works
        verify_hmac(h2, payload2, tag2, KEY)
        with self.assertRaises(HmacMismatch):
            verify_hmac(h2, payload2, tag2, b"wrong")


if __name__ == "__main__":
    unittest.main()
