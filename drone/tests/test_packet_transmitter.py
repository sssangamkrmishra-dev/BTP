"""
Tests for DronePacketTransmitter.

These verify the drone-side packet packing, fragmentation, HMAC signing,
and transmission via UDP. Each test uses a real UDP socket on a captured
ephemeral port to receive the packets and verify their structure.

Run with: python -m unittest drone.tests.test_packet_transmitter -v
"""

import os
import socket
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from drone.packet_transmitter import DronePacketTransmitter
from ingestion_interceptor.protocol import (
    PacketHeader,
    PacketType,
    decode_packet,
    decode_submission,
)


KEY = "shared_secret_001"


def _minimal_submission(drone_id="DRN-001"):
    return {
        "drone_id": drone_id,
        "timestamp": "2025-10-13T03:00:12Z",
        "payloads": [
            {"type": "image", "filename": "test.jpg", "mime": "image/jpeg",
             "size_bytes": 50000, "encryption": False, "container": False},
        ],
    }


class _UdpSink:
    """Plain UDP sink that collects raw packets without verification."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.5)
        self.host, self.port = self.sock.getsockname()
        self.received: list = []

    def collect(self, expected: int, timeout: float = 1.0):
        deadline = time.time() + timeout
        while len(self.received) < expected and time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(4096)
                self.received.append(data)
            except socket.timeout:
                continue
        return self.received

    def close(self):
        self.sock.close()


class TestDronePacketTransmitter(unittest.TestCase):

    def test_construction_validates_args(self):
        with self.assertRaises(ValueError):
            DronePacketTransmitter("", "127.0.0.1", 5005, KEY)
        with self.assertRaises(ValueError):
            DronePacketTransmitter("DRN-001", "127.0.0.1", 5005, "")
        with self.assertRaises(ValueError):
            DronePacketTransmitter("DRN-001", "127.0.0.1", 5005, KEY, chunk_size=0)
        with self.assertRaises(ValueError):
            DronePacketTransmitter(
                "DRN-001", "127.0.0.1", 5005, KEY, simulate_packet_loss=1.5,
            )

    def test_single_chunk_submission_emits_three_packets(self):
        sink = _UdpSink()
        try:
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=1024,
            )
            n = tx.send(_minimal_submission())
            packets = sink.collect(expected=3)
            self.assertEqual(n, 3)
            self.assertEqual(len(packets), 3)
            tx.close()
        finally:
            sink.close()

    def test_packet_types_in_order(self):
        sink = _UdpSink()
        try:
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=1024,
            )
            tx.send(_minimal_submission())
            packets = sink.collect(expected=3)
            types = []
            for p in packets:
                hdr, _ = decode_packet(p, KEY.encode("utf-8"))
                types.append(hdr.packet_type)
            self.assertEqual(
                types,
                [PacketType.SESSION_START, PacketType.CHUNK, PacketType.SESSION_END],
            )
            tx.close()
        finally:
            sink.close()

    def test_multi_chunk_fragmentation(self):
        sink = _UdpSink()
        try:
            sub = _minimal_submission()
            sub["additional_metadata"] = {"big": "x" * 3000}
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=512,
            )
            tx.send(sub)
            packets = sink.collect(expected=10)
            chunks = 0
            total = 0
            for p in packets:
                hdr, _ = decode_packet(p, KEY.encode("utf-8"))
                if hdr.packet_type == PacketType.CHUNK:
                    chunks += 1
                if hdr.packet_type == PacketType.SESSION_START:
                    total = hdr.total_chunks
            self.assertGreater(chunks, 1)
            self.assertEqual(chunks, total)
            tx.close()
        finally:
            sink.close()

    def test_session_id_stable_within_one_session(self):
        sink = _UdpSink()
        try:
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=1024,
            )
            tx.send(_minimal_submission())
            packets = sink.collect(expected=3)
            session_ids = set()
            for p in packets:
                hdr, _ = decode_packet(p, KEY.encode("utf-8"))
                session_ids.add(hdr.session_id)
            self.assertEqual(len(session_ids), 1)
            tx.close()
        finally:
            sink.close()

    def test_two_sessions_have_different_ids(self):
        sink = _UdpSink()
        try:
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=1024,
            )
            tx.send(_minimal_submission())
            tx.send(_minimal_submission())
            packets = sink.collect(expected=6)
            session_ids = set()
            for p in packets:
                hdr, _ = decode_packet(p, KEY.encode("utf-8"))
                if hdr.packet_type == PacketType.SESSION_START:
                    session_ids.add(hdr.session_id)
            self.assertEqual(len(session_ids), 2)
            tx.close()
        finally:
            sink.close()

    def test_payload_can_be_decoded_back_to_submission(self):
        sink = _UdpSink()
        try:
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY, chunk_size=1024,
            )
            tx.send(_minimal_submission())
            packets = sink.collect(expected=3)
            blob = bytearray()
            for p in packets:
                hdr, payload = decode_packet(p, KEY.encode("utf-8"))
                if hdr.packet_type == PacketType.CHUNK:
                    blob += payload
            decoded = decode_submission(bytes(blob))
            self.assertEqual(decoded["drone_id"], "DRN-001")
            self.assertEqual(len(decoded["payloads"]), 1)
            tx.close()
        finally:
            sink.close()

    def test_packet_loss_simulation_drops_packets(self):
        sink = _UdpSink()
        try:
            # 100% loss → no packets should arrive
            tx = DronePacketTransmitter(
                "DRN-001", sink.host, sink.port, KEY,
                chunk_size=1024, simulate_packet_loss=1.0,
            )
            n = tx.send(_minimal_submission())
            self.assertEqual(n, 0)
            self.assertEqual(tx.stats["packets_dropped_simulated"], 3)
            packets = sink.collect(expected=1, timeout=0.3)
            self.assertEqual(len(packets), 0)
            tx.close()
        finally:
            sink.close()


if __name__ == "__main__":
    unittest.main()
