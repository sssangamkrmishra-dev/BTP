"""
Tests for the packet receiver (UDP listener + reassembly).

These exercise the receiver via real UDP sockets on localhost using
ephemeral ports, so they verify the threading and socket plumbing in
addition to the reassembly logic.

Run with: python -m unittest ingestion_interceptor.tests.test_packet_receiver -v
"""

import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ingestion_interceptor import IngestionInterceptor, InterceptorConfig
from ingestion_interceptor.packet_receiver import PacketReceiver, ReassemblyBuffer
from ingestion_interceptor.protocol import (
    MAX_PAYLOAD_LEN,
    PacketHeader,
    PacketType,
    encode_packet,
    encode_submission,
)


KEY_001 = "shared_secret_001"


def _build_session_packets(
    submission: dict, drone_id: str, hmac_key: str, chunk_size: int = MAX_PAYLOAD_LEN
):
    """
    Build the START / CHUNK / END packets for a submission.
    Returns (session_id, list_of_packets).
    """
    blob = encode_submission(submission)
    total_chunks = max(1, (len(blob) + chunk_size - 1) // chunk_size)
    session_id = struct.unpack("!Q", os.urandom(8))[0]
    key_bytes = hmac_key.encode("utf-8")

    packets = []
    packets.append(
        encode_packet(
            PacketHeader(
                packet_type=PacketType.SESSION_START,
                session_id=session_id, seq=0, total_chunks=total_chunks,
            ),
            drone_id.encode("utf-8"),
            key_bytes,
        )
    )
    for i in range(total_chunks):
        chunk = blob[i * chunk_size : (i + 1) * chunk_size]
        packets.append(
            encode_packet(
                PacketHeader(
                    packet_type=PacketType.CHUNK,
                    session_id=session_id, seq=i,
                ),
                chunk, key_bytes,
            )
        )
    packets.append(
        encode_packet(
            PacketHeader(
                packet_type=PacketType.SESSION_END,
                session_id=session_id, seq=total_chunks,
            ),
            b"", key_bytes,
        )
    )
    return session_id, packets


def _minimal_submission(drone_id="DRN-001"):
    return {
        "drone_id": drone_id,
        "timestamp": "2025-10-13T03:00:12Z",
        "payloads": [
            {"type": "image", "filename": "test.jpg", "mime": "image/jpeg",
             "size_bytes": 50000, "encryption": False, "container": False},
        ],
    }


class _CapturingReceiverHarness:
    """Spins up a PacketReceiver bound to an ephemeral port and captures
    every successfully reassembled submission via the on_submission callback."""

    def __init__(self, key_store=None, **receiver_kwargs):
        self.received: list = []
        self.lock = threading.Lock()

        def on_submission(sub):
            with self.lock:
                self.received.append(sub)

        # Use `is None` so an explicit empty dict means "no keys configured"
        if key_store is None:
            key_store = {"DRN-001": KEY_001}

        self.receiver = PacketReceiver(
            host="127.0.0.1",
            port=0,
            key_store=key_store,
            on_submission=on_submission,
            **receiver_kwargs,
        )
        self.receiver.start()

        # Client socket for sending packets
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host, port = self.receiver.bound_address
        self.target = (host, port)

    def send(self, packet: bytes):
        self.client.sendto(packet, self.target)

    def stop(self):
        self.client.close()
        self.receiver.stop()

    def wait_for_received(self, n: int, timeout: float = 2.0) -> bool:
        """Block until at least n submissions have been captured, or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if len(self.received) >= n:
                    return True
            time.sleep(0.01)
        return False


class TestReassemblyBuffer(unittest.TestCase):

    def test_single_chunk_complete(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=1, started_at=time.time()
        )
        self.assertFalse(buf.is_complete())
        buf.add_chunk(0, b"hello")
        self.assertTrue(buf.is_complete())
        self.assertEqual(buf.assemble(), b"hello")

    def test_multi_chunk_in_order(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=3, started_at=time.time()
        )
        buf.add_chunk(0, b"hel")
        buf.add_chunk(1, b"lo ")
        buf.add_chunk(2, b"wld")
        self.assertEqual(buf.assemble(), b"hello wld")

    def test_multi_chunk_out_of_order(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=3, started_at=time.time()
        )
        buf.add_chunk(2, b"wld")
        buf.add_chunk(0, b"hel")
        buf.add_chunk(1, b"lo ")
        self.assertEqual(buf.assemble(), b"hello wld")

    def test_duplicate_chunk_returns_false(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=2, started_at=time.time()
        )
        self.assertTrue(buf.add_chunk(0, b"a"))
        self.assertFalse(buf.add_chunk(0, b"a"))  # duplicate

    def test_assemble_missing_chunk_raises(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=3, started_at=time.time()
        )
        buf.add_chunk(0, b"a")
        buf.add_chunk(2, b"c")
        with self.assertRaises(ValueError):
            buf.assemble()

    def test_expiration(self):
        buf = ReassemblyBuffer(
            drone_id="DRN-001", session_id=1, total_chunks=1,
            started_at=time.time() - 100,
        )
        self.assertTrue(buf.is_expired(timeout_seconds=30))
        self.assertFalse(buf.is_expired(timeout_seconds=200))


class TestPacketReceiverEndToEnd(unittest.TestCase):

    def test_in_order_reassembly(self):
        h = _CapturingReceiverHarness()
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            for p in packets:
                h.send(p)
            self.assertTrue(h.wait_for_received(1), "submission was not reassembled")
            sub = h.received[0]
            self.assertEqual(sub["drone_id"], "DRN-001")
            self.assertEqual(len(sub["payloads"]), 1)
        finally:
            h.stop()

    def test_out_of_order_reassembly(self):
        h = _CapturingReceiverHarness()
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            # Send START, then chunks reversed, then END
            h.send(packets[0])
            for p in reversed(packets[1:-1]):
                h.send(p)
            h.send(packets[-1])
            self.assertTrue(h.wait_for_received(1))
        finally:
            h.stop()

    def test_missing_chunk_triggers_truncation_on_session_end(self):
        h = _CapturingReceiverHarness(
            session_timeout_seconds=10.0,
        )
        try:
            # Build a multi-chunk submission by inflating additional_metadata
            sub = _minimal_submission()
            sub["additional_metadata"] = {"big": "x" * 5000}
            _, packets = _build_session_packets(sub, "DRN-001", KEY_001, chunk_size=512)
            self.assertGreater(len(packets), 4)  # need >1 chunk
            # Send START, all chunks except one, then END
            h.send(packets[0])
            for p in packets[1:-2]:  # skip the second-to-last chunk
                h.send(p)
            h.send(packets[-1])  # SESSION_END
            time.sleep(0.3)
            self.assertEqual(len(h.received), 0)
            self.assertGreaterEqual(h.receiver.stats.sessions_truncated, 1)
        finally:
            h.stop()

    def test_replay_protection_drops_duplicate_chunk(self):
        # Need a multi-chunk submission so we can replay one CHUNK while
        # the session is still open (eager finalization closes the session
        # the moment all expected chunks arrive).
        h = _CapturingReceiverHarness()
        try:
            sub = _minimal_submission()
            sub["additional_metadata"] = {"big": "x" * 3000}
            _, packets = _build_session_packets(
                sub, "DRN-001", KEY_001, chunk_size=512,
            )
            # packets = [START, CHUNK0, CHUNK1, ..., END]
            self.assertGreater(len(packets) - 2, 1)
            h.send(packets[0])         # START
            h.send(packets[1])         # CHUNK 0
            h.send(packets[1])         # duplicate CHUNK 0 (replay)
            for p in packets[2:]:      # remaining CHUNKs + END
                h.send(p)
            self.assertTrue(h.wait_for_received(1))
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_replay, 1)
        finally:
            h.stop()

    def test_hmac_mismatch_dropped(self):
        h = _CapturingReceiverHarness(key_store={"DRN-001": "wrong_key"})
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            for p in packets:
                h.send(p)
            time.sleep(0.3)
            self.assertEqual(len(h.received), 0)
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_hmac, 1)
        finally:
            h.stop()

    def test_unknown_drone_dropped_when_hmac_required(self):
        h = _CapturingReceiverHarness(key_store={})  # no keys
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            for p in packets:
                h.send(p)
            time.sleep(0.3)
            self.assertEqual(len(h.received), 0)
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_unknown_drone, 1)
        finally:
            h.stop()

    def test_orphaned_chunk_when_session_start_missing(self):
        h = _CapturingReceiverHarness()
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            # Drop SESSION_START — send only chunks
            for p in packets[1:]:
                h.send(p)
            time.sleep(0.3)
            self.assertEqual(len(h.received), 0)
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_orphaned, 1)
        finally:
            h.stop()

    def test_two_concurrent_sessions_from_different_drones(self):
        h = _CapturingReceiverHarness(
            key_store={"DRN-001": KEY_001, "DRN-002": "shared_secret_002"},
        )
        try:
            _, p1 = _build_session_packets(_minimal_submission("DRN-001"), "DRN-001", KEY_001)
            _, p2 = _build_session_packets(
                _minimal_submission("DRN-002"), "DRN-002", "shared_secret_002"
            )
            # Interleave the two streams
            for a, b in zip(p1, p2):
                h.send(a)
                h.send(b)
            self.assertTrue(h.wait_for_received(2))
            ids = {s["drone_id"] for s in h.received}
            self.assertEqual(ids, {"DRN-001", "DRN-002"})
        finally:
            h.stop()

    def test_session_too_many_chunks_rejected(self):
        h = _CapturingReceiverHarness(max_session_chunks=4)
        try:
            sub = _minimal_submission()
            sub["additional_metadata"] = {"big": "x" * 6000}
            _, packets = _build_session_packets(sub, "DRN-001", KEY_001, chunk_size=512)
            self.assertGreater(len(packets) - 2, 4)  # >4 CHUNK packets
            h.send(packets[0])  # SESSION_START with too many total_chunks
            time.sleep(0.2)
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_malformed, 1)
            self.assertEqual(h.receiver.stats.sessions_started, 0)
        finally:
            h.stop()

    def test_late_session_end_after_eager_finalize_is_benign(self):
        h = _CapturingReceiverHarness()
        try:
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            for p in packets:
                h.send(p)
            self.assertTrue(h.wait_for_received(1))
            stats = h.receiver.stats
            # SESSION_END arrived but session was already eagerly finalized
            self.assertEqual(stats.packets_dropped_malformed, 0)
            self.assertEqual(stats.packets_dropped_orphaned, 0)
        finally:
            h.stop()

    def test_duplicate_session_start_dropped_as_malformed(self):
        # An attacker (or buggy client) sending a second SESSION_START
        # for an active session must NOT be able to overwrite the
        # legitimate drone's reassembly buffer.
        h = _CapturingReceiverHarness()
        try:
            sub = _minimal_submission()
            sub["additional_metadata"] = {"big": "x" * 3000}
            _, packets = _build_session_packets(
                sub, "DRN-001", KEY_001, chunk_size=512,
            )
            h.send(packets[0])  # legitimate SESSION_START
            h.send(packets[0])  # duplicate — must be rejected
            for p in packets[1:]:
                h.send(p)
            self.assertTrue(h.wait_for_received(1))
            self.assertGreaterEqual(h.receiver.stats.packets_dropped_malformed, 1)
            self.assertEqual(h.receiver.stats.sessions_started, 1)
        finally:
            h.stop()

    def test_periodic_gc_runs_under_continuous_traffic(self):
        # With session_timeout small and steady traffic, the GC must fire
        # even when recvfrom never times out, so half-open sessions don't
        # accumulate.
        h = _CapturingReceiverHarness(session_timeout_seconds=0.2)
        try:
            # Open a session but never finish it
            _, packets = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
            h.send(packets[0])  # SESSION_START only — half-open
            # Now drive continuous traffic to keep recvfrom busy. Each
            # iteration sends a fresh complete session.
            for _ in range(20):
                _, p = _build_session_packets(_minimal_submission(), "DRN-001", KEY_001)
                for pkt in p:
                    h.send(pkt)
                time.sleep(0.05)
            # The half-open session should have been GC'd by now.
            time.sleep(0.5)
            self.assertGreaterEqual(h.receiver.stats.sessions_expired, 1)
        finally:
            h.stop()


class TestInterceptorPacketIntegration(unittest.TestCase):
    """Verify that the IngestionInterceptor's start_packet_listener wires
    everything up: packets in → process() pipeline runs → stats update."""

    def test_end_to_end_via_interceptor(self):
        interceptor = IngestionInterceptor(
            config=InterceptorConfig(verify_checksums=False),
            device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
            zone_risk_lookup={"zone-alpha": 0.4},
            key_store={"DRN-001": KEY_001},
        )
        interceptor.start_packet_listener(host="127.0.0.1", port=0)
        try:
            host, port = interceptor.packet_receiver.bound_address
            sub = _minimal_submission()
            sub["mission_zone"] = "zone-alpha"
            _, packets = _build_session_packets(sub, "DRN-001", KEY_001)

            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for p in packets:
                    client.sendto(p, (host, port))
            finally:
                client.close()

            # Wait for the pipeline to run
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if interceptor.stats["total_processed"] >= 1:
                    break
                time.sleep(0.01)

            self.assertEqual(interceptor.stats["total_processed"], 1)
            self.assertEqual(interceptor.stats["total_rejected"], 0)
            self.assertEqual(interceptor.packet_stats.sessions_completed, 1)
        finally:
            interceptor.stop_packet_listener()


if __name__ == "__main__":
    unittest.main()
