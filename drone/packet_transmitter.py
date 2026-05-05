"""
Drone-side packet transmitter.

Takes a DroneSubmission dict, marshals it to binary using the shared
submission codec, fragments the bytes into MAX_PAYLOAD_LEN chunks, signs
each packet with HMAC-SHA256, and sends them as UDP datagrams to the
ingestion interceptor.

Sequence per submission:
    1. Generate a random 64-bit session_id
    2. Encode the submission with submission_codec.encode_submission()
    3. Compute total_chunks = ceil(len(blob) / MAX_PAYLOAD_LEN)
    4. Send SESSION_START with total_chunks (payload = drone_id utf-8)
    5. Send total_chunks CHUNK packets, each with monotonic seq 0..N-1
    6. Send SESSION_END

Optional packet-loss simulation drops random packets before transmission
to exercise the receiver's truncation defenses end-to-end. The drone does
not retransmit — packet loss in the field is real and the receiver should
flag the security event.
"""

import logging
import math
import os
import random
import socket
import struct
from typing import Any, Dict, List, Optional

from ingestion_interceptor.protocol import (
    MAX_PAYLOAD_LEN,
    PacketHeader,
    PacketType,
    encode_packet,
    encode_submission,
)

logger = logging.getLogger(__name__)


class DronePacketTransmitter:
    """
    Wire-level transmitter for one drone.

    Stateless across submissions — every send() call opens a fresh
    session. The UDP socket is created on construction and reused.
    """

    def __init__(
        self,
        drone_id: str,
        host: str,
        port: int,
        hmac_key: str,
        chunk_size: int = MAX_PAYLOAD_LEN,
        simulate_packet_loss: float = 0.0,
    ):
        if not drone_id:
            raise ValueError("drone_id required")
        if not hmac_key:
            raise ValueError("hmac_key required (HMAC is mandatory)")
        if chunk_size <= 0 or chunk_size > MAX_PAYLOAD_LEN:
            raise ValueError(
                f"chunk_size must be in (0, {MAX_PAYLOAD_LEN}]"
            )
        if not 0.0 <= simulate_packet_loss <= 1.0:
            raise ValueError("simulate_packet_loss must be in [0.0, 1.0]")

        self._drone_id = drone_id
        self._host = host
        self._port = port
        self._hmac_key = hmac_key.encode("utf-8")
        self._chunk_size = chunk_size
        self._simulate_packet_loss = simulate_packet_loss

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self._packets_sent = 0
        self._packets_dropped_simulated = 0
        self._sessions_sent = 0
        self._bytes_sent = 0

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "sessions_sent": self._sessions_sent,
            "packets_sent": self._packets_sent,
            "packets_dropped_simulated": self._packets_dropped_simulated,
            "bytes_sent": self._bytes_sent,
        }

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def send(self, submission: Dict[str, Any]) -> int:
        """
        Encode the submission, fragment it, and send all packets.

        Returns the number of packets actually emitted onto the wire
        (excluding any dropped by the loss simulator).
        """
        # 1. Marshal to binary
        blob = encode_submission(submission)
        total_chunks = max(1, math.ceil(len(blob) / self._chunk_size))

        # 2. Generate session_id (random 64-bit)
        session_id = struct.unpack("!Q", os.urandom(8))[0]

        # 3. Build all packets
        packets: List[bytes] = []

        # SESSION_START — payload carries drone_id so the receiver can
        # look up the HMAC key on every subsequent CHUNK
        start_header = PacketHeader(
            packet_type=PacketType.SESSION_START,
            session_id=session_id,
            seq=0,
            total_chunks=total_chunks,
        )
        packets.append(
            encode_packet(start_header, self._drone_id.encode("utf-8"), self._hmac_key)
        )

        # CHUNK packets
        for i in range(total_chunks):
            chunk = blob[i * self._chunk_size : (i + 1) * self._chunk_size]
            chunk_header = PacketHeader(
                packet_type=PacketType.CHUNK,
                session_id=session_id,
                seq=i,
                total_chunks=0,
            )
            packets.append(encode_packet(chunk_header, chunk, self._hmac_key))

        # SESSION_END
        end_header = PacketHeader(
            packet_type=PacketType.SESSION_END,
            session_id=session_id,
            seq=total_chunks,
            total_chunks=0,
        )
        packets.append(encode_packet(end_header, b"", self._hmac_key))

        # 4. Transmit (with optional packet-loss simulation)
        actually_sent = 0
        for pkt in packets:
            if (
                self._simulate_packet_loss > 0.0
                and random.random() < self._simulate_packet_loss
            ):
                self._packets_dropped_simulated += 1
                logger.debug(
                    "simulated packet loss: drone=%s session=0x%x",
                    self._drone_id, session_id,
                )
                continue
            self._sock.sendto(pkt, (self._host, self._port))
            actually_sent += 1
            self._bytes_sent += len(pkt)

        self._packets_sent += actually_sent
        self._sessions_sent += 1
        logger.info(
            "drone=%s sent session=0x%x: %d/%d packets, %d bytes total",
            self._drone_id, session_id, actually_sent, len(packets), len(blob),
        )
        return actually_sent
