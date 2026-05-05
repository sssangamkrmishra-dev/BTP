"""
UDP packet receiver and reassembly buffer for the Ingestion Interceptor.

This module sits in front of the existing 7-stage pipeline as Stage 0:
Packet Reception. It listens on a UDP socket, verifies HMAC tags,
reassembles fragmented submissions, and hands the reconstructed
DroneSubmission dict to a callback (the existing interceptor.process()).

Threading model:
    A daemon thread blocks on socket.recvfrom() and dispatches packets
    synchronously. The on_submission callback runs on this same thread,
    so callers should avoid long-running work in the callback (the
    interceptor's process() takes ~1ms for metadata-only work and is
    fine here).

Security defenses (Stage 0 of the pipeline):
    - Magic byte + version verification (codec layer)
    - Per-packet HMAC-SHA256 (codec layer)
    - Per-session monotonic seq + duplicate detection
    - Reassembly timeout (drops half-open sessions)
    - Max concurrent sessions per drone (DoS bound)
    - Max chunks per session (memory bound)
    - Sequence-gap detection at SESSION_END (truncation attacks)
"""

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .protocol import (
    HmacMismatch,
    MalformedPacket,
    PacketHeader,
    PacketType,
    UnsupportedVersion,
    decode_submission,
)
from .protocol.codec import decode_packet_unverified, verify_hmac
from .protocol.errors import MalformedSubmission

logger = logging.getLogger(__name__)


# ── Statistics ─────────────────────────────────────────────────────────

@dataclass
class PacketReceiverStats:
    """
    Counters for the packet receiver. Surfaced via interceptor.packet_stats.

    Drop categories distinguish *why* a packet was rejected so operators
    can tell apart benign network loss from attack indicators:

      packets_dropped_malformed   bad magic / version / truncated / oversize
                                  → attack indicator or misconfigured client
      packets_dropped_hmac        HMAC tag did not verify
                                  → wire tampering, MITM, or wrong key
      packets_dropped_unknown_drone   no key configured for drone_id
                                  → unauthorized device
      packets_dropped_replay      duplicate seq within an active session
                                  → pcap replay or buggy retransmit
      packets_dropped_orphaned    CHUNK arrived for an unknown session_id
                                  → typically benign: SESSION_START was
                                    lost to packet loss; can also indicate
                                    a session-id guessing attack
      packets_dropped_session_overflow  too many concurrent sessions per
                                  drone → DoS attempt
    """

    packets_received: int = 0
    packets_dropped_malformed: int = 0
    packets_dropped_hmac: int = 0
    packets_dropped_unknown_drone: int = 0
    packets_dropped_replay: int = 0
    packets_dropped_orphaned: int = 0
    packets_dropped_session_overflow: int = 0
    sessions_started: int = 0
    sessions_completed: int = 0
    sessions_expired: int = 0
    sessions_truncated: int = 0
    submissions_decoded: int = 0
    submissions_decode_failed: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "packets_received": self.packets_received,
            "packets_dropped_malformed": self.packets_dropped_malformed,
            "packets_dropped_hmac": self.packets_dropped_hmac,
            "packets_dropped_unknown_drone": self.packets_dropped_unknown_drone,
            "packets_dropped_replay": self.packets_dropped_replay,
            "packets_dropped_orphaned": self.packets_dropped_orphaned,
            "packets_dropped_session_overflow": self.packets_dropped_session_overflow,
            "sessions_started": self.sessions_started,
            "sessions_completed": self.sessions_completed,
            "sessions_expired": self.sessions_expired,
            "sessions_truncated": self.sessions_truncated,
            "submissions_decoded": self.submissions_decoded,
            "submissions_decode_failed": self.submissions_decode_failed,
        }


# ── Reassembly buffer ──────────────────────────────────────────────────

@dataclass
class ReassemblyBuffer:
    """
    Per-session state for reassembling a fragmented submission.

    Keyed by (drone_id, session_id). Holds the chunks indexed by seq,
    the expected total, and creation timestamp for timeout enforcement.
    """

    drone_id: str
    session_id: int
    total_chunks: int
    started_at: float
    chunks: Dict[int, bytes] = field(default_factory=dict)

    def add_chunk(self, seq: int, payload: bytes) -> bool:
        """
        Add a chunk to the buffer. Returns True if this seq was new,
        False if it was a duplicate (replay).
        """
        if seq in self.chunks:
            return False
        self.chunks[seq] = payload
        return True

    def is_complete(self) -> bool:
        """All expected chunks present (eager-reassembly trigger)."""
        if self.total_chunks == 0:
            return False
        return len(self.chunks) == self.total_chunks

    def is_expired(self, timeout_seconds: float, now: Optional[float] = None) -> bool:
        if now is None:
            now = time.time()
        return (now - self.started_at) > timeout_seconds

    def assemble(self) -> bytes:
        """
        Concatenate chunks in seq order. Raises ValueError if any expected
        chunk is missing — caller should treat this as `incomplete_packet_stream`.
        """
        if self.total_chunks == 0:
            raise ValueError("session has no expected chunk count")
        out = bytearray()
        for i in range(self.total_chunks):
            if i not in self.chunks:
                raise ValueError(f"missing chunk seq={i}")
            out += self.chunks[i]
        return bytes(out)


# ── Packet receiver ────────────────────────────────────────────────────

class PacketReceiver:
    """
    UDP packet receiver that runs in a daemon thread.

    Lifecycle:
        receiver = PacketReceiver(
            host="0.0.0.0", port=5005,
            key_store={"DRN-001": "shared_secret"},
            on_submission=interceptor.process,
        )
        receiver.start()
        ...
        receiver.stop()

    The on_submission callback receives a dict in the same shape that
    interceptor.process() expects (the same shape decoded by
    submission_codec.decode_submission).
    """

    # Hard caps — also surfaced via InterceptorConfig but enforced here
    # for safety even if config values are misset.
    _SOCKET_RECV_TIMEOUT_S: float = 0.5  # poll interval for stop()
    _GC_INTERVAL_S: float = 1.0          # max wall-clock between GC passes

    def __init__(
        self,
        host: str,
        port: int,
        key_store: Dict[str, str],
        on_submission: Callable[[Dict], None],
        max_session_chunks: int = 256,
        max_concurrent_sessions: int = 100,
        session_timeout_seconds: float = 30.0,
        require_hmac: bool = True,
    ):
        self._host = host
        self._port = port
        self._key_store = key_store
        self._on_submission = on_submission
        self._max_session_chunks = max_session_chunks
        self._max_concurrent_sessions = max_concurrent_sessions
        self._session_timeout_seconds = session_timeout_seconds
        self._require_hmac = require_hmac

        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        # Sessions are keyed by (drone_id, session_id). The session_id
        # alone is NOT a unique key — two drones could (very improbably)
        # pick the same random 64-bit id. Lookup-by-id-only therefore
        # scans this dict under _sessions_lock; the cost is O(active
        # sessions) which is bounded by max_concurrent_sessions × num
        # drones (default 100 × N).
        self._sessions: Dict[Tuple[str, int], ReassemblyBuffer] = {}
        self._sessions_lock = threading.Lock()
        self._stats = PacketReceiverStats()
        self._last_gc_at: float = time.time()

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def stats(self) -> PacketReceiverStats:
        return self._stats

    @property
    def bound_address(self) -> Tuple[str, int]:
        """Returns (host, port) the socket is actually bound to."""
        if self._sock is None:
            return (self._host, self._port)
        return self._sock.getsockname()

    def start(self) -> None:
        """Bind the socket and launch the listener thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.settimeout(self._SOCKET_RECV_TIMEOUT_S)
        self._running.set()
        self._thread = threading.Thread(
            target=self._listen_loop,
            name=f"PacketReceiver-{self._port}",
            daemon=True,
        )
        self._thread.start()
        bound = self._sock.getsockname()
        logger.info("PacketReceiver listening on %s:%d", bound[0], bound[1])

    def stop(self, join_timeout: float = 2.0) -> None:
        """Signal the listener thread to exit and close the socket."""
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        logger.info("PacketReceiver stopped")

    def update_key_store(self, key_store: Dict[str, str]) -> None:
        """Replace the key store (e.g., after device registry changes)."""
        self._key_store = key_store

    # ── Listener loop ──────────────────────────────────────────────────

    def _listen_loop(self) -> None:
        """Block on recvfrom and dispatch packets until stopped."""
        assert self._sock is not None
        while self._running.is_set():
            try:
                raw, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                # Periodic janitor pass for expired sessions
                self._maybe_run_gc()
                continue
            except OSError:
                # socket closed during stop() — exit cleanly
                break

            self._stats.packets_received += 1
            try:
                self._handle_packet(raw, addr)
            except Exception as e:  # pragma: no cover - safety net
                logger.exception("packet handler crashed: %s", e)
            # Run GC even under continuous traffic so half-open sessions
            # can't accumulate when recvfrom never times out.
            self._maybe_run_gc()

    # ── Packet dispatch ────────────────────────────────────────────────

    def _handle_packet(self, raw: bytes, addr: Tuple[str, int]) -> None:
        """Validate, HMAC-verify, and dispatch a single packet."""
        try:
            header, payload, tag = decode_packet_unverified(raw)
        except (MalformedPacket, UnsupportedVersion) as e:
            self._stats.packets_dropped_malformed += 1
            logger.warning("malformed packet from %s: %s", addr, e)
            return

        # SESSION_START packets carry the drone_id in the payload (utf-8).
        # CHUNK and SESSION_END packets do not, so we resolve the drone_id
        # by scanning active sessions for one whose session_id matches.
        # The scan is bounded by the per-drone session cap × num drones
        # (default 100×N) and runs under the sessions lock for consistency
        # with the writer paths.
        if header.packet_type == PacketType.SESSION_START:
            drone_id = payload.decode("utf-8", errors="replace")
        else:
            drone_id = self._lookup_drone_for_session(header.session_id)
            if drone_id is None:
                # SESSION_END for an already-finalized session is benign
                # (eager reassembly may have run before SESSION_END arrived).
                # Silently ignore.
                if header.packet_type == PacketType.SESSION_END:
                    logger.debug(
                        "late SESSION_END for finalized session_id=0x%x",
                        header.session_id,
                    )
                    return
                # CHUNK for an unknown session: orphaned. Most commonly the
                # SESSION_START was dropped to packet loss. Could also be
                # session-id guessing — log it but don't classify as malformed.
                self._stats.packets_dropped_orphaned += 1
                logger.debug(
                    "orphaned packet for unknown session_id=0x%x from %s",
                    header.session_id, addr,
                )
                return

        # Look up key
        key_str = self._key_store.get(drone_id)
        if not key_str:
            if self._require_hmac:
                self._stats.packets_dropped_unknown_drone += 1
                logger.warning(
                    "no HMAC key for drone_id=%s from %s",
                    drone_id, addr,
                )
                return
            # No-key sandbox mode: skip verification
        else:
            try:
                verify_hmac(header, payload, tag, key_str.encode("utf-8"))
            except HmacMismatch:
                self._stats.packets_dropped_hmac += 1
                logger.warning(
                    "HMAC mismatch for drone_id=%s session=0x%x seq=%d from %s",
                    drone_id, header.session_id, header.seq, addr,
                )
                return

        # Dispatch by type
        if header.packet_type == PacketType.SESSION_START:
            self._handle_session_start(header, drone_id)
        elif header.packet_type == PacketType.CHUNK:
            self._handle_chunk(header, payload, drone_id)
        elif header.packet_type == PacketType.SESSION_END:
            self._handle_session_end(header, drone_id)

    def _handle_session_start(self, header: PacketHeader, drone_id: str) -> None:
        """Open a new reassembly buffer for this session."""
        if header.total_chunks == 0:
            self._stats.packets_dropped_malformed += 1
            logger.warning(
                "SESSION_START with total_chunks=0 from drone_id=%s", drone_id
            )
            return
        if header.total_chunks > self._max_session_chunks:
            self._stats.packets_dropped_malformed += 1
            logger.warning(
                "SESSION_START total_chunks=%d exceeds max %d from drone_id=%s",
                header.total_chunks, self._max_session_chunks, drone_id,
            )
            return

        with self._sessions_lock:
            key = (drone_id, header.session_id)
            if key in self._sessions:
                # Duplicate SESSION_START for an already-open session is
                # treated as a security event: an attacker who guessed an
                # active session_id could otherwise overwrite a legitimate
                # drone's reassembly buffer. The legitimate buffer stays
                # intact and the duplicate START is dropped.
                self._stats.packets_dropped_malformed += 1
                logger.warning(
                    "duplicate SESSION_START for drone=%s session_id=0x%x",
                    drone_id, header.session_id,
                )
                return

            # Per-drone concurrent session bound
            active_for_drone = sum(
                1 for (d, _) in self._sessions if d == drone_id
            )
            if active_for_drone >= self._max_concurrent_sessions:
                self._stats.packets_dropped_session_overflow += 1
                logger.warning(
                    "drone_id=%s exceeded max concurrent sessions (%d)",
                    drone_id, self._max_concurrent_sessions,
                )
                return

            self._sessions[key] = ReassemblyBuffer(
                drone_id=drone_id,
                session_id=header.session_id,
                total_chunks=header.total_chunks,
                started_at=time.time(),
            )

        self._stats.sessions_started += 1
        logger.debug(
            "session started: drone=%s session_id=0x%x total_chunks=%d",
            drone_id, header.session_id, header.total_chunks,
        )

    def _handle_chunk(
        self, header: PacketHeader, payload: bytes, drone_id: str
    ) -> None:
        """Add a chunk to its session buffer; eager-assemble when complete."""
        key = (drone_id, header.session_id)
        with self._sessions_lock:
            buf = self._sessions.get(key)
            if buf is None:
                # CHUNK arrived before SESSION_START — drop
                self._stats.packets_dropped_malformed += 1
                logger.warning(
                    "CHUNK for unknown session: drone=%s session_id=0x%x",
                    drone_id, header.session_id,
                )
                return

            if header.seq >= buf.total_chunks:
                self._stats.packets_dropped_malformed += 1
                logger.warning(
                    "CHUNK seq %d >= total_chunks %d (drone=%s)",
                    header.seq, buf.total_chunks, drone_id,
                )
                return

            is_new = buf.add_chunk(header.seq, payload)
            if not is_new:
                self._stats.packets_dropped_replay += 1
                logger.debug(
                    "replay/duplicate CHUNK seq=%d (drone=%s)",
                    header.seq, drone_id,
                )
                return

            complete = buf.is_complete()
        # Assemble outside the lock to avoid blocking other packets
        if complete:
            self._finalize_session(key, source="eager")

    def _handle_session_end(self, header: PacketHeader, drone_id: str) -> None:
        """Explicit close — assemble even if partial (will fail truncated)."""
        key = (drone_id, header.session_id)
        with self._sessions_lock:
            if key not in self._sessions:
                # Session already finalized eagerly
                return
        self._finalize_session(key, source="session_end")

    def _finalize_session(
        self, key: Tuple[str, int], source: str
    ) -> None:
        """
        Pop the session, attempt reassembly, and dispatch to the callback.
        Handles eager-completion, SESSION_END, and timeout-flush paths.
        """
        with self._sessions_lock:
            buf = self._sessions.pop(key, None)
            if buf is None:
                return

        # Try assembly
        try:
            blob = buf.assemble()
        except ValueError as e:
            self._stats.sessions_truncated += 1
            logger.warning(
                "incomplete_packet_stream drone=%s session_id=0x%x source=%s: %s",
                buf.drone_id, buf.session_id, source, e,
            )
            return

        # Decode the binary submission
        try:
            submission = decode_submission(blob)
        except MalformedSubmission as e:
            self._stats.submissions_decode_failed += 1
            logger.warning(
                "malformed_submission drone=%s session_id=0x%x: %s",
                buf.drone_id, buf.session_id, e,
            )
            return

        self._stats.sessions_completed += 1
        self._stats.submissions_decoded += 1
        logger.info(
            "session reassembled drone=%s session_id=0x%x bytes=%d source=%s",
            buf.drone_id, buf.session_id, len(blob), source,
        )

        # Hand off to the callback (interceptor.process)
        try:
            self._on_submission(submission)
        except Exception as e:  # pragma: no cover - callback safety net
            logger.exception("on_submission callback raised: %s", e)

    def _lookup_drone_for_session(self, session_id: int) -> Optional[str]:
        """
        Find the drone_id of an active session with this session_id.
        Returns None if no such session exists. Called from the listener
        thread under the sessions lock to avoid races with start/finalize.
        """
        with self._sessions_lock:
            for (drone_id, sid) in self._sessions.keys():
                if sid == session_id:
                    return drone_id
        return None

    def _maybe_run_gc(self) -> None:
        """
        Run GC if at least _GC_INTERVAL_S has elapsed since the last pass.
        This makes GC fire under continuous traffic (when recvfrom never
        times out) as well as during quiet periods.
        """
        now = time.time()
        if now - self._last_gc_at < self._GC_INTERVAL_S:
            return
        self._last_gc_at = now
        self._gc_expired_sessions(now=now)

    def _gc_expired_sessions(self, now: Optional[float] = None) -> None:
        """Drop sessions that have outlived their timeout."""
        if now is None:
            now = time.time()
        expired: List[Tuple[str, int]] = []
        with self._sessions_lock:
            for k, buf in self._sessions.items():
                if buf.is_expired(self._session_timeout_seconds, now):
                    expired.append(k)
            for k in expired:
                self._sessions.pop(k, None)
        for k in expired:
            self._stats.sessions_expired += 1
            logger.warning(
                "session expired drone=%s session_id=0x%x", k[0], k[1]
            )
