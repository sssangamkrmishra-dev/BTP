"""
Communication layer: handles signing, formatting, and transmitting
drone submissions to the ingestion interceptor.

Two transports are supported, selected by config.transport_mode:

  * "in_process" — call interceptor.process(submission) directly. Used
    for unit tests and the original integration demo. Synchronous, returns
    the IngestResult immediately.

  * "packet" — fragment the submission into UDP packets and send them
    over the wire to a PacketReceiver. Asynchronous, fire-and-forget,
    matches how real drones push data to an edge node.
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import DroneConfig
from .models import CapturedPayload, DroneState
from .packet_transmitter import DronePacketTransmitter

logger = logging.getLogger(__name__)


class DroneTransmitter:
    """
    Handles drone-to-edge communication.

    Responsibilities:
        - Format payloads into the DroneSubmission JSON schema
        - Sign submissions with HMAC-SHA256 (if signing enabled)
        - Transmit submissions to the ingestion interceptor (direct call,
          UDP packets, or queue)
        - Log transmission events for audit
    """

    def __init__(self, config: DroneConfig):
        self.config = config
        self._transmission_log: List[Dict[str, Any]] = []
        self._packet_tx: Optional[DronePacketTransmitter] = None
        if config.transport_mode == "packet":
            if not config.signing_key:
                raise ValueError(
                    "transport_mode='packet' requires signing_key to be set "
                    "(used as the per-packet HMAC key)"
                )
            self._packet_tx = DronePacketTransmitter(
                drone_id=config.drone_id,
                host=config.interceptor_host,
                port=config.interceptor_port,
                hmac_key=config.signing_key,
                chunk_size=config.packet_chunk_size,
                simulate_packet_loss=config.simulate_packet_loss,
            )

    def build_submission(
        self,
        state: DroneState,
        payloads: List[CapturedPayload],
        mission_id: str = "",
        mission_zone: str = "",
        additional_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a drone submission JSON in the exact format expected by
        the Ingestion Interceptor.

        This is the contract between the drone and the ingestion pipeline.
        """
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        submission: Dict[str, Any] = {
            "drone_id": self.config.drone_id,
            "timestamp": timestamp,
            "mission_id": mission_id or f"MSN-{int(time.time()) % 10000:04d}",
            "mission_zone": mission_zone or self.config.default_mission_zone,
            "geo": state.position.to_dict(),
            "payloads": [p.to_submission_dict() for p in payloads],
            "telemetry": state.telemetry_dict(),
            "signature": None,
            "firmware_version": self.config.firmware_version,
            "operator_id": self.config.operator_id,
            "additional_metadata": additional_metadata or {
                "camera_model": self.config.camera_model,
                "platform_model": self.config.platform_model,
                "frame_rate": self.config.video_fps,
            },
        }

        # Sign if enabled — but only in in_process mode. In packet mode the
        # per-packet HMAC tag is the wire authentication, and the submission
        # round-trips through a binary codec that coerces additional_metadata
        # values to strings, which would invalidate any application-level
        # signature on the receiving side.
        if (
            self.config.signing_enabled
            and self.config.signing_key
            and self.config.transport_mode != "packet"
        ):
            submission["signature"] = self._sign_submission(submission)

        return submission

    def transmit(
        self,
        submission: Dict[str, Any],
        interceptor: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Transmit a submission to the ingestion interceptor.

        Behaviour depends on config.transport_mode:

          * "in_process": calls interceptor.process(submission) directly
            and returns the IngestResult. The interceptor argument is
            required.

          * "packet": fragments the submission into UDP packets and sends
            them via the DronePacketTransmitter. Fire-and-forget — returns
            None. The interceptor argument is ignored.

        Args:
            submission: The formatted drone submission dict.
            interceptor: IngestionInterceptor instance (required for in_process,
                ignored for packet).

        Returns:
            IngestResult if in_process mode, None for packet mode.
        """
        tx_record: Dict[str, Any] = {
            "drone_id": submission.get("drone_id"),
            "timestamp": submission.get("timestamp"),
            "num_payloads": len(submission.get("payloads", [])),
            "transmitted_at": datetime.now(timezone.utc).isoformat(),
            "transport": self.config.transport_mode,
        }

        result = None

        if self.config.transport_mode == "packet":
            assert self._packet_tx is not None
            try:
                num_pkts = self._packet_tx.send(submission)
                tx_record["delivered"] = True
                tx_record["packets_sent"] = num_pkts
                logger.info(
                    "Transmitted via packets: %s -> %d packets",
                    submission.get("drone_id"), num_pkts,
                )
            except Exception as e:
                tx_record["delivered"] = False
                tx_record["error"] = str(e)
                logger.error("Packet transmission failed: %s", e)
        elif interceptor is not None:
            try:
                result = interceptor.process(submission)
                tx_record["delivered"] = True
                tx_record["ingest_success"] = result.success
                if result.success:
                    tx_record["ingest_id"] = result.ingest_metadata.ingest_id
                else:
                    tx_record["errors"] = result.errors
                logger.info(
                    "Transmitted to interceptor: %s -> %s",
                    submission.get("drone_id"),
                    "OK" if result.success else result.errors,
                )
            except Exception as e:
                tx_record["delivered"] = False
                tx_record["error"] = str(e)
                logger.error("Transmission failed: %s", e)
        else:
            tx_record["delivered"] = False
            tx_record["queued"] = True
            logger.debug("Submission queued (no interceptor connected)")

        self._transmission_log.append(tx_record)
        return result

    @property
    def packet_transmitter(self) -> Optional[DronePacketTransmitter]:
        """Direct access to the underlying packet transmitter (if any)."""
        return self._packet_tx

    def close(self) -> None:
        """Release the packet socket if one is held."""
        if self._packet_tx is not None:
            self._packet_tx.close()
            self._packet_tx = None

    @property
    def transmission_log(self) -> List[Dict[str, Any]]:
        """Return the transmission audit log."""
        return list(self._transmission_log)

    # ── Private ────────────────────────────────────────────────────────

    def _sign_submission(self, submission: Dict[str, Any]) -> str:
        """Sign the submission payload with HMAC-SHA256."""
        # Canonical serialization for signing
        payload_for_signing = json.dumps(
            {k: v for k, v in submission.items() if k != "signature"},
            sort_keys=True,
        ).encode("utf-8")

        sig = hmac.new(
            self.config.signing_key.encode("utf-8"),
            payload_for_signing,
            hashlib.sha256,
        ).hexdigest()

        return f"{self.config.signing_algorithm}:{sig}"
