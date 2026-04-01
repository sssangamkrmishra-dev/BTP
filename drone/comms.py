"""
Communication layer: handles signing, formatting, and transmitting
drone submissions to the ingestion interceptor.
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

logger = logging.getLogger(__name__)


class DroneTransmitter:
    """
    Handles drone-to-edge communication.

    Responsibilities:
        - Format payloads into the DroneSubmission JSON schema
        - Sign submissions with HMAC-SHA256 (if signing enabled)
        - Transmit submissions to the ingestion interceptor (direct call or queue)
        - Log transmission events for audit
    """

    def __init__(self, config: DroneConfig):
        self.config = config
        self._transmission_log: List[Dict[str, Any]] = []

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

        # Sign if enabled
        if self.config.signing_enabled and self.config.signing_key:
            submission["signature"] = self._sign_submission(submission)

        return submission

    def transmit(
        self,
        submission: Dict[str, Any],
        interceptor: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Transmit a submission to the ingestion interceptor.

        If an interceptor instance is provided, calls its process() method
        directly (in-process integration). Otherwise, logs the submission
        for later retrieval.

        Args:
            submission: The formatted drone submission dict.
            interceptor: Optional IngestionInterceptor instance.

        Returns:
            IngestResult if interceptor is provided, None otherwise.
        """
        tx_record = {
            "drone_id": submission.get("drone_id"),
            "timestamp": submission.get("timestamp"),
            "num_payloads": len(submission.get("payloads", [])),
            "transmitted_at": datetime.now(timezone.utc).isoformat(),
        }

        result = None
        if interceptor is not None:
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
