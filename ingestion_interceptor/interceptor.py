"""
Main Ingestion Interceptor orchestrator.
Ties together validation, authentication, metadata extraction,
payload analysis, checksum verification, and artifact management.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .artifact_manager import create_artifact_record, generate_ingest_id
from .authenticator import AuthResult, Authenticator, DeviceRegistry, SignatureVerifier
from .checksum_verifier import compute_bytes_checksum, resolve_file_path, verify_checksum
from .config import InterceptorConfig
from .metadata_extractor import (
    extract_additional_metadata,
    extract_geo_metadata,
    extract_mission_context,
    extract_telemetry_summary,
)
from .models import ArtifactRecord, DroneSubmission, IngestMetadata, IngestResult, PayloadEntry
from .payload_analyzer import analyze_payload, compute_payload_risk_score, generate_threat_notes
from .uplink import UplinkCommandHandler, UplinkReceiver
from .validator import validate_submission

logger = logging.getLogger(__name__)


class IngestionInterceptor:
    """
    Core ingestion interceptor for drone/RPA data streams.

    Pipeline stages:
    1. Validate submission structure
    2. Authenticate source device
    3. Extract and normalize metadata
    4. Analyze each payload for security flags
    5. Verify file checksums (if files are accessible)
    6. Generate artifact records
    7. Produce structured ingest output for downstream modules

    The output feeds into the Game-Theoretic Threat Estimator.
    """

    def __init__(
        self,
        config: Optional[InterceptorConfig] = None,
        device_registry: Optional[Dict[str, Dict[str, Any]]] = None,
        zone_risk_lookup: Optional[Dict[str, float]] = None,
        key_store: Optional[Dict[str, str]] = None,
    ):
        self.config = config or InterceptorConfig()
        self._setup_logging()

        # Authentication
        registry = DeviceRegistry(registry=device_registry)
        sig_verifier = SignatureVerifier(key_store=key_store)
        self._authenticator = Authenticator(
            device_registry=registry,
            signature_verifier=sig_verifier,
            unknown_device_policy=self.config.unknown_device_policy,
        )

        # Zone risk
        self._zone_risk = dict(zone_risk_lookup) if zone_risk_lookup else {}

        # Uplink (optional)
        self._uplink_receiver = UplinkReceiver(mode="memory")
        self._uplink_handler = UplinkCommandHandler(
            authenticator=self._authenticator,
            zone_risk_lookup=self._zone_risk,
        )

        # Statistics
        self._stats = {
            "total_processed": 0,
            "total_rejected": 0,
            "total_flagged": 0,
        }

    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.config.log_level, logging.INFO),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

    def process(self, drone_json: Dict[str, Any]) -> IngestResult:
        """
        Process a single drone submission through the full ingestion pipeline.

        Args:
            drone_json: Raw drone submission as a dict.

        Returns:
            IngestResult with metadata, artifact records, or errors.
        """
        start_time = time.time()
        received_at = datetime.now(timezone.utc).isoformat()

        # --- Check uplink commands ---
        self._process_uplink_commands()

        # --- Stage 1: Validate ---
        errors, warnings = validate_submission(drone_json, self.config)
        if errors:
            self._stats["total_rejected"] += 1
            logger.warning("Validation failed for submission: %s", errors)
            return IngestResult(success=False, errors=errors, warnings=warnings)

        # --- Parse into structured model ---
        submission = DroneSubmission.from_dict(drone_json)
        ingest_id = generate_ingest_id()

        # --- Stage 2: Authenticate ---
        payload_hash = compute_bytes_checksum(
            json.dumps(drone_json, sort_keys=True).encode(), self.config.checksum_algorithm
        ) or ""
        auth_result = self._authenticator.authenticate(
            drone_id=submission.drone_id,
            signature=submission.signature,
            payload_hash=payload_hash,
        )

        if auth_result.status == "rejected":
            self._stats["total_rejected"] += 1
            logger.warning("Device rejected: %s", submission.drone_id)
            return IngestResult(
                success=False,
                errors=[f"device_rejected:{auth_result.details.get('reason', 'unknown')}"],
                warnings=warnings,
            )

        # --- Stage 3: Extract metadata ---
        mission_context = extract_mission_context(submission)
        geo_data = extract_geo_metadata(submission)
        telemetry_summary = extract_telemetry_summary(submission)
        additional_meta = extract_additional_metadata(submission)

        # --- Stage 4 & 5: Analyze payloads + verify checksums ---
        artifact_records: List[ArtifactRecord] = []
        all_flags: set = set()

        for payload in submission.payloads:
            # Analyze for security flags
            flags = analyze_payload(payload, self.config)
            all_flags.update(flags)

            # Verify checksum if possible
            checksum_verified = None
            if self.config.verify_checksums and payload.checksum:
                local_path = resolve_file_path(payload.uri, self.config.storage_base_path)
                if local_path:
                    checksum_verified = verify_checksum(
                        local_path, payload.checksum, self.config.checksum_algorithm
                    )

            # Create artifact record
            artifact = create_artifact_record(
                payload=payload,
                security_flags=flags,
                drone_id=submission.drone_id,
                ingest_id=ingest_id,
                config=self.config,
                checksum_verified=checksum_verified,
            )
            artifact_records.append(artifact)

        # --- Stage 6: Build ingest metadata ---
        sorted_flags = sorted(all_flags)
        zone_risk = self._get_zone_risk(submission.mission_zone)
        notes = generate_threat_notes(sorted_flags, auth_result.status)

        ingest_metadata = IngestMetadata(
            ingest_id=ingest_id,
            drone_id=submission.drone_id,
            timestamp=submission.timestamp,
            received_at=received_at,
            mission_id=mission_context.get("mission_id"),
            mission_zone=mission_context.get("mission_zone"),
            geo=geo_data,
            operator_id=mission_context.get("operator_id"),
            firmware_version=mission_context.get("firmware_version"),
            num_files=len(submission.payloads),
            total_size_bytes=sum(p.size_bytes for p in submission.payloads),
            insecure_flags=sorted_flags,
            auth_result=auth_result.status,
            auth_details=auth_result.to_dict(),
            reputation=auth_result.reputation,
            zone_risk=zone_risk,
            notes=notes,
            additional_metadata=additional_meta,
        )

        # --- Update stats ---
        self._stats["total_processed"] += 1
        if sorted_flags:
            self._stats["total_flagged"] += 1

        elapsed = time.time() - start_time
        logger.info(
            "Processed %s from %s in %.3fs | flags=%s | auth=%s",
            ingest_id, submission.drone_id, elapsed, sorted_flags, auth_result.status,
        )

        return IngestResult(
            success=True,
            ingest_metadata=ingest_metadata,
            artifact_records=artifact_records,
            warnings=warnings,
        )

    def process_batch(self, submissions: List[Dict[str, Any]]) -> List[IngestResult]:
        """Process multiple drone submissions."""
        return [self.process(s) for s in submissions]

    def _get_zone_risk(self, zone: Optional[str]) -> Optional[float]:
        """Look up zone risk, falling back to uplink-updated values."""
        if not zone:
            return None
        # Check uplink-updated zone risks first
        uplink_risks = self._uplink_handler.zone_risk_lookup
        if zone in uplink_risks:
            return uplink_risks[zone]
        return self._zone_risk.get(zone, self.config.default_zone_risk)

    def _process_uplink_commands(self) -> None:
        """Process any pending uplink commands."""
        commands = self._uplink_receiver.poll_commands()
        for cmd in commands:
            result = self._uplink_handler.handle(cmd)
            self._uplink_receiver.acknowledge(cmd.command_id)
            logger.debug("Uplink command processed: %s -> %s", cmd.command_type, result)

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def authenticator(self) -> Authenticator:
        return self._authenticator

    @property
    def uplink_receiver(self) -> UplinkReceiver:
        return self._uplink_receiver


def ingestion_interceptor(
    drone_json: Dict[str, Any],
    device_registry: Optional[Dict[str, Dict[str, Any]]] = None,
    require_signature: bool = False,
    zone_risk_lookup: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Functional API (backward-compatible with prototype).
    Creates an IngestionInterceptor instance and processes a single submission.
    """
    config = InterceptorConfig(require_signature=require_signature)
    interceptor = IngestionInterceptor(
        config=config,
        device_registry=device_registry,
        zone_risk_lookup=zone_risk_lookup,
    )
    result = interceptor.process(drone_json)
    return result.to_dict()
