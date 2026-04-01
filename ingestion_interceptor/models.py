"""
Data models for the Ingestion Interceptor pipeline.
Uses dataclasses for structured, typed representations of all entities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


def _generate_id(prefix: str, length: int = 12) -> str:
    return f"{prefix}{uuid.uuid4().hex[:length]}"


@dataclass
class GeoLocation:
    lat: float
    lon: float
    alt: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {"lat": self.lat, "lon": self.lon, "alt": self.alt}

    @classmethod
    def from_dict(cls, d: Optional[Dict]) -> Optional["GeoLocation"]:
        if not d or not isinstance(d, dict):
            return None
        try:
            return cls(lat=float(d["lat"]), lon=float(d["lon"]), alt=float(d.get("alt", 0.0)))
        except (KeyError, ValueError, TypeError):
            return None


@dataclass
class PayloadEntry:
    type: str
    filename: str
    mime: str
    size_bytes: int
    encryption: bool = False
    container: bool = False
    checksum: Optional[str] = None
    uri: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "type": self.type,
            "filename": self.filename,
            "mime": self.mime,
            "size_bytes": self.size_bytes,
            "encryption": self.encryption,
            "container": self.container,
        }
        if self.checksum:
            d["checksum"] = self.checksum
        if self.uri:
            d["uri"] = self.uri
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PayloadEntry":
        return cls(
            type=d.get("type", ""),
            filename=d.get("filename", ""),
            mime=d.get("mime", ""),
            size_bytes=d.get("size_bytes", 0),
            encryption=d.get("encryption", False),
            container=d.get("container", False),
            checksum=d.get("checksum"),
            uri=d.get("uri"),
        )


@dataclass
class DroneSubmission:
    drone_id: str
    timestamp: str
    payloads: List[PayloadEntry]
    mission_id: Optional[str] = None
    mission_zone: Optional[str] = None
    geo: Optional[GeoLocation] = None
    telemetry: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    firmware_version: Optional[str] = None
    operator_id: Optional[str] = None
    additional_metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DroneSubmission":
        payloads = [PayloadEntry.from_dict(p) for p in d.get("payloads", [])]
        geo = GeoLocation.from_dict(d.get("geo"))
        return cls(
            drone_id=d.get("drone_id", ""),
            timestamp=d.get("timestamp", ""),
            payloads=payloads,
            mission_id=d.get("mission_id"),
            mission_zone=d.get("mission_zone"),
            geo=geo,
            telemetry=d.get("telemetry"),
            signature=d.get("signature"),
            firmware_version=d.get("firmware_version"),
            operator_id=d.get("operator_id"),
            additional_metadata=d.get("additional_metadata"),
        )


@dataclass
class ArtifactRecord:
    artifact_id: str
    filename: str
    type: str
    mime: str
    size_bytes: int
    encryption: bool
    container: bool
    security_flags: List[str]
    checksum_verified: Optional[bool] = None
    thumbnail: Optional[str] = None
    pointer_storage: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "filename": self.filename,
            "type": self.type,
            "mime": self.mime,
            "size_bytes": self.size_bytes,
            "encryption": self.encryption,
            "container": self.container,
            "security_flags": self.security_flags,
            "checksum_verified": self.checksum_verified,
            "thumbnail": self.thumbnail,
            "pointer_storage": self.pointer_storage,
        }


@dataclass
class IngestMetadata:
    ingest_id: str
    drone_id: str
    timestamp: str
    received_at: str
    mission_id: Optional[str] = None
    mission_zone: Optional[str] = None
    geo: Optional[Dict[str, float]] = None
    operator_id: Optional[str] = None
    firmware_version: Optional[str] = None
    num_files: int = 0
    total_size_bytes: int = 0
    insecure_flags: List[str] = field(default_factory=list)
    auth_result: str = "unknown"
    auth_details: Optional[Dict[str, Any]] = None
    reputation: Optional[float] = None
    zone_risk: Optional[float] = None
    notes: str = ""
    additional_metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "ingest_id": self.ingest_id,
            "drone_id": self.drone_id,
            "timestamp": self.timestamp,
            "received_at": self.received_at,
            "mission_id": self.mission_id,
            "mission_zone": self.mission_zone,
            "geo": self.geo,
            "operator_id": self.operator_id,
            "firmware_version": self.firmware_version,
            "num_files": self.num_files,
            "total_size_bytes": self.total_size_bytes,
            "insecure_flags": self.insecure_flags,
            "auth_result": self.auth_result,
            "notes": self.notes,
        }
        if self.auth_details:
            d["auth_details"] = self.auth_details
        if self.reputation is not None:
            d["reputation"] = self.reputation
        if self.zone_risk is not None:
            d["zone_risk"] = self.zone_risk
        if self.additional_metadata:
            d["additional_metadata"] = self.additional_metadata
        return d


@dataclass
class IngestResult:
    success: bool
    ingest_metadata: Optional[IngestMetadata] = None
    artifact_records: List[ArtifactRecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        if not self.success:
            return {
                "error": True,
                "errors": self.errors,
                "warnings": self.warnings,
            }
        return {
            "ingest_metadata": self.ingest_metadata.to_dict() if self.ingest_metadata else {},
            "artifact_records": [a.to_dict() for a in self.artifact_records],
            "warnings": self.warnings,
        }
