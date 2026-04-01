"""
Ingestion Interceptor Package
==============================

Secure ingestion pipeline for drone/RPA data streams.
Validates, authenticates, analyzes, and catalogs incoming drone payloads
before they enter the operational network.

Main entry points:
    - IngestionInterceptor: Class-based API with full configuration
    - ingestion_interceptor(): Functional API (backward-compatible)

Usage:
    from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

    config = InterceptorConfig(require_signature=False)
    interceptor = IngestionInterceptor(
        config=config,
        device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
        zone_risk_lookup={"zone-a": 0.6},
    )
    result = interceptor.process(drone_json)
"""

from .config import InterceptorConfig
from .interceptor import IngestionInterceptor, ingestion_interceptor
from .models import (
    ArtifactRecord,
    DroneSubmission,
    GeoLocation,
    IngestMetadata,
    IngestResult,
    PayloadEntry,
)
from .authenticator import Authenticator, AuthResult, DeviceRegistry, SignatureVerifier
from .payload_analyzer import analyze_payload, compute_payload_risk_score
from .validator import validate_submission

__all__ = [
    "IngestionInterceptor",
    "ingestion_interceptor",
    "InterceptorConfig",
    "DroneSubmission",
    "PayloadEntry",
    "GeoLocation",
    "ArtifactRecord",
    "IngestMetadata",
    "IngestResult",
    "Authenticator",
    "AuthResult",
    "DeviceRegistry",
    "SignatureVerifier",
    "analyze_payload",
    "compute_payload_risk_score",
    "validate_submission",
]
