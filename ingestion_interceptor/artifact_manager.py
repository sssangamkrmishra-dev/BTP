"""
Artifact record creation and storage pointer management.
Handles artifact ID generation, thumbnail references, and storage URI construction.
"""

import os
import uuid
from typing import Any, Dict, List, Optional

from .config import InterceptorConfig
from .models import ArtifactRecord, PayloadEntry


def generate_artifact_id() -> str:
    return f"artifact://{uuid.uuid4().hex[:16]}"


def generate_ingest_id() -> str:
    return f"ingest_{uuid.uuid4().hex[:12]}"


def build_storage_pointer(
    payload: PayloadEntry,
    drone_id: str,
    ingest_id: str,
    config: InterceptorConfig,
) -> str:
    """
    Build the storage URI for an artifact.

    For filesystem backend: uses local path under storage_base_path.
    For s3/minio: constructs a bucket path.
    """
    unique_suffix = uuid.uuid4().hex[:8]

    if config.storage_backend == "filesystem":
        return os.path.join(
            config.storage_base_path,
            drone_id,
            payload.filename,
        )

    # S3/MinIO style
    return f"{config.artifact_uri_prefix}/{drone_id}/{ingest_id}/{unique_suffix}_{payload.filename}"


def resolve_storage_pointer(payload: PayloadEntry, drone_id: str, config: InterceptorConfig) -> str:
    """
    If the payload already has a URI (from drone upload), use it.
    Otherwise, construct a pointer.
    """
    if payload.uri:
        return payload.uri
    return build_storage_pointer(payload, drone_id, "", config)


def generate_thumbnail_ref(payload: PayloadEntry) -> Optional[str]:
    """Generate a thumbnail reference for visual payload types."""
    if payload.type in ("image", "video"):
        return f"thumb://{uuid.uuid4().hex[:12]}"
    return None


def create_artifact_record(
    payload: PayloadEntry,
    security_flags: List[str],
    drone_id: str,
    ingest_id: str,
    config: InterceptorConfig,
    checksum_verified: Optional[bool] = None,
) -> ArtifactRecord:
    """Create a complete artifact record for a single payload."""
    return ArtifactRecord(
        artifact_id=generate_artifact_id(),
        filename=payload.filename,
        type=payload.type,
        mime=payload.mime,
        size_bytes=payload.size_bytes,
        encryption=payload.encryption,
        container=payload.container,
        security_flags=security_flags,
        checksum_verified=checksum_verified,
        thumbnail=generate_thumbnail_ref(payload),
        pointer_storage=resolve_storage_pointer(payload, drone_id, config),
    )
