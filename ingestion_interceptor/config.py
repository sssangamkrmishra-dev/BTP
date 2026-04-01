"""
Configuration and constants for the Ingestion Interceptor.
All tuneable parameters are centralized here.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class InterceptorConfig:
    # --- Validation ---
    require_signature: bool = False
    max_payload_size_bytes: int = 500_000_000  # 500 MB hard cap per payload
    max_payloads_per_submission: int = 50
    allowed_mime_types: set = field(default_factory=lambda: {
        "video/mp4", "video/x-matroska", "video/avi",
        "image/jpeg", "image/png", "image/tiff", "image/bmp",
        "application/json", "text/plain", "text/csv",
        "application/zip", "application/x-tar", "application/gzip",
        "application/octet-stream",
    })

    # --- Security flag thresholds ---
    large_binary_threshold: int = 10_000_000  # 10 MB
    suspicious_mime_types: set = field(default_factory=lambda: {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
        "application/octet-stream",
    })
    suspicious_extensions: set = field(default_factory=lambda: {
        "exe", "dll", "bat", "cmd", "ps1", "sh", "vbs", "js", "msi", "scr", "com",
    })

    # --- Authentication ---
    auth_backend: str = "registry"  # "registry", "jwt", "mtls"
    auth_timeout_seconds: float = 5.0
    unknown_device_policy: str = "flag"  # "flag", "reject", "allow"

    # --- Checksum ---
    checksum_algorithm: str = "sha256"  # "sha256", "md5", "sha1"
    verify_checksums: bool = True

    # --- Storage ---
    storage_backend: str = "filesystem"  # "filesystem", "s3", "minio"
    storage_base_path: str = "drone_remote_store"
    artifact_uri_prefix: str = "s3://forensics/artifacts"

    # --- Zone risk defaults ---
    default_zone_risk: float = 0.5

    # --- Logging ---
    log_level: str = "INFO"
    structured_logging: bool = True

    # --- Uplink ---
    uplink_enabled: bool = False
    uplink_endpoint: str = ""
    uplink_poll_interval_seconds: float = 10.0
