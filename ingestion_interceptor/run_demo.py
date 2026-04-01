"""
Demo runner: processes sample drone submissions through the complete Ingestion Interceptor.
Run with: python -m ingestion_interceptor.run_demo
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion_interceptor import IngestionInterceptor, InterceptorConfig


# ===================== SAMPLE DATA =====================

DEVICE_REGISTRY = {
    "DRN-001": {"trusted": True, "reputation": 0.9},
    "DRN-002": {"trusted": False, "reputation": 0.4},
    "DRN-003": {"trusted": True, "reputation": 0.95},
    "DRN-004": {"trusted": True, "reputation": 0.85},
}

ZONE_RISK_LOOKUP = {"zone-a": 0.6, "zone-b": 0.2, "zone-c": 0.8}

KEY_STORE = {
    "DRN-001": "secret_key_001",
    "DRN-004": "secret_key_004",
}

SAMPLES = {
    "A": {
        "drone_id": "DRN-001",
        "timestamp": "2025-10-13T03:00:12Z",
        "mission_id": "MSN-142",
        "mission_zone": "zone-a",
        "geo": {"lat": 12.971598, "lon": 77.594566, "alt": 120},
        "payloads": [
            {"type": "video", "filename": "drn001_fpv_001.mp4", "mime": "video/mp4",
             "size_bytes": 4500000, "encryption": False, "container": False, "checksum": "a1b2c3d4..."},
            {"type": "image", "filename": "drn001_cam_001.jpg", "mime": "image/jpeg",
             "size_bytes": 320000, "encryption": False, "container": False, "checksum": "e5f6g7h8..."},
        ],
        "telemetry": {"speed": 12.5, "heading": 145.2, "battery": 78.4, "signal_strength": 82.1},
        "signature": None,
        "firmware_version": "v1.2.0",
        "operator_id": "OP-12",
        "additional_metadata": {"camera_model": "CAM-X1000", "frame_rate": 30},
    },
    "B": {
        "drone_id": "DRN-002",
        "timestamp": "2025-10-13T03:05:45Z",
        "mission_id": "MSN-143",
        "mission_zone": "zone-c",
        "geo": {"lat": 13.035542, "lon": 77.597100, "alt": 85},
        "payloads": [
            {"type": "archive", "filename": "payload_bundle.zip", "mime": "application/zip",
             "size_bytes": 4200000, "encryption": True, "container": True, "checksum": "9f8e7d6c..."},
            {"type": "text", "filename": "notes.txt", "mime": "text/plain",
             "size_bytes": 2048, "encryption": False, "container": False, "checksum": "1234abcd..."},
        ],
        "telemetry": {"speed": 0.0, "heading": 0.0, "battery": 56.1, "signal_strength": 65.3},
        "signature": "ed25519:abcdef012345...",
        "firmware_version": "v1.1.9",
        "operator_id": "OP-23",
        "additional_metadata": {"mission_priority": "high", "notes": "compressed mission dataset"},
    },
    "C": {
        "drone_id": "DRN-003",
        "timestamp": "2025-10-13T03:10:03Z",
        "mission_id": "MSN-144",
        "mission_zone": "zone-b",
        "geo": {"lat": 12.967800, "lon": 77.601200, "alt": 35},
        "payloads": [
            {"type": "telemetry", "filename": "telemetry_snapshot.json", "mime": "application/json",
             "size_bytes": 1500, "encryption": False, "container": False, "checksum": "fedcba987..."},
        ],
        "telemetry": {"speed": 6.2, "heading": 220.0, "battery": 92.3, "signal_strength": 90.4},
        "signature": None,
        "firmware_version": "v1.2.3",
        "operator_id": "OP-33",
        "additional_metadata": {"note": "routine patrol", "weather": "clear"},
    },
    "D": {
        "drone_id": "DRN-004",
        "timestamp": "2025-10-13T03:15:22Z",
        "mission_id": "MSN-145",
        "mission_zone": "zone-a",
        "geo": {"lat": 12.975000, "lon": 77.590000, "alt": 200},
        "payloads": [
            {"type": "video", "filename": "survey_coverage_long.mp4", "mime": "video/mp4",
             "size_bytes": 12500000, "encryption": False, "container": False, "checksum": "aaaabbbbcccc..."},
            {"type": "image", "filename": "survey_frame_2345.jpg", "mime": "image/jpeg",
             "size_bytes": 550000, "encryption": False, "container": False, "checksum": "ddddeeeeffff..."},
        ],
        "telemetry": {"speed": 8.1, "heading": 98.7, "battery": 64.0, "signal_strength": 75.0},
        "signature": "ed25519:98765fedcba...",
        "firmware_version": "v2.0.0",
        "operator_id": "OP-05",
        "additional_metadata": {"camera_model": "CAM-PRO-4k", "mission_sensitivity": "critical"},
    },
    "E_suspicious": {
        "drone_id": "DRN-999",
        "timestamp": "2025-10-13T04:00:00Z",
        "mission_id": "MSN-666",
        "mission_zone": "zone-c",
        "geo": {"lat": 12.980000, "lon": 77.600000, "alt": 50},
        "payloads": [
            {"type": "archive", "filename": "data.tar.gz.exe", "mime": "application/x-msdownload",
             "size_bytes": 15000000, "encryption": True, "container": True, "checksum": "deadbeef..."},
        ],
        "telemetry": {"speed": -5.0, "heading": 400, "battery": 120, "signal_strength": -10},
        "signature": None,
        "firmware_version": "v0.0.1",
        "operator_id": "OP-00",
        "additional_metadata": {"mission_sensitivity": "critical"},
    },
}


def print_separator(char="=", width=100):
    print(char * width)


def run_demo():
    print_separator()
    print("  INGESTION INTERCEPTOR - COMPLETE PIPELINE DEMO")
    print_separator()

    config = InterceptorConfig(
        require_signature=False,
        verify_checksums=True,
        storage_backend="s3",
    )

    interceptor = IngestionInterceptor(
        config=config,
        device_registry=DEVICE_REGISTRY,
        zone_risk_lookup=ZONE_RISK_LOOKUP,
        key_store=KEY_STORE,
    )

    all_outputs = {}

    for name, sample in SAMPLES.items():
        print(f"\n{'─' * 100}")
        print(f"  Processing Sample {name}: drone={sample['drone_id']}")
        print(f"{'─' * 100}")

        result = interceptor.process(sample)
        output = result.to_dict()
        all_outputs[name] = output

        if not result.success:
            print(f"  REJECTED: {result.errors}")
            continue

        meta = result.ingest_metadata
        print(f"  Ingest ID     : {meta.ingest_id}")
        print(f"  Auth Result   : {meta.auth_result}")
        print(f"  Reputation    : {meta.reputation}")
        print(f"  Zone Risk     : {meta.zone_risk}")
        print(f"  Files         : {meta.num_files} ({meta.total_size_bytes:,} bytes)")
        print(f"  Security Flags: {meta.insecure_flags}")
        print(f"  Notes         : {meta.notes}")

        if result.warnings:
            print(f"  Warnings      : {result.warnings}")

        print(f"\n  Artifacts:")
        for i, art in enumerate(result.artifact_records, 1):
            print(f"    [{i}] {art.filename} ({art.type}, {art.size_bytes:,}B)")
            print(f"        flags={art.security_flags}, checksum_ok={art.checksum_verified}")
            print(f"        storage={art.pointer_storage}")

    print(f"\n{'=' * 100}")
    print(f"  PIPELINE STATS: {interceptor.stats}")
    print(f"{'=' * 100}")

    # Save outputs
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ingest_outputs_complete.json")
    with open(output_path, "w") as f:
        json.dump(all_outputs, f, indent=2)
    print(f"\n  Outputs saved to {output_path}")


if __name__ == "__main__":
    run_demo()
