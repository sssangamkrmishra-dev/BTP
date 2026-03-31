# %%
import json
from datetime import datetime
import uuid

# %%
# =========================
# Sample Drone Payloads
# =========================

# --- Sample A: Video + Image (normal) ---
sample_A = {
    "drone_id": "DRN-001",
    "timestamp": "2025-10-13T03:00:12Z",
    "mission_id": "MSN-142",
    "mission_zone": "zone-a",
    "geo": {"lat": 12.971598, "lon": 77.594566, "alt": 120},
    "payloads": [
        {
            "type": "video",
            "filename": "drn001_fpv_001.mp4",
            "mime": "video/mp4",
            "size_bytes": 4500000,
            "encryption": False,
            "container": False,
            "checksum": "a1b2c3d4..."
        },
        {
            "type": "image",
            "filename": "drn001_cam_001.jpg",
            "mime": "image/jpeg",
            "size_bytes": 320000,
            "encryption": False,
            "container": False,
            "checksum": "e5f6g7h8..."
        }
    ],
    "telemetry": {"speed": 12.5, "heading": 145.2, "battery": 78.4, "signal_strength": 82.1},
    "signature": None,
    "firmware_version": "v1.2.0",
    "operator_id": "OP-12",
    "additional_metadata": {"camera_model": "CAM-X1000", "frame_rate": 30}
}

# --- Sample B: Encrypted nested archive (suspicious-looking) ---
sample_B = {
    "drone_id": "DRN-002",
    "timestamp": "2025-10-13T03:05:45Z",
    "mission_id": "MSN-143",
    "mission_zone": "zone-c",
    "geo": {"lat": 13.035542, "lon": 77.597100, "alt": 85},
    "payloads": [
        {
            "type": "archive",
            "filename": "payload_bundle.zip",
            "mime": "application/zip",
            "size_bytes": 4200000,
            "encryption": True,
            "container": True,
            "checksum": "9f8e7d6c..."
        },
        {
            "type": "text",
            "filename": "notes.txt",
            "mime": "text/plain",
            "size_bytes": 2048,
            "encryption": False,
            "container": False,
            "checksum": "1234abcd..."
        }
    ],
    "telemetry": {"speed": 0.0, "heading": 0.0, "battery": 56.1, "signal_strength": 65.3},
    "signature": "ed25519:abcdef012345...",
    "firmware_version": "v1.1.9",
    "operator_id": "OP-23",
    "additional_metadata": {"mission_priority": "high", "notes": "compressed mission dataset"}
}

# --- Sample C: Telemetry-only / small text (low-risk) ---
sample_C = {
    "drone_id": "DRN-003",
    "timestamp": "2025-10-13T03:10:03Z",
    "mission_id": "MSN-144",
    "mission_zone": "zone-b",
    "geo": {"lat": 12.967800, "lon": 77.601200, "alt": 35},
    "payloads": [
        {
            "type": "telemetry",
            "filename": "telemetry_snapshot.json",
            "mime": "application/json",
            "size_bytes": 1500,
            "encryption": False,
            "container": False,
            "checksum": "fedcba987..."
        }
    ],
    "telemetry": {"speed": 6.2, "heading": 220.0, "battery": 92.3, "signal_strength": 90.4},
    "signature": None,
    "firmware_version": "v1.2.3",
    "operator_id": "OP-33",
    "additional_metadata": {"note": "routine patrol", "weather": "clear"}
}

# --- Sample D: Mixed with large video + camera metadata (mission-critical) ---
sample_D = {
    "drone_id": "DRN-004",
    "timestamp": "2025-10-13T03:15:22Z",
    "mission_id": "MSN-145",
    "mission_zone": "zone-a",
    "geo": {"lat": 12.975000, "lon": 77.590000, "alt": 200},
    "payloads": [
        {
            "type": "video",
            "filename": "survey_coverage_long.mp4",
            "mime": "video/mp4",
            "size_bytes": 12500000,
            "encryption": False,
            "container": False,
            "checksum": "aaaabbbbcccc..."
        },
        {
            "type": "image",
            "filename": "survey_frame_2345.jpg",
            "mime": "image/jpeg",
            "size_bytes": 550000,
            "encryption": False,
            "container": False,
            "checksum": "ddddeeeeffff..."
        }
    ],
    "telemetry": {"speed": 8.1, "heading": 98.7, "battery": 64.0, "signal_strength": 75.0},
    "signature": "ed25519:98765fedcba...",
    "firmware_version": "v2.0.0",
    "operator_id": "OP-05",
    "additional_metadata": {"camera_model": "CAM-PRO-4k", "mission_sensitivity": "critical"}
}


# %%
sample_E={
  "drone_id": "DRN-003",
  "timestamp": "2025-11-05T12:18:40Z",
  "mission_id": "MSN-519",
  "mission_zone": "zone-a",
  "geo": {
    "lat": 12.963181,
    "lon": 77.599333,
    "alt": 296.0
  },
  "payloads": [
    {
      "type": "image",
      "filename": "DRN-003_img_1762345120_d03cdf.jpg",
      "mime": "image/jpeg",
      "size_bytes": 5075,
      "encryption": False,
      "container": False,
      "checksum": "a695551d53e7bb4c99577e0be5e6e3f43da8536d0e905401916efe9f278fefae",
      "uri": "file:/C:\\Users\\sanga\\Desktop\\BTP\\drone_remote_store\\DRN-003\\DRN-003_img_1762345120_d03cdf.jpg"
    },
    {
      "type": "image",
      "filename": "DRN-003_img_1762345121_50a1e4.jpg",
      "mime": "image/jpeg",
      "size_bytes": 12555,
      "encryption": False,
      "container": False,
      "checksum": "8974f2fc72a7ff7cd1d3a42a5696d50be7fab3ab2f1fc7e3a04920d959ac0238",
      "uri": "file:/C:\\Users\\sanga\\Desktop\\BTP\\drone_remote_store\\DRN-003\\DRN-003_img_1762345121_50a1e4.jpg"
    },
    {
      "type": "video",
      "filename": "DRN-003_vid_1762345122_0cc6be.mp4",
      "mime": "video/mp4",
      "size_bytes": 1116442,
      "encryption": False,
      "container": False,
      "checksum": "4ff48dc8e8649cefcde02ca603d485425d587f76af3b2f5ec7c91fe66b7a11a8",
      "uri": "file:/C:\\Users\\sanga\\Desktop\\BTP\\drone_remote_store\\DRN-003\\DRN-003_vid_1762345122_0cc6be.mp4"
    }
  ],
  "telemetry": {
    "speed": 14.67,
    "heading": 289.2,
    "battery": 28.9,
    "signal_strength": 99.7
  },
  "signature": "adsfaddsf",
  "firmware_version": "v1.6.6",
  "operator_id": "OP-64",
  "additional_metadata": {
    "camera_model": "CAM-STD-1",
    "frame_rate": 30
  }
}

# %%
def generate_artifact_id():
    return f"artifact://{uuid.uuid4().hex[:12]}"

def generate_ingest_id():
    return f"ingest_{uuid.uuid4().hex[:10]}"

def detect_insecure_flags(payload):
    flags = []
    if payload.get("encryption"):
        flags.append("encrypted_payload")
    if payload.get("container"):
        flags.append("nested_archive")
    if payload.get("size_bytes", 0) > 10_000_000:
        flags.append("large_binary")
    return flags

def ingestion_interceptor(drone_json):
    required_fields = ["drone_id", "timestamp", "payloads"]
    for f in required_fields:
        if f not in drone_json:
            raise ValueError(f"Missing field: {f}")

    ingest_output = {
        "ingest_metadata": {
            "ingest_id": generate_ingest_id(),
            "drone_id": drone_json["drone_id"],
            "timestamp": drone_json["timestamp"],
            "mission_id": drone_json.get("mission_id"),
            "mission_zone": drone_json.get("mission_zone"),
            "geo": drone_json.get("geo"),
            "operator_id": drone_json.get("operator_id"),
            "firmware_version": drone_json.get("firmware_version"),
            "num_files": len(drone_json["payloads"]),
            "insecure_flags": [],
            "auth_result": "ok",  # mock authentication
            "notes": ""
        },
        "artifact_records": []
    }

    combined_flags = set()
    for payload in drone_json["payloads"]:
        artifact = {
            "artifact_id": generate_artifact_id(),
            "filename": payload["filename"],
            "type": payload["type"],
            "mime": payload["mime"],
            "size_bytes": payload["size_bytes"],
            "encryption": payload["encryption"],
            "container": payload["container"],
            "thumbnail": None if payload["type"] not in ["video", "image"] else f"thumb://{uuid.uuid4().hex[:10]}",
            # Add real data from drone itself
            "pointer_storage": f"s3://forensics/artifacts/{uuid.uuid4().hex[:12]}"
        }
        flags = detect_insecure_flags(payload)
        combined_flags.update(flags)
        ingest_output["artifact_records"].append(artifact)

    ingest_output["ingest_metadata"]["insecure_flags"] = list(combined_flags)

    if "encrypted_payload" in combined_flags:
        ingest_output["ingest_metadata"]["notes"] = "contains encrypted payload(s)"
    elif "large_binary" in combined_flags:
        ingest_output["ingest_metadata"]["notes"] = "large video or data file"
    else:
        ingest_output["ingest_metadata"]["notes"] = "normal feed"

    return ingest_output


# %%
output_A = ingestion_interceptor(sample_A)
print(json.dumps(output_A, indent=2))


# %%
output_B = ingestion_interceptor(sample_B)
print(json.dumps(output_B, indent=2))

# %%
output_C = ingestion_interceptor(sample_C)
print(json.dumps(output_C, indent=2))

# %%
output_D = ingestion_interceptor(sample_D)
print(json.dumps(output_D, indent=2))

# %%
# Ingestion Interceptor helpers + sample run (drop into your notebook)
import json, uuid
from datetime import datetime, timezone

# ------------------------
# Sample payloads (A - D)
# ------------------------
sample_A = {
    "drone_id": "DRN-001",
    "timestamp": "2025-10-13T03:00:12Z",
    "mission_id": "MSN-142",
    "mission_zone": "zone-a",
    "geo": {"lat": 12.971598, "lon": 77.594566, "alt": 120},
    "payloads": [
        {"type": "video", "filename": "drn001_fpv_001.mp4", "mime": "video/mp4", "size_bytes": 4500000, "encryption": False, "container": False, "checksum": "a1b2c3d4..."},
        {"type": "image", "filename": "drn001_cam_001.jpg", "mime": "image/jpeg", "size_bytes": 320000, "encryption": False, "container": False, "checksum": "e5f6g7h8..."}
    ],
    "telemetry": {"speed": 12.5, "heading": 145.2, "battery": 78.4, "signal_strength": 82.1},
    "signature": None,
    "firmware_version": "v1.2.0",
    "operator_id": "OP-12",
    "additional_metadata": {"camera_model": "CAM-X1000", "frame_rate": 30}
}

sample_B = {
    "drone_id": "DRN-002",
    "timestamp": "2025-10-13T03:05:45Z",
    "mission_id": "MSN-143",
    "mission_zone": "zone-c",
    "geo": {"lat": 13.035542, "lon": 77.597100, "alt": 85},
    "payloads": [
        {"type": "archive", "filename": "payload_bundle.zip", "mime": "application/zip", "size_bytes": 4200000, "encryption": True, "container": True, "checksum": "9f8e7d6c..."},
        {"type": "text", "filename": "notes.txt", "mime": "text/plain", "size_bytes": 2048, "encryption": False, "container": False, "checksum": "1234abcd..."}
    ],
    "telemetry": {"speed": 0.0, "heading": 0.0, "battery": 56.1, "signal_strength": 65.3},
    "signature": "ed25519:abcdef012345...",
    "firmware_version": "v1.1.9",
    "operator_id": "OP-23",
    "additional_metadata": {"mission_priority": "high", "notes": "compressed mission dataset"}
}

sample_C = {
    "drone_id": "DRN-003",
    "timestamp": "2025-10-13T03:10:03Z",
    "mission_id": "MSN-144",
    "mission_zone": "zone-b",
    "geo": {"lat": 12.967800, "lon": 77.601200, "alt": 35},
    "payloads": [
        {"type": "telemetry", "filename": "telemetry_snapshot.json", "mime": "application/json", "size_bytes": 1500, "encryption": False, "container": False, "checksum": "fedcba987..."}
    ],
    "telemetry": {"speed": 6.2, "heading": 220.0, "battery": 92.3, "signal_strength": 90.4},
    "signature": None,
    "firmware_version": "v1.2.3",
    "operator_id": "OP-33",
    "additional_metadata": {"note": "routine patrol", "weather": "clear"}
}

sample_D = {
    "drone_id": "DRN-004",
    "timestamp": "2025-10-13T03:15:22Z",
    "mission_id": "MSN-145",
    "mission_zone": "zone-a",
    "geo": {"lat": 12.975000, "lon": 77.590000, "alt": 200},
    "payloads": [
        {"type": "video", "filename": "survey_coverage_long.mp4", "mime": "video/mp4", "size_bytes": 12500000, "encryption": False, "container": False, "checksum": "aaaabbbbcccc..."},
        {"type": "image", "filename": "survey_frame_2345.jpg", "mime": "image/jpeg", "size_bytes": 550000, "encryption": False, "container": False, "checksum": "ddddeeeeffff..."}
    ],
    "telemetry": {"speed": 8.1, "heading": 98.7, "battery": 64.0, "signal_strength": 75.0},
    "signature": "ed25519:98765fedcba...",
    "firmware_version": "v2.0.0",
    "operator_id": "OP-05",
    "additional_metadata": {"camera_model": "CAM-PRO-4k", "mission_sensitivity": "critical"}
}

# ------------------------
# Helper functions
# ------------------------
def parse_timestamp_simple(ts_str):
    # Accept ISO 8601 with trailing Z or offset
    if not isinstance(ts_str, str):
        raise ValueError("timestamp must be a string")
    if ts_str.endswith("Z"):
        ts_str = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ts_str)

def validate_drone_payload(drone_json, require_signature=False):
    """
    Return a list of error codes (empty if valid).
    Basic checks:
      - required top-level fields
      - payloads is a non-empty list
      - timestamp parseable
      - optional signature presence (if require_signature=True)
      - each payload has type, filename, mime, size_bytes
    """
    errors = []
    for f in ("drone_id", "timestamp", "payloads"):
        if f not in drone_json:
            errors.append(f"missing_field:{f}")
    if "payloads" in drone_json:
        if not isinstance(drone_json["payloads"], list) or len(drone_json["payloads"]) == 0:
            errors.append("invalid_payloads:must_be_nonempty_list")
    if "timestamp" in drone_json:
        try:
            parse_timestamp_simple(drone_json["timestamp"])
        except Exception:
            errors.append("invalid_timestamp")
    if require_signature and not drone_json.get("signature"):
        errors.append("missing_signature")
    if "payloads" in drone_json and isinstance(drone_json["payloads"], list):
        for i, p in enumerate(drone_json["payloads"]):
            if not isinstance(p, dict):
                errors.append(f"payload_{i}:not_object")
                continue
            for key in ("type", "filename", "mime", "size_bytes"):
                if key not in p:
                    errors.append(f"payload_{i}:missing_{key}")
            if "size_bytes" in p and (not isinstance(p["size_bytes"], int) or p["size_bytes"] < 0):
                errors.append(f"payload_{i}:invalid_size_bytes")
    return errors

def analyze_payload(payload):
    """
    Return a list of flags for this single payload.
    Heuristics:
      - encrypted_payload, nested_archive, large_binary (>=10MB)
      - suspicious_mime, executable_file
    """
    flags = []
    if payload.get("encryption"):
        flags.append("encrypted_payload")
    if payload.get("container"):
        flags.append("nested_archive")
    size = payload.get("size_bytes", 0)
    if isinstance(size, int) and size >= 10_000_000:
        flags.append("large_binary")
    mime = (payload.get("mime") or "").lower()
    if mime in ("application/x-msdownload", "application/octet-stream"):
        flags.append("suspicious_mime")
    fname = payload.get("filename","")
    if fname and "." in fname:
        ext = fname.rsplit(".",1)[1].lower()
        if ext == "exe":
            flags.append("executable_file")
    return flags

# ID generators
def generate_artifact_id():
    return f"artifact://{uuid.uuid4().hex[:12]}"

def generate_ingest_id():
    return f"ingest_{uuid.uuid4().hex[:10]}"

# ------------------------
# Main ingestion_interceptor
# ------------------------
def ingestion_interceptor(drone_json, device_registry=None, require_signature=False, zone_risk_lookup=None):
    """
    Validate, authenticate (using device_registry), extract metadata,
    flag insecure payloads, and produce ingest output.
    Returns {"ingest_metadata": {...}, "artifact_records":[...]} or {"error": True, "errors": [...]}
    """
    errors = validate_drone_payload(drone_json, require_signature=require_signature)
    if errors:
        return {"error": True, "errors": errors}

    drone_id = drone_json["drone_id"]
    reg_info = (device_registry or {}).get(drone_id)
    if reg_info is None:
        auth_result = "unknown"
        reputation = None
    else:
        auth_result = "ok" if reg_info.get("trusted", False) else "unknown"
        reputation = reg_info.get("reputation")

    ingest_meta = {
        "ingest_id": generate_ingest_id(),
        "drone_id": drone_id,
        "timestamp": drone_json["timestamp"],
        "mission_id": drone_json.get("mission_id"),
        "mission_zone": drone_json.get("mission_zone"),
        "geo": drone_json.get("geo"),
        "operator_id": drone_json.get("operator_id"),
        "firmware_version": drone_json.get("firmware_version"),
        "num_files": len(drone_json.get("payloads", [])),
        "insecure_flags": [],
        "auth_result": auth_result,
        "notes": ""
    }

    artifact_records = []
    agg_flags = set()
    for payload in drone_json.get("payloads", []):
        pflags = analyze_payload(payload)
        for f in pflags:
            agg_flags.add(f)
        artifact = {
            "artifact_id": generate_artifact_id(),
            "filename": payload.get("filename"),
            "type": payload.get("type"),
            "mime": payload.get("mime"),
            "size_bytes": payload.get("size_bytes"),
            "encryption": payload.get("encryption", False),
            "container": payload.get("container", False),
            "thumbnail": None if payload.get("type") not in ("image","video") else f"thumb://{uuid.uuid4().hex[:10]}",
            # pointer_storage here is a mock; in real system this will be an S3/MinIO path returned after the drone uploaded the blob
            "pointer_storage": f"s3://forensics/artifacts/{uuid.uuid4().hex[:12]}"
        }
        artifact_records.append(artifact)

    ingest_meta["insecure_flags"] = sorted(list(agg_flags))

    if "encrypted_payload" in agg_flags or "nested_archive" in agg_flags:
        ingest_meta["notes"] = "defer analysis: encrypted or nested contents"
    elif "large_binary" in agg_flags:
        ingest_meta["notes"] = "large binary - consider selective sampling/sandboxing"
    else:
        ingest_meta["notes"] = "normal feed"

    if reputation is not None:
        ingest_meta["reputation"] = reputation
    if zone_risk_lookup and ingest_meta.get("mission_zone"):
        ingest_meta["zone_risk"] = zone_risk_lookup.get(ingest_meta["mission_zone"], 0.5)

    return {"ingest_metadata": ingest_meta, "artifact_records": artifact_records}

# ------------------------
# Mock registry and zone risk (for demo)
# ------------------------
device_registry = {
    "DRN-001": {"trusted": True, "reputation": 0.9},
    "DRN-002": {"trusted": False, "reputation": 0.4},
    "DRN-003": {"trusted": True, "reputation": 0.95},
    "DRN-004": {"trusted": True, "reputation": 0.85}
}
zone_risk_lookup = {"zone-a": 0.6, "zone-b": 0.2, "zone-c": 0.8}

# ------------------------
# Run interceptor on all samples and save outputs
# ------------------------
samples = {"A": sample_A, "B": sample_B, "C": sample_C, "D": sample_D}
outputs = {}
for name, s in samples.items():
    out = ingestion_interceptor(s, device_registry=device_registry, require_signature=False, zone_risk_lookup=zone_risk_lookup)
    outputs[name] = out
    print(f"\n--- Ingest Output for Sample {name} ---")
    print(json.dumps(out, indent=2))

# Optionally persist results for later stages
try:
    with open("/mnt/data/ingest_outputs_samples.json", "w") as f:
        json.dump(outputs, f, indent=2)
    print("\nSaved outputs to /mnt/data/ingest_outputs_samples.json")
except Exception:
    # environment may not allow writes; ignore if so
    pass



