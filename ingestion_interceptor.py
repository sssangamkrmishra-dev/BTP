# ingestion_interceptor_verbose.py
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

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
def parse_timestamp_simple(ts_str: str) -> datetime:
    # Accept ISO 8601 with trailing Z or offset
    if not isinstance(ts_str, str):
        raise ValueError("timestamp must be a string")
    if ts_str.endswith("Z"):
        ts_str = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ts_str)

def validate_drone_payload(drone_json: Dict[str, Any], require_signature: bool=False) -> List[str]:
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

def analyze_payload(payload: Dict[str, Any]) -> List[str]:
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
def generate_artifact_id() -> str:
    return f"artifact://{uuid.uuid4().hex[:12]}"

def generate_ingest_id() -> str:
    return f"ingest_{uuid.uuid4().hex[:10]}"

# ------------------------
# Main ingestion_interceptor
# ------------------------
def ingestion_interceptor(drone_json: Dict[str, Any],
                          device_registry: Dict[str, Dict[str, Any]]=None,
                          require_signature: bool=False,
                          zone_risk_lookup: Dict[str, float]=None) -> Dict[str, Any]:
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
# Printing helpers (detailed)
# ------------------------
def print_sep():
    print("\n" + ("-" * 100))

def print_input_details(sample_name: str, sample: Dict[str, Any]):
    print_sep()
    print(f"INPUT: Sample {sample_name}")
    print_sep()
    # Top-level fields
    top_keys = ["drone_id", "timestamp", "mission_id", "mission_zone", "firmware_version", "operator_id"]
    for k in top_keys:
        print(f"{k:20}: {sample.get(k)}")
    # parsed timestamp
    try:
        parsed_ts = parse_timestamp_simple(sample["timestamp"])
        print(f"{'parsed_timestamp':20}: {parsed_ts.isoformat()} (tzinfo={parsed_ts.tzinfo})")
    except Exception as e:
        print(f"{'parsed_timestamp':20}: INVALID ({e})")
    # geo + telemetry + additional_metadata
    print(f"{'geo':20}: {sample.get('geo')}")
    print(f"{'telemetry':20}: {sample.get('telemetry')}")
    print(f"{'additional_metadata':20}: {sample.get('additional_metadata')}")
    print(f"{'signature':20}: {sample.get('signature')}")
    # payloads (detailed)
    print("\nPayloads:")
    for i, p in enumerate(sample.get("payloads", []), start=1):
        flags = analyze_payload(p)
        print(f"  Payload #{i}")
        print(f"    {'filename':16}: {p.get('filename')}")
        print(f"    {'type':16}: {p.get('type')} (mime: {p.get('mime')})")
        print(f"    {'size_bytes':16}: {p.get('size_bytes')}")
        print(f"    {'encryption':16}: {p.get('encryption')}")
        print(f"    {'container':16}: {p.get('container')}")
        print(f"    {'checksum':16}: {p.get('checksum')}")
        print(f"    {'heuristic_flags':16}: {flags}")

def print_output_details(sample_name: str, output: Dict[str, Any]):
    print_sep()
    print(f"OUTPUT: Ingest Result for Sample {sample_name}")
    print_sep()
    if output.get("error"):
        print("Validation/Error output:")
        for e in output.get("errors", []):
            print(f"  - {e}")
        return
    meta = output["ingest_metadata"]
    artifacts = output["artifact_records"]
    # ingest metadata
    print("Ingest Metadata:")
    for k in ("ingest_id", "drone_id", "timestamp", "mission_id", "mission_zone", "operator_id", "firmware_version"):
        print(f"  {k:18}: {meta.get(k)}")
    print(f"  {'num_files':18}: {meta.get('num_files')}")
    print(f"  {'auth_result':18}: {meta.get('auth_result')}")
    if "reputation" in meta:
        print(f"  {'reputation':18}: {meta.get('reputation')}")
    if "zone_risk'":
        pass  # just being defensive; real key is 'zone_risk' if present
    if "zone_risk" in meta:
        print(f"  {'zone_risk':18}: {meta.get('zone_risk')}")
    print(f"  {'insecure_flags':18}: {meta.get('insecure_flags')}")
    print(f"  {'notes':18}: {meta.get('notes')}")
    # artifacts
    print("\nArtifact Records:")
    for i, a in enumerate(artifacts, start=1):
        print(f"  Artifact #{i}")
        for k in ("artifact_id", "filename", "type", "mime", "size_bytes", "encryption", "container", "thumbnail", "pointer_storage"):
            print(f"    {k:18}: {a.get(k)}")
    # quick summary
    total_size = sum(a.get("size_bytes", 0) for a in artifacts)
    print("\nSummary:")
    print(f"  {'artifact_count':18}: {len(artifacts)}")
    print(f"  {'total_size_bytes':18}: {total_size}")
    print(f"  {'ingest_notes':18}: {meta.get('notes')}")
    print_sep()

# ------------------------
# Run interceptor on all samples and print details
# ------------------------
def run_and_print_all():
    samples = {"A": sample_A, "B": sample_B, "C": sample_C, "D": sample_D}
    outputs = {}

    for name, s in samples.items():
        # print input details
        print_input_details(name, s)

        # run interceptor
        out = ingestion_interceptor(s, device_registry=device_registry, require_signature=False, zone_risk_lookup=zone_risk_lookup)
        outputs[name] = out

        # print output details (human readable)
        print_output_details(name, out)

        # also print JSON for machines & audit
        print("Raw JSON output (compact):")
        print(json.dumps(out, indent=2))

    # optionally persist results for later stages
    try:
        with open("ingest_outputs_samples.json", "w") as f:
            json.dump(outputs, f, indent=2)
        print("\nSaved outputs to ./ingest_outputs_samples.json")
    except Exception as e:
        print("\nCould not save outputs to file:", e)

if __name__ == "__main__":
    run_and_print_all()
