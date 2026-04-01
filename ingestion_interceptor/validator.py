"""
Payload validation for incoming drone submissions.
Validates structure, types, constraints, and timestamps.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from .config import InterceptorConfig


def parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp string into a datetime object."""
    if not isinstance(ts_str, str):
        raise ValueError("timestamp must be a string")
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str)


def validate_submission(drone_json: Dict[str, Any], config: InterceptorConfig) -> Tuple[List[str], List[str]]:
    """
    Validate a raw drone submission dict.

    Returns:
        (errors, warnings) - errors are fatal, warnings are informational.
    """
    errors: List[str] = []
    warnings: List[str] = []

    # --- Required top-level fields ---
    for f in ("drone_id", "timestamp", "payloads"):
        if f not in drone_json:
            errors.append(f"missing_field:{f}")

    if errors:
        return errors, warnings

    # --- drone_id must be a non-empty string ---
    drone_id = drone_json["drone_id"]
    if not isinstance(drone_id, str) or not drone_id.strip():
        errors.append("invalid_drone_id:must_be_nonempty_string")

    # --- Timestamp validation ---
    ts = drone_json["timestamp"]
    try:
        parsed_ts = parse_timestamp(ts)
        now = datetime.now(timezone.utc)
        # Reject timestamps more than 24 hours in the future
        if parsed_ts > now.replace(tzinfo=parsed_ts.tzinfo) + __import__("datetime").timedelta(hours=24):
            warnings.append("timestamp_future:more_than_24h_ahead")
    except Exception:
        errors.append("invalid_timestamp:not_iso8601")

    # --- Payloads validation ---
    payloads = drone_json["payloads"]
    if not isinstance(payloads, list) or len(payloads) == 0:
        errors.append("invalid_payloads:must_be_nonempty_list")
        return errors, warnings

    if len(payloads) > config.max_payloads_per_submission:
        errors.append(f"too_many_payloads:max_{config.max_payloads_per_submission}")

    # --- Signature check ---
    if config.require_signature and not drone_json.get("signature"):
        errors.append("missing_signature")

    # --- Per-payload validation ---
    for i, p in enumerate(payloads):
        if not isinstance(p, dict):
            errors.append(f"payload_{i}:not_object")
            continue

        for key in ("type", "filename", "mime", "size_bytes"):
            if key not in p:
                errors.append(f"payload_{i}:missing_{key}")

        if "size_bytes" in p:
            size = p["size_bytes"]
            if not isinstance(size, (int, float)) or size < 0:
                errors.append(f"payload_{i}:invalid_size_bytes")
            elif size > config.max_payload_size_bytes:
                errors.append(f"payload_{i}:exceeds_max_size:{config.max_payload_size_bytes}")

        if "mime" in p:
            mime = p["mime"]
            if config.allowed_mime_types and mime not in config.allowed_mime_types:
                warnings.append(f"payload_{i}:unrecognized_mime:{mime}")

        if "filename" in p:
            fname = p["filename"]
            if not isinstance(fname, str) or not fname.strip():
                errors.append(f"payload_{i}:invalid_filename")
            elif "/" in fname or "\\" in fname:
                errors.append(f"payload_{i}:path_traversal_in_filename")

    return errors, warnings
