"""
Metadata extraction and normalization from drone submissions.
Extracts mission context, geo data, telemetry, and additional fields.
"""

from typing import Any, Dict, Optional

from .models import DroneSubmission, GeoLocation


def extract_mission_context(submission: DroneSubmission) -> Dict[str, Any]:
    """
    Extract mission-relevant metadata from the drone submission.
    Normalizes fields and fills defaults where appropriate.
    """
    context = {
        "mission_id": submission.mission_id,
        "mission_zone": submission.mission_zone,
        "operator_id": submission.operator_id,
        "firmware_version": submission.firmware_version,
    }

    # Extract mission sensitivity from additional_metadata
    add_meta = submission.additional_metadata or {}
    sensitivity = add_meta.get("mission_sensitivity") or add_meta.get("mission_priority")
    if sensitivity:
        context["mission_sensitivity"] = str(sensitivity).lower()

    return context


def extract_geo_metadata(submission: DroneSubmission) -> Optional[Dict[str, float]]:
    """Extract and validate geolocation data."""
    if submission.geo is None:
        return None

    geo = submission.geo
    # Basic sanity checks on coordinates
    if not (-90 <= geo.lat <= 90):
        return None
    if not (-180 <= geo.lon <= 180):
        return None
    if geo.alt < -500 or geo.alt > 100000:
        return None

    return geo.to_dict()


def extract_telemetry_summary(submission: DroneSubmission) -> Optional[Dict[str, Any]]:
    """
    Extract and summarize telemetry data.
    Flags anomalous telemetry values that might indicate a compromised drone.
    """
    telem = submission.telemetry
    if not telem:
        return None

    summary = dict(telem)
    anomalies = []

    # Check for anomalous values
    battery = telem.get("battery")
    if battery is not None and (battery < 0 or battery > 100):
        anomalies.append("invalid_battery_level")

    speed = telem.get("speed")
    if speed is not None and speed < 0:
        anomalies.append("negative_speed")

    signal = telem.get("signal_strength")
    if signal is not None and (signal < 0 or signal > 100):
        anomalies.append("invalid_signal_strength")

    heading = telem.get("heading")
    if heading is not None and (heading < 0 or heading >= 360):
        anomalies.append("invalid_heading")

    if anomalies:
        summary["telemetry_anomalies"] = anomalies

    return summary


def extract_additional_metadata(submission: DroneSubmission) -> Optional[Dict[str, Any]]:
    """
    Pass through additional metadata while stripping potentially dangerous fields.
    This is a lightweight pre-sanitization step (full sanitization happens
    in the separate Metadata Sanitizer module).
    """
    add_meta = submission.additional_metadata
    if not add_meta:
        return None

    # Strip fields that should never propagate raw into the pipeline
    dangerous_keys = {"__proto__", "constructor", "prototype", "eval", "exec"}
    cleaned = {k: v for k, v in add_meta.items() if k.lower() not in dangerous_keys}

    # Truncate excessively long string values (potential payload injection)
    max_value_len = 10000
    for k, v in cleaned.items():
        if isinstance(v, str) and len(v) > max_value_len:
            cleaned[k] = v[:max_value_len] + "...[truncated]"

    return cleaned if cleaned else None
