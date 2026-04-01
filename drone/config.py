"""
Configuration for the Drone Simulator.
Models real-world drone parameters: airframe, sensors, battery, comms.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class DroneConfig:
    """
    All tuneable parameters for a simulated drone platform.
    Defaults model a mid-range surveillance RPA (e.g., DJI Matrice-class).
    """

    # ── Identity ───────────────────────────────────────────────────────
    drone_id: str = "DRN-001"
    firmware_version: str = "v2.1.0"
    operator_id: str = "OP-01"
    platform_model: str = "RPA-MK4"

    # ── Airframe / Flight ──────────────────────────────────────────────
    max_speed_ms: float = 20.0          # m/s (72 km/h)
    cruise_speed_ms: float = 12.0       # typical cruise speed
    max_altitude_m: float = 500.0       # AGL ceiling
    min_altitude_m: float = 5.0         # minimum safe altitude
    climb_rate_ms: float = 3.0          # vertical climb rate m/s
    turn_rate_deg_s: float = 45.0       # max heading change per second

    # ── Battery ────────────────────────────────────────────────────────
    battery_capacity_wh: float = 150.0  # watt-hours
    battery_initial_pct: float = 100.0  # starting charge %
    power_idle_w: float = 15.0          # idle power draw (hover/ground)
    power_per_speed_w: float = 3.5      # additional watts per m/s of speed
    power_per_altitude_w: float = 0.02  # additional watts per meter altitude
    power_per_payload_w: float = 0.5    # additional watts per active sensor
    low_battery_threshold: float = 20.0 # % — triggers RTL (return to launch)
    critical_battery_threshold: float = 10.0

    # ── Sensors ────────────────────────────────────────────────────────
    camera_resolution: str = "4K"       # "1080p", "4K", "8K"
    camera_model: str = "CAM-X1000"
    camera_fov_deg: float = 84.0        # field of view
    video_fps: int = 30
    video_bitrate_mbps: float = 25.0    # approximate
    image_size_bytes_range: Tuple[int, int] = (200_000, 800_000)
    video_size_bytes_per_sec: int = 3_000_000  # ~3 MB/s at 25 Mbps
    telemetry_interval_sec: float = 1.0 # how often telemetry is sampled

    # ── Communication ──────────────────────────────────────────────────
    signal_strength_base: float = 85.0  # % at launch
    signal_decay_per_km: float = 5.0    # % loss per km from base
    comms_protocol: str = "encrypted_radio"  # "encrypted_radio", "lte", "satellite"
    max_comm_range_km: float = 15.0

    # ── Storage ────────────────────────────────────────────────────────
    onboard_storage_gb: float = 64.0
    storage_base_path: str = "drone_remote_store"
    storage_uri_prefix: str = "file:/"

    # ── Mission defaults ───────────────────────────────────────────────
    default_mission_zone: str = "zone-alpha"
    home_position: Tuple[float, float, float] = (12.971598, 77.594566, 0.0)  # lat, lon, alt

    # ── Crypto / Auth ──────────────────────────────────────────────────
    signing_enabled: bool = False
    signing_key: str = ""               # HMAC shared secret
    signing_algorithm: str = "hmac-sha256"

    # ── Anomaly injection (for testing) ────────────────────────────────
    inject_anomalies: bool = False
    anomaly_probability: float = 0.0    # 0.0 to 1.0
    anomaly_types: List[str] = field(default_factory=lambda: [
        "spoofed_gps",           # random GPS jump
        "negative_speed",        # negative speed value
        "battery_overflow",      # battery > 100%
        "signal_dropout",        # signal = 0
        "encrypted_payload",     # encrypt a normal payload
        "executable_injection",  # inject .exe payload
        "path_traversal",        # ../etc/passwd filename
        "double_extension",      # photo.jpg.exe
        "oversized_metadata",    # huge additional_metadata field
    ])
