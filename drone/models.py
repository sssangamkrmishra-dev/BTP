"""
Data models for the Drone Simulator.
Typed dataclasses representing drone state, flight plans, and sensor readings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import uuid


class DroneStatus(Enum):
    """Operational state of the drone."""
    IDLE = "idle"               # on ground, powered on
    TAKEOFF = "takeoff"         # ascending to mission altitude
    IN_FLIGHT = "in_flight"     # cruising / executing mission
    HOVERING = "hovering"       # stationary in air
    LANDING = "landing"         # descending to ground
    RETURNED = "returned"       # back at home position
    EMERGENCY = "emergency"     # low battery / signal loss
    OFFLINE = "offline"         # powered off


class SensorType(Enum):
    """Types of sensors on the drone."""
    CAMERA_STILL = "camera_still"
    CAMERA_VIDEO = "camera_video"
    TELEMETRY = "telemetry"
    LIDAR = "lidar"
    THERMAL = "thermal"


@dataclass
class Waypoint:
    """A single waypoint in a flight plan."""
    lat: float
    lon: float
    alt: float                          # meters AGL
    action: str = "flyover"             # "flyover", "hover", "capture_image", "record_video", "loiter"
    loiter_time_sec: float = 0.0        # seconds to stay at waypoint
    speed_ms: Optional[float] = None    # override speed for this leg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lat": self.lat, "lon": self.lon, "alt": self.alt,
            "action": self.action, "loiter_time_sec": self.loiter_time_sec,
        }


@dataclass
class FlightPlan:
    """
    A complete mission plan: sequence of waypoints + mission metadata.
    The drone follows waypoints in order, executing actions at each.
    """
    mission_id: str = ""
    mission_zone: str = "zone-alpha"
    mission_sensitivity: str = "medium"   # "low", "medium", "high", "critical"
    waypoints: List[Waypoint] = field(default_factory=list)
    repeat: bool = False                  # loop the waypoint list

    def __post_init__(self):
        if not self.mission_id:
            self.mission_id = f"MSN-{uuid.uuid4().hex[:6].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "mission_zone": self.mission_zone,
            "mission_sensitivity": self.mission_sensitivity,
            "waypoints": [w.to_dict() for w in self.waypoints],
        }


@dataclass
class GeoPosition:
    """Current geographic position of the drone."""
    lat: float
    lon: float
    alt: float      # meters AGL

    def to_dict(self) -> Dict[str, float]:
        return {"lat": round(self.lat, 6), "lon": round(self.lon, 6), "alt": round(self.alt, 1)}

    def distance_to(self, other: "GeoPosition") -> float:
        """Approximate distance in meters using equirectangular projection."""
        import math
        lat1, lon1 = math.radians(self.lat), math.radians(self.lon)
        lat2, lon2 = math.radians(other.lat), math.radians(other.lon)
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        x = dlon * math.cos((lat1 + lat2) / 2)
        return math.sqrt(dlat**2 + x**2) * 6_371_000  # Earth radius in meters


@dataclass
class DroneState:
    """
    Complete instantaneous state of the drone.
    Updated every simulation tick.
    """
    status: DroneStatus = DroneStatus.IDLE
    position: GeoPosition = field(default_factory=lambda: GeoPosition(0.0, 0.0, 0.0))
    speed_ms: float = 0.0
    heading_deg: float = 0.0            # 0=North, 90=East
    vertical_speed_ms: float = 0.0
    battery_pct: float = 100.0
    battery_wh_remaining: float = 150.0
    signal_strength_pct: float = 85.0
    temperature_c: float = 25.0
    uptime_sec: float = 0.0
    distance_from_home_m: float = 0.0
    total_distance_m: float = 0.0
    current_waypoint_idx: int = 0
    payloads_captured: int = 0
    storage_used_bytes: int = 0
    active_sensors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def telemetry_dict(self) -> Dict[str, Any]:
        """Export telemetry in the format expected by the ingestion interceptor."""
        return {
            "speed": round(self.speed_ms, 2),
            "heading": round(self.heading_deg, 1),
            "battery": round(self.battery_pct, 1),
            "signal_strength": round(self.signal_strength_pct, 1),
            "vertical_speed": round(self.vertical_speed_ms, 2),
            "temperature": round(self.temperature_c, 1),
            "distance_from_home": round(self.distance_from_home_m, 1),
        }


@dataclass
class CapturedPayload:
    """A file captured by a drone sensor, ready for transmission."""
    type: str               # "image", "video", "telemetry", "text", "archive"
    filename: str
    mime: str
    size_bytes: int
    encryption: bool = False
    container: bool = False
    checksum: str = ""
    uri: str = ""
    local_path: str = ""

    def to_submission_dict(self) -> Dict[str, Any]:
        """Convert to the payload format expected by the ingestion interceptor."""
        d: Dict[str, Any] = {
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
