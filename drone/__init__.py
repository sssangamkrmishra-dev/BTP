"""
Drone Simulator Package
========================

Realistic drone/RPA simulator that generates data in the exact format
expected by the Ingestion Interceptor. Simulates flight dynamics,
sensor capture, battery management, and communication.

Part of the Multi-Layered Malware Detection and Threat Prevention System
for drone/RPA data streams.

Usage:
    from drone import Drone, DroneConfig, FlightPlan, Waypoint

    # Simple: quick capture
    d = Drone(DroneConfig(drone_id="DRN-001"))
    submission = d.quick_capture("image")
    # submission is a dict ready for IngestionInterceptor.process()

    # Full mission
    plan = FlightPlan(
        mission_zone="zone-alpha",
        waypoints=[
            Waypoint(12.975, 77.590, 100, action="capture_image"),
            Waypoint(12.980, 77.595, 120, action="record_video"),
        ],
    )
    d.fly_mission(plan)
    submissions = d.get_submissions()

    # Direct pipeline integration
    from ingestion_interceptor import IngestionInterceptor
    interceptor = IngestionInterceptor(device_registry={...})
    results = d.transmit_all(interceptor)

    # Fleet operations
    from drone import DroneFleet
    fleet = DroneFleet()
    fleet.add_drone(DroneConfig(drone_id="DRN-001"))
    fleet.add_drone(DroneConfig(drone_id="DRN-002"))
    fleet.assign_mission("DRN-001", plan)
    fleet.execute_all()
    all_submissions = fleet.collect_submissions()
"""

from .config import DroneConfig
from .models import (
    CapturedPayload,
    DroneState,
    DroneStatus,
    FlightPlan,
    GeoPosition,
    SensorType,
    Waypoint,
)
from .drone import Drone
from .fleet import DroneFleet
from .sensors import SensorSuite
from .flight_controller import FlightController
from .comms import DroneTransmitter
from .anomaly_injector import AnomalyInjector

__all__ = [
    "Drone",
    "DroneConfig",
    "DroneFleet",
    "FlightPlan",
    "Waypoint",
    "GeoPosition",
    "DroneState",
    "DroneStatus",
    "CapturedPayload",
    "SensorType",
    "SensorSuite",
    "FlightController",
    "DroneTransmitter",
    "AnomalyInjector",
]
