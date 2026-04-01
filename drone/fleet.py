"""
Fleet management: operate multiple drones simultaneously.
Useful for simulating realistic multi-drone operational scenarios.
"""

import logging
from typing import Any, Dict, List, Optional

from .config import DroneConfig
from .drone import Drone
from .models import FlightPlan, Waypoint

logger = logging.getLogger(__name__)


class DroneFleet:
    """
    Manages a fleet of drone simulators.

    Usage:
        fleet = DroneFleet()
        fleet.add_drone(DroneConfig(drone_id="DRN-001"))
        fleet.add_drone(DroneConfig(drone_id="DRN-002"))

        # Assign missions
        fleet.assign_mission("DRN-001", plan_a)
        fleet.assign_mission("DRN-002", plan_b)

        # Execute all missions
        fleet.execute_all()

        # Collect all submissions
        all_subs = fleet.collect_submissions()

        # Or transmit all to interceptor
        results = fleet.transmit_all(interceptor)
    """

    def __init__(self):
        self._drones: Dict[str, Drone] = {}
        self._plans: Dict[str, FlightPlan] = {}

    def add_drone(self, config: DroneConfig) -> Drone:
        """Add a drone to the fleet."""
        drone = Drone(config)
        self._drones[config.drone_id] = drone
        logger.info("Fleet: added %s", config.drone_id)
        return drone

    def get_drone(self, drone_id: str) -> Optional[Drone]:
        """Get a drone by ID."""
        return self._drones.get(drone_id)

    def remove_drone(self, drone_id: str) -> bool:
        """Remove a drone from the fleet."""
        if drone_id in self._drones:
            del self._drones[drone_id]
            self._plans.pop(drone_id, None)
            return True
        return False

    def assign_mission(self, drone_id: str, plan: FlightPlan) -> None:
        """Assign a flight plan to a drone."""
        if drone_id not in self._drones:
            raise ValueError(f"Drone {drone_id} not in fleet")
        self._plans[drone_id] = plan

    def execute_all(self) -> Dict[str, Any]:
        """
        Execute all assigned missions.

        Returns:
            Dict mapping drone_id to final state summary.
        """
        results = {}
        for drone_id, plan in self._plans.items():
            drone = self._drones[drone_id]
            state = drone.fly_mission(plan)
            results[drone_id] = {
                "status": state.status.value,
                "battery": round(state.battery_pct, 1),
                "payloads": state.payloads_captured,
                "distance_m": round(state.total_distance_m, 1),
                "warnings": state.warnings,
            }
        self._plans.clear()
        return results

    def collect_submissions(self) -> List[Dict[str, Any]]:
        """Collect all pending submissions from all drones."""
        all_subs = []
        for drone in self._drones.values():
            all_subs.extend(drone.get_submissions())
        return all_subs

    def transmit_all(self, interceptor: Any) -> Dict[str, List[Any]]:
        """Transmit all pending submissions from all drones to an interceptor."""
        results = {}
        for drone_id, drone in self._drones.items():
            results[drone_id] = drone.transmit_all(interceptor)
        return results

    def recharge_all(self) -> None:
        """Recharge all drones to full battery."""
        for drone in self._drones.values():
            drone.recharge()

    @property
    def drone_ids(self) -> List[str]:
        return list(self._drones.keys())

    @property
    def fleet_size(self) -> int:
        return len(self._drones)

    def fleet_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status summary for all drones."""
        return {
            did: {
                "status": d.status.value,
                "battery": round(d.battery, 1),
                "position": d.position.to_dict(),
            }
            for did, d in self._drones.items()
        }
