"""
Main Drone class: the complete drone simulator.

Integrates flight controller, sensor suite, communication layer,
and anomaly injector into a single coherent drone platform that
produces submissions in the exact format expected by the
Ingestion Interceptor.
"""

import logging
import random
from typing import Any, Dict, List, Optional

from .anomaly_injector import AnomalyInjector
from .comms import DroneTransmitter
from .config import DroneConfig
from .flight_controller import FlightController
from .models import (
    CapturedPayload,
    DroneState,
    DroneStatus,
    FlightPlan,
    GeoPosition,
    Waypoint,
)
from .sensors import SensorSuite

logger = logging.getLogger(__name__)


class Drone:
    """
    Complete drone simulator platform.

    Simulates a real Remotely Piloted Aircraft with:
        - Flight dynamics (GPS navigation, altitude, battery drain)
        - Sensor suite (camera, video, telemetry, logs)
        - Communication (submission formatting, HMAC signing)
        - Anomaly injection (for testing the detection pipeline)

    Usage:
        from drone import Drone, DroneConfig, FlightPlan, Waypoint

        # Create drone
        drone = Drone(DroneConfig(drone_id="DRN-001"))

        # Fly a mission
        plan = FlightPlan(
            mission_zone="zone-alpha",
            waypoints=[
                Waypoint(lat=12.975, lon=77.590, alt=100, action="capture_image"),
                Waypoint(lat=12.980, lon=77.595, alt=120, action="record_video"),
            ],
        )
        drone.fly_mission(plan)

        # Get submissions for the ingestion interceptor
        submissions = drone.get_submissions()

        # Or connect directly to the interceptor
        from ingestion_interceptor import IngestionInterceptor
        interceptor = IngestionInterceptor(...)
        results = drone.transmit_all(interceptor)
    """

    def __init__(self, config: Optional[DroneConfig] = None):
        self.config = config or DroneConfig()
        self._flight = FlightController(self.config)
        self._sensors = SensorSuite(self.config)
        self._comms = DroneTransmitter(self.config)
        self._anomaly = AnomalyInjector(self.config)

        self._state = self._flight.initialize_state()
        self._pending_submissions: List[Dict[str, Any]] = []
        self._mission_payloads: List[CapturedPayload] = []
        self._current_plan: Optional[FlightPlan] = None

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def state(self) -> DroneState:
        """Current drone state."""
        return self._state

    @property
    def drone_id(self) -> str:
        return self.config.drone_id

    @property
    def battery(self) -> float:
        return self._state.battery_pct

    @property
    def position(self) -> GeoPosition:
        return self._state.position

    @property
    def status(self) -> DroneStatus:
        return self._state.status

    @property
    def pending_submissions(self) -> List[Dict[str, Any]]:
        """Submissions waiting to be transmitted."""
        return list(self._pending_submissions)

    # ── Mission operations ─────────────────────────────────────────────

    def fly_mission(self, plan: FlightPlan) -> DroneState:
        """
        Execute a complete mission: takeoff, fly waypoints, capture
        payloads at each waypoint, land, and prepare submissions.

        Args:
            plan: FlightPlan with waypoints and actions.

        Returns:
            Final drone state after mission.
        """
        self._current_plan = plan
        self._mission_payloads = []
        logger.info("[%s] Starting mission %s in %s",
                     self.drone_id, plan.mission_id, plan.mission_zone)

        # Takeoff
        first_alt = plan.waypoints[0].alt if plan.waypoints else 50.0
        self._state = self._flight.takeoff(self._state, target_alt=first_alt)
        self._state.active_sensors = ["gps", "imu", "barometer"]
        logger.info("[%s] Takeoff complete, alt=%.1fm, battery=%.1f%%",
                     self.drone_id, self._state.position.alt, self._state.battery_pct)

        # Fly each waypoint
        for i, wp in enumerate(plan.waypoints):
            # Navigate to waypoint
            while not self._flight.has_reached_waypoint(self._state, wp):
                self._state = self._flight.navigate_to_waypoint(self._state, wp, dt_sec=1.0)

                # Anomaly injection on telemetry
                self._state = self._anomaly.maybe_inject_telemetry(self._state)

                # Emergency check
                if self._state.status == DroneStatus.EMERGENCY:
                    logger.warning("[%s] EMERGENCY at waypoint %d, aborting",
                                    self.drone_id, i)
                    break

            if self._state.status == DroneStatus.EMERGENCY:
                break

            # Execute waypoint action
            self._execute_waypoint_action(wp)
            logger.info("[%s] Waypoint %d/%d complete: %s | battery=%.1f%%",
                         self.drone_id, i + 1, len(plan.waypoints),
                         wp.action, self._state.battery_pct)

        # Always capture a telemetry snapshot at end of mission
        telem = self._sensors.capture_telemetry(self._state)
        self._mission_payloads.append(telem)

        # Land
        self._state = self._flight.land(self._state)
        logger.info("[%s] Landed. Battery=%.1f%%, payloads=%d",
                     self.drone_id, self._state.battery_pct, len(self._mission_payloads))

        # Anomaly injection on payloads
        self._mission_payloads = self._anomaly.maybe_inject_payload(self._mission_payloads)

        # Build submission
        additional_meta: Dict[str, Any] = {
            "camera_model": self.config.camera_model,
            "platform_model": self.config.platform_model,
            "frame_rate": self.config.video_fps,
            "mission_sensitivity": plan.mission_sensitivity,
        }
        additional_meta = self._anomaly.maybe_inject_metadata(additional_meta)

        submission = self._comms.build_submission(
            state=self._state,
            payloads=self._mission_payloads,
            mission_id=plan.mission_id,
            mission_zone=plan.mission_zone,
            additional_metadata=additional_meta,
        )
        self._pending_submissions.append(submission)

        self._state.payloads_captured += len(self._mission_payloads)
        return self._state

    def quick_capture(self, capture_type: str = "image") -> Dict[str, Any]:
        """
        Quick single-capture without a full flight plan.
        Useful for generating individual test submissions.

        Args:
            capture_type: "image", "video", "telemetry", "log", or "mixed"

        Returns:
            The formatted submission dict.
        """
        payloads: List[CapturedPayload] = []

        if capture_type == "image":
            payloads.append(self._sensors.capture_image(self._state))
        elif capture_type == "video":
            payloads.append(self._sensors.capture_video(self._state, duration_sec=random.randint(3, 10)))
        elif capture_type == "telemetry":
            payloads.append(self._sensors.capture_telemetry(self._state))
        elif capture_type == "log":
            payloads.append(self._sensors.capture_log(self._state))
        elif capture_type == "mixed":
            payloads.append(self._sensors.capture_image(self._state))
            payloads.append(self._sensors.capture_video(self._state))
            payloads.append(self._sensors.capture_telemetry(self._state))
        else:
            payloads.append(self._sensors.capture_telemetry(self._state))

        payloads = self._anomaly.maybe_inject_payload(payloads)

        submission = self._comms.build_submission(
            state=self._state,
            payloads=payloads,
        )
        self._pending_submissions.append(submission)
        return submission

    def get_submissions(self) -> List[Dict[str, Any]]:
        """Return all pending submissions and clear the queue."""
        subs = list(self._pending_submissions)
        self._pending_submissions.clear()
        return subs

    def transmit_all(self, interceptor: Any) -> List[Any]:
        """
        Transmit all pending submissions to an IngestionInterceptor.

        Args:
            interceptor: An IngestionInterceptor instance.

        Returns:
            List of IngestResult objects.
        """
        results = []
        for sub in self._pending_submissions:
            result = self._comms.transmit(sub, interceptor)
            results.append(result)
        self._pending_submissions.clear()
        return results

    def recharge(self, to_pct: float = 100.0) -> None:
        """Recharge battery to specified percentage."""
        self._state.battery_pct = min(100.0, to_pct)
        self._state.battery_wh_remaining = (
            self.config.battery_capacity_wh * self._state.battery_pct / 100.0
        )
        self._state.status = DroneStatus.IDLE
        self._state.warnings = [w for w in self._state.warnings
                                if w not in ("LOW_BATTERY", "CRITICAL_BATTERY")]

    def reset(self) -> None:
        """Full reset: re-initialize state, clear queues."""
        self._state = self._flight.initialize_state()
        self._pending_submissions.clear()
        self._mission_payloads.clear()
        self._anomaly.reset()

    # ── Private ────────────────────────────────────────────────────────

    def _execute_waypoint_action(self, wp: Waypoint) -> None:
        """Execute the sensor action at a waypoint."""
        if wp.action == "capture_image":
            self._state.active_sensors = ["camera_still"]
            payload = self._sensors.capture_image(self._state)
            self._mission_payloads.append(payload)

        elif wp.action == "record_video":
            self._state.active_sensors = ["camera_video"]
            duration = max(3, int(wp.loiter_time_sec)) if wp.loiter_time_sec > 0 else 5
            payload = self._sensors.capture_video(self._state, duration_sec=duration)
            self._mission_payloads.append(payload)

        elif wp.action == "capture_telemetry":
            payload = self._sensors.capture_telemetry(self._state)
            self._mission_payloads.append(payload)

        elif wp.action == "hover" or wp.action == "loiter":
            pass  # just hold position, handled by flight controller

        elif wp.action == "flyover":
            pass  # no action, just transit

        else:
            # Default: capture image
            payload = self._sensors.capture_image(self._state)
            self._mission_payloads.append(payload)
