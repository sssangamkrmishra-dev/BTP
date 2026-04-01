"""
Flight controller: simulates GPS navigation, altitude hold, battery drain,
and heading management. The core physics engine of the drone simulator.
"""

import math
import random
from typing import Optional

from .config import DroneConfig
from .models import DroneState, DroneStatus, FlightPlan, GeoPosition, Waypoint


class FlightController:
    """
    Simulates drone flight dynamics.

    Responsibilities:
        - Navigate between waypoints (great-circle interpolation)
        - Manage altitude transitions (takeoff, climb, descend, land)
        - Simulate battery drain based on speed, altitude, and payload
        - Update heading toward next waypoint
        - Detect low-battery and trigger RTL (return to launch)
        - Compute signal strength based on distance from home
    """

    def __init__(self, config: DroneConfig):
        self.config = config
        self._home = GeoPosition(
            lat=config.home_position[0],
            lon=config.home_position[1],
            alt=config.home_position[2],
        )

    def initialize_state(self) -> DroneState:
        """Create the initial drone state at the home position."""
        return DroneState(
            status=DroneStatus.IDLE,
            position=GeoPosition(
                lat=self._home.lat,
                lon=self._home.lon,
                alt=0.0,
            ),
            battery_pct=self.config.battery_initial_pct,
            battery_wh_remaining=self.config.battery_capacity_wh
                * (self.config.battery_initial_pct / 100.0),
            signal_strength_pct=self.config.signal_strength_base,
        )

    def takeoff(self, state: DroneState, target_alt: float = 50.0) -> DroneState:
        """Simulate takeoff to a target altitude."""
        state.status = DroneStatus.TAKEOFF
        state.position.alt = min(target_alt, self.config.max_altitude_m)
        state.vertical_speed_ms = self.config.climb_rate_ms
        state.speed_ms = 0.0
        # Battery cost for takeoff (most power-intensive phase)
        energy_wh = (target_alt / self.config.climb_rate_ms) * (
            self.config.power_idle_w + 20.0  # extra hover power during climb
        ) / 3600.0
        state = self._drain_battery(state, energy_wh)
        state.status = DroneStatus.HOVERING
        state.vertical_speed_ms = 0.0
        return state

    def land(self, state: DroneState) -> DroneState:
        """Simulate landing from current altitude."""
        state.status = DroneStatus.LANDING
        descent_time = state.position.alt / self.config.climb_rate_ms
        energy_wh = descent_time * self.config.power_idle_w / 3600.0
        state = self._drain_battery(state, energy_wh)
        state.position.alt = 0.0
        state.speed_ms = 0.0
        state.vertical_speed_ms = 0.0
        state.status = DroneStatus.RETURNED
        return state

    def navigate_to_waypoint(
        self, state: DroneState, waypoint: Waypoint, dt_sec: float = 1.0
    ) -> DroneState:
        """
        Move the drone toward a waypoint for dt_sec seconds.

        Uses equirectangular approximation for short distances.
        Returns updated state (may not have reached waypoint yet).
        """
        target = GeoPosition(lat=waypoint.lat, lon=waypoint.lon, alt=waypoint.alt)
        dist = state.position.distance_to(target)

        speed = waypoint.speed_ms or self.config.cruise_speed_ms
        speed = min(speed, self.config.max_speed_ms)

        # Update heading toward waypoint
        state.heading_deg = self._bearing(state.position, target)

        # Move toward waypoint
        move_dist = speed * dt_sec
        if move_dist >= dist and dist > 0:
            # Arrived at waypoint
            state.position.lat = target.lat
            state.position.lon = target.lon
            move_dist = dist
        elif dist > 0:
            # Interpolate position
            frac = move_dist / dist
            state.position.lat += (target.lat - state.position.lat) * frac
            state.position.lon += (target.lon - state.position.lon) * frac

        # Altitude adjustment
        alt_diff = target.alt - state.position.alt
        max_alt_change = self.config.climb_rate_ms * dt_sec
        if abs(alt_diff) <= max_alt_change:
            state.position.alt = target.alt
            state.vertical_speed_ms = 0.0
        else:
            change = max_alt_change if alt_diff > 0 else -max_alt_change
            state.position.alt += change
            state.vertical_speed_ms = change / dt_sec

        state.speed_ms = speed
        state.status = DroneStatus.IN_FLIGHT
        state.total_distance_m += move_dist

        # Battery drain
        power_w = (
            self.config.power_idle_w
            + self.config.power_per_speed_w * speed
            + self.config.power_per_altitude_w * state.position.alt
            + self.config.power_per_payload_w * len(state.active_sensors)
        )
        energy_wh = power_w * dt_sec / 3600.0
        state = self._drain_battery(state, energy_wh)

        # Update derived values
        state.distance_from_home_m = state.position.distance_to(self._home)
        state.signal_strength_pct = self._compute_signal(state)
        state.uptime_sec += dt_sec

        # Low battery check
        if state.battery_pct <= self.config.critical_battery_threshold:
            state.status = DroneStatus.EMERGENCY
            state.warnings.append("CRITICAL_BATTERY")
        elif state.battery_pct <= self.config.low_battery_threshold:
            if "LOW_BATTERY" not in state.warnings:
                state.warnings.append("LOW_BATTERY")

        return state

    def execute_flight_plan(
        self, state: DroneState, plan: FlightPlan, time_limit_sec: float = 600.0
    ) -> DroneState:
        """
        Execute a complete flight plan: visit all waypoints in sequence.

        Args:
            state: Current drone state.
            plan: Flight plan with waypoints.
            time_limit_sec: Maximum simulation time.

        Returns:
            Updated state after executing the plan.
        """
        if not plan.waypoints:
            return state

        elapsed = 0.0
        dt = 1.0  # simulation tick
        wp_idx = 0

        while wp_idx < len(plan.waypoints) and elapsed < time_limit_sec:
            wp = plan.waypoints[wp_idx]
            target = GeoPosition(lat=wp.lat, lon=wp.lon, alt=wp.alt)

            # Navigate toward waypoint
            state = self.navigate_to_waypoint(state, wp, dt)
            elapsed += dt

            # Check if we reached the waypoint
            dist = state.position.distance_to(target)
            if dist < 5.0:  # within 5 meters = arrived
                # Loiter if needed
                if wp.loiter_time_sec > 0:
                    loiter_steps = int(wp.loiter_time_sec / dt)
                    for _ in range(loiter_steps):
                        state.speed_ms = 0.0
                        state.status = DroneStatus.HOVERING
                        power_w = self.config.power_idle_w + self.config.power_per_altitude_w * state.position.alt
                        state = self._drain_battery(state, power_w * dt / 3600.0)
                        state.uptime_sec += dt
                        elapsed += dt

                state.current_waypoint_idx = wp_idx + 1
                wp_idx += 1

            # Emergency abort
            if state.status == DroneStatus.EMERGENCY:
                break

        return state

    def has_reached_waypoint(self, state: DroneState, waypoint: Waypoint) -> bool:
        """Check if drone is within 5 meters of a waypoint."""
        target = GeoPosition(lat=waypoint.lat, lon=waypoint.lon, alt=waypoint.alt)
        return state.position.distance_to(target) < 5.0

    # ── Private helpers ────────────────────────────────────────────────

    def _drain_battery(self, state: DroneState, energy_wh: float) -> DroneState:
        """Drain battery by the given watt-hours."""
        state.battery_wh_remaining = max(0.0, state.battery_wh_remaining - energy_wh)
        state.battery_pct = (
            state.battery_wh_remaining / self.config.battery_capacity_wh * 100.0
        )
        return state

    def _compute_signal(self, state: DroneState) -> float:
        """Compute signal strength based on distance from home."""
        dist_km = state.distance_from_home_m / 1000.0
        signal = self.config.signal_strength_base - (
            self.config.signal_decay_per_km * dist_km
        )
        # Add some noise
        signal += random.gauss(0, 1.5)
        return max(0.0, min(100.0, round(signal, 1)))

    @staticmethod
    def _bearing(from_pos: GeoPosition, to_pos: GeoPosition) -> float:
        """Compute bearing in degrees from one position to another."""
        lat1 = math.radians(from_pos.lat)
        lat2 = math.radians(to_pos.lat)
        dlon = math.radians(to_pos.lon - from_pos.lon)

        x = math.sin(dlon) * math.cos(lat2)
        y = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)

        bearing = math.degrees(math.atan2(x, y))
        return (bearing + 360) % 360
