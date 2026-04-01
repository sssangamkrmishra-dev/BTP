"""
Tests for the Drone Simulator module.
Run: python -m unittest drone.tests.test_drone -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from drone import (
    Drone, DroneConfig, DroneFleet, FlightPlan, Waypoint,
    GeoPosition, DroneState, DroneStatus, FlightController,
    SensorSuite, DroneTransmitter, AnomalyInjector,
)


class TestDroneConfig(unittest.TestCase):

    def test_defaults(self):
        c = DroneConfig()
        self.assertEqual(c.drone_id, "DRN-001")
        self.assertEqual(c.max_speed_ms, 20.0)
        self.assertEqual(c.battery_initial_pct, 100.0)

    def test_custom(self):
        c = DroneConfig(drone_id="DRN-X", cruise_speed_ms=8.0, battery_capacity_wh=200.0)
        self.assertEqual(c.drone_id, "DRN-X")
        self.assertEqual(c.cruise_speed_ms, 8.0)


class TestModels(unittest.TestCase):

    def test_geo_position_distance(self):
        a = GeoPosition(lat=12.971598, lon=77.594566, alt=0)
        b = GeoPosition(lat=12.971598, lon=77.594566, alt=0)
        self.assertAlmostEqual(a.distance_to(b), 0.0, delta=1.0)

    def test_geo_position_nonzero_distance(self):
        a = GeoPosition(lat=12.97, lon=77.59, alt=0)
        b = GeoPosition(lat=12.98, lon=77.60, alt=0)
        dist = a.distance_to(b)
        self.assertGreater(dist, 1000)  # ~1.5 km

    def test_waypoint_to_dict(self):
        wp = Waypoint(lat=12.0, lon=77.0, alt=100, action="capture_image")
        d = wp.to_dict()
        self.assertEqual(d["action"], "capture_image")

    def test_flight_plan_auto_mission_id(self):
        plan = FlightPlan()
        self.assertTrue(plan.mission_id.startswith("MSN-"))

    def test_drone_state_telemetry_dict(self):
        state = DroneState()
        state.speed_ms = 12.5
        state.heading_deg = 145.2
        state.battery_pct = 78.4
        t = state.telemetry_dict()
        self.assertEqual(t["speed"], 12.5)
        self.assertEqual(t["heading"], 145.2)


class TestFlightController(unittest.TestCase):

    def setUp(self):
        self.config = DroneConfig(home_position=(12.971598, 77.594566, 0.0))
        self.fc = FlightController(self.config)

    def test_initialize_state(self):
        state = self.fc.initialize_state()
        self.assertEqual(state.status, DroneStatus.IDLE)
        self.assertAlmostEqual(state.battery_pct, 100.0, delta=0.1)

    def test_takeoff(self):
        state = self.fc.initialize_state()
        state = self.fc.takeoff(state, target_alt=50.0)
        self.assertEqual(state.position.alt, 50.0)
        self.assertLess(state.battery_pct, 100.0)
        self.assertEqual(state.status, DroneStatus.HOVERING)

    def test_land(self):
        state = self.fc.initialize_state()
        state = self.fc.takeoff(state, 50.0)
        state = self.fc.land(state)
        self.assertEqual(state.position.alt, 0.0)
        self.assertEqual(state.status, DroneStatus.RETURNED)

    def test_navigate(self):
        state = self.fc.initialize_state()
        state = self.fc.takeoff(state, 100.0)
        wp = Waypoint(lat=12.975, lon=77.598, alt=100)
        initial_dist = state.position.distance_to(
            GeoPosition(lat=wp.lat, lon=wp.lon, alt=wp.alt)
        )
        state = self.fc.navigate_to_waypoint(state, wp, dt_sec=1.0)
        new_dist = state.position.distance_to(
            GeoPosition(lat=wp.lat, lon=wp.lon, alt=wp.alt)
        )
        self.assertLess(new_dist, initial_dist)

    def test_battery_drains_during_flight(self):
        state = self.fc.initialize_state()
        state = self.fc.takeoff(state, 100.0)
        batt_before = state.battery_pct
        wp = Waypoint(lat=12.980, lon=77.600, alt=100)
        for _ in range(30):
            state = self.fc.navigate_to_waypoint(state, wp, dt_sec=1.0)
        self.assertLess(state.battery_pct, batt_before)


class TestSensorSuite(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = DroneConfig(
            drone_id="TEST-001",
            storage_base_path=self.tmpdir,
        )
        self.sensors = SensorSuite(self.config)
        self.state = DroneState(
            position=GeoPosition(12.97, 77.59, 100),
            speed_ms=10.0,
            battery_pct=80.0,
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_capture_image(self):
        p = self.sensors.capture_image(self.state)
        self.assertEqual(p.type, "image")
        self.assertEqual(p.mime, "image/jpeg")
        self.assertTrue(p.filename.endswith(".jpg"))
        self.assertTrue(os.path.isfile(p.local_path))
        self.assertGreater(p.size_bytes, 0)
        self.assertEqual(len(p.checksum), 64)

    def test_capture_video(self):
        p = self.sensors.capture_video(self.state, duration_sec=2)
        self.assertEqual(p.type, "video")
        self.assertEqual(p.mime, "video/mp4")
        self.assertTrue(os.path.isfile(p.local_path))

    def test_capture_telemetry(self):
        p = self.sensors.capture_telemetry(self.state)
        self.assertEqual(p.type, "telemetry")
        self.assertEqual(p.mime, "application/json")
        # Verify JSON content
        with open(p.local_path) as f:
            data = json.load(f)
        self.assertIn("telemetry", data)
        self.assertIn("position", data)

    def test_capture_log(self):
        p = self.sensors.capture_log(self.state)
        self.assertEqual(p.type, "text")
        self.assertTrue(os.path.isfile(p.local_path))

    def test_payload_submission_format(self):
        p = self.sensors.capture_image(self.state)
        d = p.to_submission_dict()
        self.assertIn("type", d)
        self.assertIn("filename", d)
        self.assertIn("mime", d)
        self.assertIn("size_bytes", d)
        self.assertIn("encryption", d)
        self.assertIn("container", d)


class TestDroneTransmitter(unittest.TestCase):

    def test_build_submission_format(self):
        config = DroneConfig(drone_id="DRN-TX")
        tx = DroneTransmitter(config)
        state = DroneState(position=GeoPosition(12.97, 77.59, 100))

        from drone.models import CapturedPayload
        payload = CapturedPayload(
            type="image", filename="test.jpg", mime="image/jpeg",
            size_bytes=50000, checksum="abc123",
        )
        sub = tx.build_submission(state, [payload], mission_id="MSN-001")

        # Verify exact format expected by ingestion interceptor
        self.assertIn("drone_id", sub)
        self.assertIn("timestamp", sub)
        self.assertIn("payloads", sub)
        self.assertIn("telemetry", sub)
        self.assertIn("geo", sub)
        self.assertIn("firmware_version", sub)
        self.assertIn("operator_id", sub)
        self.assertEqual(sub["drone_id"], "DRN-TX")
        self.assertEqual(len(sub["payloads"]), 1)

    def test_signing(self):
        config = DroneConfig(
            drone_id="DRN-SIGN",
            signing_enabled=True,
            signing_key="test_secret_key",
        )
        tx = DroneTransmitter(config)
        state = DroneState(position=GeoPosition(12.97, 77.59, 100))
        from drone.models import CapturedPayload
        payload = CapturedPayload(
            type="telemetry", filename="t.json", mime="application/json", size_bytes=100,
        )
        sub = tx.build_submission(state, [payload])
        self.assertIsNotNone(sub["signature"])
        self.assertTrue(sub["signature"].startswith("hmac-sha256:"))


class TestDrone(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = DroneConfig(
            drone_id="DRN-TEST",
            storage_base_path=self.tmpdir,
        )
        self.drone = Drone(self.config)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_quick_capture_image(self):
        sub = self.drone.quick_capture("image")
        self.assertEqual(sub["drone_id"], "DRN-TEST")
        self.assertEqual(len(sub["payloads"]), 1)
        self.assertEqual(sub["payloads"][0]["type"], "image")

    def test_quick_capture_mixed(self):
        sub = self.drone.quick_capture("mixed")
        self.assertEqual(len(sub["payloads"]), 3)
        types = {p["type"] for p in sub["payloads"]}
        self.assertIn("image", types)
        self.assertIn("video", types)

    def test_fly_mission(self):
        plan = FlightPlan(
            mission_zone="zone-test",
            waypoints=[
                Waypoint(12.975, 77.590, 100, action="capture_image"),
                Waypoint(12.976, 77.591, 100, action="record_video"),
            ],
        )
        state = self.drone.fly_mission(plan)
        self.assertIn(state.status, (DroneStatus.RETURNED, DroneStatus.EMERGENCY))
        subs = self.drone.get_submissions()
        self.assertEqual(len(subs), 1)
        # Should have: image + video + telemetry
        self.assertGreaterEqual(len(subs[0]["payloads"]), 3)

    def test_submissions_cleared_after_get(self):
        self.drone.quick_capture("telemetry")
        subs = self.drone.get_submissions()
        self.assertEqual(len(subs), 1)
        subs2 = self.drone.get_submissions()
        self.assertEqual(len(subs2), 0)

    def test_recharge(self):
        plan = FlightPlan(waypoints=[
            Waypoint(12.975, 77.590, 100, action="flyover"),
        ])
        self.drone.fly_mission(plan)
        self.assertLess(self.drone.battery, 100.0)
        self.drone.recharge()
        self.assertAlmostEqual(self.drone.battery, 100.0, delta=0.1)

    def test_submission_is_interceptor_compatible(self):
        """Verify the submission matches ingestion_interceptor's expected format."""
        sub = self.drone.quick_capture("image")
        # All required fields
        for key in ("drone_id", "timestamp", "payloads"):
            self.assertIn(key, sub)
        # Payload has required fields
        p = sub["payloads"][0]
        for key in ("type", "filename", "mime", "size_bytes", "encryption", "container"):
            self.assertIn(key, p)


class TestDroneFleet(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fleet_operations(self):
        fleet = DroneFleet()
        fleet.add_drone(DroneConfig(drone_id="DRN-A", storage_base_path=self.tmpdir))
        fleet.add_drone(DroneConfig(drone_id="DRN-B", storage_base_path=self.tmpdir))
        self.assertEqual(fleet.fleet_size, 2)
        self.assertIn("DRN-A", fleet.drone_ids)

    def test_fleet_quick_capture_and_collect(self):
        fleet = DroneFleet()
        fleet.add_drone(DroneConfig(drone_id="DRN-A", storage_base_path=self.tmpdir))
        fleet.add_drone(DroneConfig(drone_id="DRN-B", storage_base_path=self.tmpdir))

        fleet.get_drone("DRN-A").quick_capture("image")
        fleet.get_drone("DRN-B").quick_capture("telemetry")

        subs = fleet.collect_submissions()
        self.assertEqual(len(subs), 2)
        ids = {s["drone_id"] for s in subs}
        self.assertEqual(ids, {"DRN-A", "DRN-B"})


class TestAnomalyInjector(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_injection_when_disabled(self):
        config = DroneConfig(inject_anomalies=False, storage_base_path=self.tmpdir)
        injector = AnomalyInjector(config)
        state = DroneState()
        state = injector.maybe_inject_telemetry(state)
        self.assertEqual(len(injector.injected_anomalies), 0)

    def test_injection_when_enabled_high_probability(self):
        config = DroneConfig(
            inject_anomalies=True,
            anomaly_probability=1.0,
            storage_base_path=self.tmpdir,
        )
        injector = AnomalyInjector(config)
        payloads = []
        payloads = injector.maybe_inject_payload(payloads)
        self.assertGreater(len(payloads), 0)
        self.assertGreater(len(injector.injected_anomalies), 0)


class TestPipelineIntegration(unittest.TestCase):
    """Test that drone output feeds correctly into the ingestion interceptor."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_drone_to_interceptor(self):
        """End-to-end: drone generates submission → interceptor processes it."""
        try:
            from ingestion_interceptor import IngestionInterceptor
        except ImportError:
            self.skipTest("ingestion_interceptor not available")

        drone = Drone(DroneConfig(
            drone_id="DRN-001",
            storage_base_path=self.tmpdir,
        ))
        interceptor = IngestionInterceptor(
            device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
            zone_risk_lookup={"zone-alpha": 0.3},
        )

        sub = drone.quick_capture("mixed")
        result = interceptor.process(sub)

        self.assertTrue(result.success)
        self.assertEqual(result.ingest_metadata.drone_id, "DRN-001")
        self.assertEqual(result.ingest_metadata.auth_result, "authenticated")
        self.assertGreater(len(result.artifact_records), 0)


if __name__ == "__main__":
    unittest.main()
