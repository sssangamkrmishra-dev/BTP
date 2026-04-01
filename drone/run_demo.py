"""
Demo: Drone Simulator → Ingestion Interceptor pipeline.
Run: python -m drone.run_demo
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drone import Drone, DroneConfig, DroneFleet, FlightPlan, Waypoint


def main():
    print("=" * 80)
    print("  DRONE SIMULATOR — FULL PIPELINE DEMO")
    print("=" * 80)

    # ── Setup fleet ────────────────────────────────────────────────────
    storage = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "drone_remote_store")

    fleet = DroneFleet()

    # Normal trusted drone
    fleet.add_drone(DroneConfig(
        drone_id="DRN-001", firmware_version="v2.1.0", operator_id="OP-12",
        camera_model="CAM-X1000", storage_base_path=storage,
        home_position=(12.971598, 77.594566, 0.0),
    ))

    # Suspicious drone with anomaly injection
    fleet.add_drone(DroneConfig(
        drone_id="DRN-002", firmware_version="v1.1.9", operator_id="OP-23",
        camera_model="CAM-STD-1", storage_base_path=storage,
        home_position=(13.035, 77.597, 0.0),
        inject_anomalies=True, anomaly_probability=0.8,
    ))

    # Patrol drone
    fleet.add_drone(DroneConfig(
        drone_id="DRN-003", firmware_version="v2.3.0", operator_id="OP-33",
        camera_model="CAM-PRO-4K", storage_base_path=storage,
        home_position=(12.967, 77.601, 0.0),
    ))

    # ── Mission plans ──────────────────────────────────────────────────

    plan_a = FlightPlan(
        mission_zone="zone-alpha",
        mission_sensitivity="medium",
        waypoints=[
            Waypoint(12.975, 77.590, 100, action="capture_image"),
            Waypoint(12.978, 77.593, 120, action="record_video", loiter_time_sec=5),
            Waypoint(12.973, 77.596, 80, action="capture_image"),
        ],
    )

    plan_b = FlightPlan(
        mission_zone="zone-charlie",
        mission_sensitivity="high",
        waypoints=[
            Waypoint(13.040, 77.600, 150, action="record_video", loiter_time_sec=3),
        ],
    )

    plan_c = FlightPlan(
        mission_zone="zone-bravo",
        mission_sensitivity="low",
        waypoints=[
            Waypoint(12.970, 77.605, 50, action="capture_telemetry"),
            Waypoint(12.965, 77.608, 60, action="flyover"),
        ],
    )

    # ── Execute missions ───────────────────────────────────────────────
    fleet.assign_mission("DRN-001", plan_a)
    fleet.assign_mission("DRN-002", plan_b)
    fleet.assign_mission("DRN-003", plan_c)

    print("\nExecuting fleet missions...")
    results = fleet.execute_all()

    for drone_id, info in results.items():
        print(f"\n  {drone_id}: status={info['status']}, battery={info['battery']}%, "
              f"payloads={info['payloads']}, distance={info['distance_m']}m")
        if info["warnings"]:
            print(f"    warnings: {info['warnings']}")

    # ── Collect submissions ────────────────────────────────────────────
    submissions = fleet.collect_submissions()
    print(f"\n{'─' * 80}")
    print(f"  Collected {len(submissions)} submissions from fleet")
    print(f"{'─' * 80}")

    for i, sub in enumerate(submissions):
        print(f"\n  Submission {i+1}: drone={sub['drone_id']}, zone={sub.get('mission_zone')}")
        print(f"    payloads: {len(sub['payloads'])}")
        for j, p in enumerate(sub["payloads"]):
            print(f"      [{j+1}] {p['filename']} ({p['type']}, {p['size_bytes']:,} bytes"
                  f"{', encrypted' if p.get('encryption') else ''})")
        print(f"    telemetry: speed={sub['telemetry']['speed']}m/s, "
              f"battery={sub['telemetry']['battery']}%")

    # ── Feed to Ingestion Interceptor ──────────────────────────────────
    print(f"\n{'=' * 80}")
    print("  FEEDING TO INGESTION INTERCEPTOR")
    print(f"{'=' * 80}")

    try:
        from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

        interceptor = IngestionInterceptor(
            config=InterceptorConfig(storage_backend="filesystem", storage_base_path=storage),
            device_registry={
                "DRN-001": {"trusted": True, "reputation": 0.95},
                "DRN-002": {"trusted": False, "reputation": 0.4},
                "DRN-003": {"trusted": True, "reputation": 0.9},
            },
            zone_risk_lookup={
                "zone-alpha": 0.2, "zone-bravo": 0.1, "zone-charlie": 0.8,
            },
        )

        print(f"\n{'DRONE':<10} {'AUTH':<15} {'FLAGS':<40} {'FILES':<6} {'STATUS'}")
        print("─" * 80)

        for sub in submissions:
            result = interceptor.process(sub)
            if result.success:
                flags = ", ".join(result.ingest_metadata.insecure_flags) or "none"
                print(f"{sub['drone_id']:<10} "
                      f"{result.ingest_metadata.auth_result:<15} "
                      f"{flags:<40} "
                      f"{result.ingest_metadata.num_files:<6} OK")
            else:
                print(f"{sub['drone_id']:<10} {'REJECTED':<15} {str(result.errors)[:40]:<40} {'--':<6} FAIL")

        print(f"\n  Interceptor stats: {interceptor.stats}")

    except ImportError:
        print("\n  ingestion_interceptor not available — printing raw submissions instead")
        for sub in submissions:
            print(json.dumps(sub, indent=2, default=str)[:500] + "...")


if __name__ == "__main__":
    main()
