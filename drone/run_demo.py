"""
Demo: Drone Simulator → Ingestion Interceptor pipeline.
Runs the same fleet through both transport modes back-to-back:

  Phase 1 — in_process: each drone calls interceptor.process() directly
  Phase 2 — packet:     drones serialize to binary, fragment into UDP
                        packets, sign with HMAC, and send over the wire
                        to a PacketReceiver running in a daemon thread.

Phase 2 also demonstrates the receiver's truncation defenses by enabling
a 5% packet-loss simulation on the suspicious drone — some sessions will
arrive incomplete and be flagged.

Run: python -m drone.run_demo
"""

import json
import os
import sys
import time

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

    # ── PHASE 1: in_process transport ──────────────────────────────────
    print(f"\n{'=' * 80}")
    print("  PHASE 1 — IN-PROCESS TRANSPORT (direct interceptor.process() calls)")
    print(f"{'=' * 80}")

    try:
        from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

        device_registry = {
            "DRN-001": {"trusted": True, "reputation": 0.95},
            "DRN-002": {"trusted": False, "reputation": 0.4},
            "DRN-003": {"trusted": True, "reputation": 0.9},
        }
        zone_risk_lookup = {
            "zone-alpha": 0.2, "zone-bravo": 0.1, "zone-charlie": 0.8,
        }
        # Shared HMAC keys for the per-packet wire authentication used in Phase 2
        key_store = {
            "DRN-001": "shared_secret_001",
            "DRN-002": "shared_secret_002",
            "DRN-003": "shared_secret_003",
        }

        interceptor = IngestionInterceptor(
            config=InterceptorConfig(storage_backend="filesystem", storage_base_path=storage),
            device_registry=device_registry,
            zone_risk_lookup=zone_risk_lookup,
            key_store=key_store,
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

        print(f"\n  Interceptor stats (in_process): {interceptor.stats}")

    except ImportError:
        print("\n  ingestion_interceptor not available — printing raw submissions instead")
        for sub in submissions:
            print(json.dumps(sub, indent=2, default=str)[:500] + "...")
        return

    # ── PHASE 2: packet transport over UDP ─────────────────────────────
    print(f"\n{'=' * 80}")
    print("  PHASE 2 — WIRE TRANSPORT (UDP packets, custom binary framing)")
    print(f"{'=' * 80}")
    print("  • Drones marshal each submission to binary (TLV format)")
    print("  • Fragment into 1024-byte chunks, sign each with HMAC-SHA256")
    print("  • Send over UDP to PacketReceiver running on a daemon thread")
    print("  • Suspicious drone simulates 25% packet loss to demonstrate")
    print("    truncation detection by the receiver")

    # Spin up a fresh interceptor + packet listener on an ephemeral port
    interceptor2 = IngestionInterceptor(
        config=InterceptorConfig(storage_backend="filesystem", storage_base_path=storage),
        device_registry=device_registry,
        zone_risk_lookup=zone_risk_lookup,
        key_store=key_store,
    )
    interceptor2.start_packet_listener(host="127.0.0.1", port=0)
    bound_host, bound_port = interceptor2.packet_receiver.bound_address
    print(f"\n  PacketReceiver bound to {bound_host}:{bound_port}")

    # Build a parallel fleet in packet mode pointing at the receiver
    packet_fleet = DroneFleet()
    packet_fleet.add_drone(DroneConfig(
        drone_id="DRN-001", firmware_version="v2.1.0", operator_id="OP-12",
        camera_model="CAM-X1000", storage_base_path=storage,
        home_position=(12.971598, 77.594566, 0.0),
        transport_mode="packet", signing_enabled=True,
        signing_key=key_store["DRN-001"],
        interceptor_host=bound_host, interceptor_port=bound_port,
    ))
    packet_fleet.add_drone(DroneConfig(
        drone_id="DRN-002", firmware_version="v1.1.9", operator_id="OP-23",
        camera_model="CAM-STD-1", storage_base_path=storage,
        home_position=(13.035, 77.597, 0.0),
        inject_anomalies=True, anomaly_probability=0.8,
        transport_mode="packet", signing_enabled=True,
        signing_key=key_store["DRN-002"],
        interceptor_host=bound_host, interceptor_port=bound_port,
        simulate_packet_loss=0.25,  # 25% loss to reliably demonstrate truncation defense
    ))
    packet_fleet.add_drone(DroneConfig(
        drone_id="DRN-003", firmware_version="v2.3.0", operator_id="OP-33",
        camera_model="CAM-PRO-4K", storage_base_path=storage,
        home_position=(12.967, 77.601, 0.0),
        transport_mode="packet", signing_enabled=True,
        signing_key=key_store["DRN-003"],
        interceptor_host=bound_host, interceptor_port=bound_port,
    ))

    # Run the same missions
    packet_fleet.assign_mission("DRN-001", plan_a)
    packet_fleet.assign_mission("DRN-002", plan_b)
    packet_fleet.assign_mission("DRN-003", plan_c)
    packet_fleet.execute_all()

    # Transmit (fire and forget — no return values in packet mode)
    print("\n  Transmitting via UDP packets...")
    packet_fleet.transmit_all()

    # Allow the receiver thread to process all incoming packets
    time.sleep(1.0)

    # Read packet-side stats
    pstats = interceptor2.packet_stats.to_dict()
    print(f"\n  PacketReceiver stats:")
    for k, v in pstats.items():
        print(f"    {k:<35} {v}")

    print(f"\n  Interceptor stats (packet): {interceptor2.stats}")
    print(f"\n  ↳ {pstats['sessions_completed']} sessions reassembled "
          f"and processed end-to-end over the wire")
    if pstats["sessions_truncated"] > 0:
        print(f"  ↳ {pstats['sessions_truncated']} sessions detected as "
              f"incomplete (truncation defense fired)")
    if pstats["packets_dropped_orphaned"] > 0:
        print(f"  ↳ {pstats['packets_dropped_orphaned']} orphaned packets "
              f"(SESSION_START lost to network loss; remaining CHUNKs had "
              f"nowhere to go)")

    # Cleanup
    for drone_id in packet_fleet.drone_ids:
        d = packet_fleet.get_drone(drone_id)
        if d is not None:
            d._comms.close()
    interceptor2.stop_packet_listener()


if __name__ == "__main__":
    main()
