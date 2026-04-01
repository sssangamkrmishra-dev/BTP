# Drone Simulator

Realistic RPA/Drone simulator for the **Multi-Layered Malware Detection and Threat Prevention System**. Generates flight telemetry, sensor payloads (images, video, telemetry JSON, logs), and drone submissions in the exact format consumed by the [Ingestion Interceptor](../ingestion_interceptor/).

## Position in Architecture

```
┌──────────────────────┐
│  Drone / RPA Platform│
│                      │
│  ┌────────────────┐  │
│  │ Flight Control │  │    Simulates GPS waypoint navigation,
│  │ (flight_ctrl)  │  │    altitude hold, battery drain, heading
│  └───────┬────────┘  │
│          │           │
│  ┌───────▼────────┐  │
│  │  Sensor Suite  │  │    Camera (JPEG), Video (MP4),
│  │  (sensors.py)  │  │    Telemetry (JSON), Logs (TXT)
│  └───────┬────────┘  │
│          │           │
│  ┌───────▼────────┐  │
│  │  Transmitter   │  │    Formats DroneSubmission JSON,
│  │  (comms.py)    │──────►  HMAC signing, transmit
│  └────────────────┘  │
│                      │
│  ┌────────────────┐  │
│  │ Anomaly Inject │  │    Spoofed GPS, executables,
│  │ (anomaly_inj.) │  │    path traversal (for testing)
│  └────────────────┘  │
└──────────────────────┘
           │
           │  DroneSubmission JSON
           ▼
┌──────────────────────┐
│ Ingestion Interceptor│
│ (ingestion_intercep.)│
└──────────┬───────────┘
           │
           ▼
  Game-Theoretic Threat Estimator → Malware Detection → ...
```

## Module Structure

```
drone/
├── __init__.py              # Public API exports
├── config.py                # DroneConfig dataclass (30+ parameters)
├── models.py                # DroneState, FlightPlan, Waypoint, GeoPosition, CapturedPayload
├── flight_controller.py     # Flight dynamics engine
├── sensors.py               # Sensor suite (camera, video, telemetry, logs)
├── comms.py                 # Submission formatting + HMAC signing + transmit
├── anomaly_injector.py      # Test anomaly injection (spoofed GPS, executables, etc.)
├── drone.py                 # Main Drone class
├── fleet.py                 # DroneFleet (multi-drone management)
├── run_demo.py              # Demo: 3-drone fleet → ingestion interceptor
├── README.md                # This file
└── tests/
    ├── __init__.py
    └── test_drone.py        # 30 unit tests
```

## Quick Start

### Single Drone — Quick Capture

```python
from drone import Drone, DroneConfig

drone = Drone(DroneConfig(drone_id="DRN-001"))
submission = drone.quick_capture("image")

# submission is a dict ready for IngestionInterceptor.process()
print(submission["drone_id"])       # "DRN-001"
print(submission["payloads"][0])    # {type: "image", filename: "...", mime: "image/jpeg", ...}
```

Capture types: `"image"`, `"video"`, `"telemetry"`, `"log"`, `"mixed"` (image + video + telemetry).

### Full Mission with Flight Plan

```python
from drone import Drone, DroneConfig, FlightPlan, Waypoint

drone = Drone(DroneConfig(
    drone_id="DRN-001",
    firmware_version="v2.1.0",
    operator_id="OP-12",
    camera_model="CAM-X1000",
))

plan = FlightPlan(
    mission_zone="zone-alpha",
    mission_sensitivity="high",
    waypoints=[
        Waypoint(lat=12.975, lon=77.590, alt=100, action="capture_image"),
        Waypoint(lat=12.978, lon=77.593, alt=120, action="record_video", loiter_time_sec=5),
        Waypoint(lat=12.973, lon=77.596, alt=80,  action="capture_image"),
    ],
)

state = drone.fly_mission(plan)

print(f"Battery: {state.battery_pct:.1f}%")
print(f"Distance: {state.total_distance_m:.0f} m")
print(f"Payloads: {state.payloads_captured}")

submissions = drone.get_submissions()  # list of DroneSubmission dicts
```

### Waypoint Actions

| Action | What Happens |
|---|---|
| `capture_image` | Takes a still photo (JPEG, 200-800 KB) |
| `record_video` | Records video (MP4, ~3 MB/sec x loiter time) |
| `capture_telemetry` | Saves telemetry snapshot (JSON) |
| `hover` / `loiter` | Holds position for `loiter_time_sec` |
| `flyover` | Transits without stopping |

### Direct Pipeline Integration

```python
from drone import Drone, DroneConfig
from ingestion_interceptor import IngestionInterceptor

# Setup
drone = Drone(DroneConfig(drone_id="DRN-001"))
interceptor = IngestionInterceptor(
    device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
    zone_risk_lookup={"zone-alpha": 0.3},
)

# Capture and transmit
drone.quick_capture("mixed")
results = drone.transmit_all(interceptor)

for r in results:
    print(f"Success: {r.success}, Auth: {r.ingest_metadata.auth_result}")
    print(f"Flags: {r.ingest_metadata.insecure_flags}")
```

### Fleet Operations

```python
from drone import DroneConfig, DroneFleet, FlightPlan, Waypoint

fleet = DroneFleet()
fleet.add_drone(DroneConfig(drone_id="DRN-001"))
fleet.add_drone(DroneConfig(drone_id="DRN-002"))
fleet.add_drone(DroneConfig(drone_id="DRN-003"))

# Assign different missions
fleet.assign_mission("DRN-001", FlightPlan(
    mission_zone="zone-alpha",
    waypoints=[Waypoint(12.975, 77.590, 100, action="capture_image")],
))
fleet.assign_mission("DRN-002", FlightPlan(
    mission_zone="zone-charlie",
    waypoints=[Waypoint(13.040, 77.600, 150, action="record_video")],
))

# Execute all missions
fleet.execute_all()

# Collect all submissions from all drones
all_submissions = fleet.collect_submissions()
print(f"Total submissions: {len(all_submissions)}")

# Or transmit all to interceptor
results = fleet.transmit_all(interceptor)
```

### HMAC Signing

```python
drone = Drone(DroneConfig(
    drone_id="DRN-001",
    signing_enabled=True,
    signing_key="shared_secret_key_001",
))

submission = drone.quick_capture("telemetry")
print(submission["signature"])  # "hmac-sha256:a3b1c4d5..."
```

The interceptor can verify this signature using the same shared key.

### Anomaly Injection (for Testing)

Inject realistic attack scenarios to test the detection pipeline:

```python
drone = Drone(DroneConfig(
    drone_id="DRN-999",
    inject_anomalies=True,
    anomaly_probability=0.8,  # 80% chance per capture
))

submission = drone.quick_capture("image")
# May contain injected anomalies:
#   - Spoofed GPS coordinates (huge lat/lon jump)
#   - Negative speed in telemetry
#   - Battery > 100%
#   - Executable payload (update_patch.exe)
#   - Path traversal filename (../../../etc/shadow)
#   - Double extension (report.pdf.exe)
#   - Encrypted archive payload
#   - Oversized metadata field (50 KB string)
```

Available anomaly types:

| Anomaly | Target | What the Interceptor Should Detect |
|---|---|---|
| `spoofed_gps` | Telemetry | Geolocation validation failure |
| `negative_speed` | Telemetry | Telemetry anomaly: negative speed |
| `battery_overflow` | Telemetry | Telemetry anomaly: battery > 100% |
| `signal_dropout` | Telemetry | Signal strength = 0 |
| `executable_injection` | Payload | `executable_file` + `suspicious_mime` flags |
| `encrypted_payload` | Payload | `encrypted_payload` + `nested_archive` flags |
| `path_traversal` | Payload | `path_traversal_in_filename` validation error |
| `double_extension` | Payload | `double_extension` flag |
| `oversized_metadata` | Metadata | Pre-sanitization truncation in metadata extractor |

## Configuration Reference

`DroneConfig` parameters grouped by category:

### Identity

| Parameter | Default | Description |
|---|---|---|
| `drone_id` | `"DRN-001"` | Unique drone identifier |
| `firmware_version` | `"v2.1.0"` | Firmware version string |
| `operator_id` | `"OP-01"` | Operator identifier |
| `platform_model` | `"RPA-MK4"` | Platform/airframe model |

### Flight

| Parameter | Default | Description |
|---|---|---|
| `max_speed_ms` | `20.0` | Maximum speed (m/s) |
| `cruise_speed_ms` | `12.0` | Typical cruise speed (m/s) |
| `max_altitude_m` | `500.0` | Altitude ceiling AGL (m) |
| `climb_rate_ms` | `3.0` | Vertical climb rate (m/s) |
| `turn_rate_deg_s` | `45.0` | Max heading change per second |

### Battery

| Parameter | Default | Description |
|---|---|---|
| `battery_capacity_wh` | `150.0` | Total battery capacity (Wh) |
| `battery_initial_pct` | `100.0` | Starting charge (%) |
| `power_idle_w` | `15.0` | Idle/hover power draw (W) |
| `power_per_speed_w` | `3.5` | Additional W per m/s of speed |
| `power_per_altitude_w` | `0.02` | Additional W per meter altitude |
| `low_battery_threshold` | `20.0` | Low battery warning (%) |
| `critical_battery_threshold` | `10.0` | Emergency RTL threshold (%) |

### Sensors

| Parameter | Default | Description |
|---|---|---|
| `camera_model` | `"CAM-X1000"` | Camera model name |
| `camera_resolution` | `"4K"` | Resolution: 1080p, 4K, 8K |
| `video_fps` | `30` | Video frame rate |
| `image_size_bytes_range` | `(200000, 800000)` | Image file size range |
| `video_size_bytes_per_sec` | `3000000` | Video data rate (~3 MB/s) |

### Communication

| Parameter | Default | Description |
|---|---|---|
| `signal_strength_base` | `85.0` | Signal at launch (%) |
| `signal_decay_per_km` | `5.0` | Signal loss per km from home |
| `signing_enabled` | `False` | Enable HMAC submission signing |
| `signing_key` | `""` | HMAC shared secret |

### Anomaly Injection

| Parameter | Default | Description |
|---|---|---|
| `inject_anomalies` | `False` | Enable anomaly injection |
| `anomaly_probability` | `0.0` | Probability per capture (0.0-1.0) |
| `anomaly_types` | all types | List of injectable anomaly types |

## Output Format

The drone produces submissions in the exact JSON format the Ingestion Interceptor expects:

```json
{
  "drone_id": "DRN-001",
  "timestamp": "2025-10-13T03:00:12Z",
  "mission_id": "MSN-A1B2C3",
  "mission_zone": "zone-alpha",
  "geo": {"lat": 12.971598, "lon": 77.594566, "alt": 100.0},
  "payloads": [
    {
      "type": "image",
      "filename": "DRN-001_img_1697166012_a1b2c3.jpg",
      "mime": "image/jpeg",
      "size_bytes": 524288,
      "encryption": false,
      "container": false,
      "checksum": "sha256hex...",
      "uri": "file:/path/to/drone_remote_store/DRN-001/..."
    }
  ],
  "telemetry": {
    "speed": 12.5,
    "heading": 145.2,
    "battery": 78.4,
    "signal_strength": 82.1,
    "vertical_speed": 0.0,
    "temperature": 25.0,
    "distance_from_home": 1250.3
  },
  "signature": null,
  "firmware_version": "v2.1.0",
  "operator_id": "OP-12",
  "additional_metadata": {
    "camera_model": "CAM-X1000",
    "platform_model": "RPA-MK4",
    "frame_rate": 30,
    "mission_sensitivity": "high"
  }
}
```

## Sensor File Generation

The sensor suite creates actual files on disk:

| Sensor | Format | Content |
|---|---|---|
| Still Camera | `.jpg` | JPEG magic bytes + simulated EXIF (GPS, camera model, timestamp) + random pixel data |
| Video Camera | `.mp4` | MP4 ftyp box + moov stub + random mdat (sized by duration x bitrate) |
| Telemetry | `.json` | Full drone state snapshot (position, telemetry, status, warnings) |
| Log | `.txt` | Timestamped mission log entries |

Files are written to `{storage_base_path}/{drone_id}/` and referenced via `uri` in the submission.

## Running Tests

```bash
python -m unittest drone.tests.test_drone -v
```

30 tests covering: config, models, flight controller, sensors, transmitter, signing, drone operations, fleet, anomaly injection, and end-to-end pipeline integration.

## Running Demo

```bash
python -m drone.run_demo
```

Runs a 3-drone fleet (trusted, suspicious with anomalies, patrol) through full missions and feeds submissions to the Ingestion Interceptor.

## Dependencies

**None** — uses Python stdlib only (`hashlib`, `json`, `os`, `math`, `random`, `uuid`, `dataclasses`).
