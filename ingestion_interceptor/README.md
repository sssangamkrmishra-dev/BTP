# Ingestion Interceptor

Stage 0–7 secure ingestion pipeline for drone/RPA data streams. Validates,
authenticates, analyses, and catalogs incoming submissions before they
enter the operational network.

Two input modes:

- **Wire mode (Stage 0):** receives UDP packets from drones, verifies
  per-packet HMAC-SHA256, reassembles fragmented submissions, decodes
  the binary TLV payload, and feeds it through the 7-stage pipeline.
- **In-process mode (legacy):** accepts a Python `dict` directly via
  `process(drone_json)`. Used by the test suite and the original
  integration demo.

Both modes coexist — pick one (or both) at startup.

Architecture, security defenses, packet format, requirements, and risk
register live in [`docs/design_ingestion_interceptor.md`](../docs/design_ingestion_interceptor.md).

---

## Requirements

- Python 3.9 or later
- **Zero external dependencies** — only the standard library
  (`hashlib`, `hmac`, `dataclasses`, `json`, `uuid`, `logging`, `socket`,
  `struct`, `threading`)

No `pip install` step. No virtualenv required (but recommended).

---

## Quick start

All commands are run from the project root: `/home/sangam/Desktop/BTP/`.

### 1. Run the built-in demo (in-process mode)

```bash
python -m ingestion_interceptor.run_demo
```

Processes 4 hand-crafted sample submissions (clean drone, suspicious
drone, trusted drone, drone with HMAC signature) through the full
pipeline and prints per-stage results, security flags, and final stats.
This is the fastest way to see the pipeline working end-to-end.

### 2. Run the wire-mode demo (UDP packets, side-by-side)

```bash
python -m drone.run_demo
```

Lives in the `drone/` package. Runs a 3-drone fleet through both
transports back-to-back:

- **Phase 1** — in-process: each drone calls `interceptor.process(...)`
  directly.
- **Phase 2** — wire: drones marshal each submission to binary, fragment
  into 1024-byte UDP chunks, sign each with HMAC-SHA256, and send to a
  `PacketReceiver` running on a daemon thread. The suspicious drone
  simulates 25% packet loss to demonstrate the truncation defense.

The output shows packet counts, reassembled sessions, orphaned packets
(SESSION_START lost to network loss), and any truncated sessions.

### 3. Use the interceptor from your own code

#### In-process mode

```python
from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

interceptor = IngestionInterceptor(
    config=InterceptorConfig(),
    device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
    zone_risk_lookup={"zone-alpha": 0.4},
    key_store={"DRN-001": "shared_secret_001"},   # for HMAC signatures
)

result = interceptor.process(drone_json)          # drone_json is a dict
print(result.success, result.ingest_metadata.insecure_flags)
```

#### Wire mode (UDP packets)

```python
from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

interceptor = IngestionInterceptor(
    config=InterceptorConfig(packet_listener_port=5005),
    device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
    zone_risk_lookup={"zone-alpha": 0.4},
    key_store={"DRN-001": "shared_secret_001"},
)

# Spawn the UDP listener on a daemon thread
interceptor.start_packet_listener(host="0.0.0.0", port=5005)
# (use port=0 to let the OS assign an ephemeral port)

# ... drones send packets to UDP 5005 ...
# Reassembled submissions are automatically forwarded into process()

# Live snapshot of packet-level stats
print(interceptor.packet_stats.to_dict())
print(interceptor.stats)        # pipeline-level stats

# Shut down cleanly
interceptor.stop_packet_listener()
```

#### Functional API (backward-compatible one-liner)

```python
from ingestion_interceptor import ingestion_interceptor

result_dict = ingestion_interceptor(
    drone_json,
    device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
    require_signature=False,
)
```

---

## Running the test suite

113 tests across 4 test files, all stdlib `unittest`. Run from the
project root.

### Just this package's tests

```bash
python -m unittest discover -s ingestion_interceptor/tests -v
```

Expected output ends with:

```
Ran 75 tests in ~5s
OK
```

### A specific test file

```bash
python -m unittest ingestion_interceptor.tests.test_interceptor -v
python -m unittest ingestion_interceptor.tests.test_packet_codec -v
python -m unittest ingestion_interceptor.tests.test_submission_codec -v
python -m unittest ingestion_interceptor.tests.test_packet_receiver -v
```

### A specific test case

```bash
python -m unittest \
    ingestion_interceptor.tests.test_packet_receiver.TestPacketReceiverEndToEnd.test_in_order_reassembly -v
```

### With pytest (if installed)

```bash
pytest ingestion_interceptor/tests/ -v
```

### Drone simulator's tests too

```bash
python -m unittest discover -s drone/tests -v
```

---

## End-to-end smoke check

To prove the wire-mode pipeline is wired up correctly without running
the full demo:

```bash
python -c "
import time
from drone import Drone, DroneConfig
from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

ic = IngestionInterceptor(
    device_registry={'DRN-001': {'trusted': True, 'reputation': 0.9}},
    key_store={'DRN-001': 'k1'},
)
ic.start_packet_listener(host='127.0.0.1', port=0)
host, port = ic.packet_receiver.bound_address

drone = Drone(DroneConfig(
    drone_id='DRN-001', transport_mode='packet',
    signing_enabled=True, signing_key='k1',
    interceptor_host=host, interceptor_port=port,
))
drone.quick_capture('mixed')
drone.transmit_all()

time.sleep(0.5)
print('pipeline:', ic.stats)
print('packets :', ic.packet_stats.to_dict())
ic.stop_packet_listener()
"
```

Expected: `total_processed: 1`, `sessions_completed: 1`, `0` dropped.

---

## Simulating wire-mode end-to-end

You **do not need two computers**. The receiver and the drone use a real
UDP socket and the OS UDP stack — even when both run on the same host —
so the protocol, HMAC, fragmentation, and reassembly are exercised
genuinely. Three levels of realism, pick whichever you need.

### Option 1 — Single process (fastest)

```bash
python -m drone.run_demo
```

Runs the side-by-side in-process + wire-mode demo. The `PacketReceiver`
runs on a daemon thread inside the same Python process; drones send to
`127.0.0.1` on an ephemeral port. Best for quick smoke testing and
regression checks.

### Option 2 — Two processes on the same machine ★ recommended

The cleanest way to demonstrate that the protocol is the only contract
between drone and interceptor — nothing leaks via shared memory.

**Terminal A — interceptor (listens on UDP 5005, prints stats every 2 s):**

```bash
python -c "
import time
from ingestion_interceptor import IngestionInterceptor, InterceptorConfig

ic = IngestionInterceptor(
    config=InterceptorConfig(packet_listener_port=5005),
    device_registry={
        'DRN-001': {'trusted': True, 'reputation': 0.9},
        'DRN-002': {'trusted': False, 'reputation': 0.4},
        'DRN-003': {'trusted': True, 'reputation': 0.95},
    },
    zone_risk_lookup={'zone-alpha': 0.2, 'zone-bravo': 0.1, 'zone-charlie': 0.8},
    key_store={
        'DRN-001': 'shared_secret_001',
        'DRN-002': 'shared_secret_002',
        'DRN-003': 'shared_secret_003',
    },
)
ic.start_packet_listener(host='0.0.0.0', port=5005)
print('Interceptor listening on 0.0.0.0:5005 — Ctrl+C to stop')
try:
    while True:
        time.sleep(2)
        print('pipeline:', ic.stats)
        print('packets :', ic.packet_stats.to_dict())
        print()
except KeyboardInterrupt:
    ic.stop_packet_listener()
"
```

**Terminal B — drone fleet (sends real UDP packets to terminal A):**

```bash
python -c "
import time
from drone import DroneConfig, DroneFleet, FlightPlan, Waypoint

key_store = {
    'DRN-001': 'shared_secret_001',
    'DRN-002': 'shared_secret_002',
    'DRN-003': 'shared_secret_003',
}

fleet = DroneFleet()
for did in ('DRN-001', 'DRN-002', 'DRN-003'):
    fleet.add_drone(DroneConfig(
        drone_id=did,
        transport_mode='packet',
        signing_enabled=True,
        signing_key=key_store[did],
        interceptor_host='127.0.0.1',
        interceptor_port=5005,
    ))

plan = FlightPlan(mission_zone='zone-alpha', waypoints=[
    Waypoint(12.975, 77.590, 100, action='capture_image'),
    Waypoint(12.978, 77.593, 120, action='record_video', loiter_time_sec=3),
    Waypoint(12.973, 77.596, 80, action='capture_image'),
])
for did in fleet.drone_ids:
    fleet.assign_mission(did, plan)
fleet.execute_all()
fleet.transmit_all()
time.sleep(1)
print('done — check terminal A for receiver stats')
"
```

Watch terminal A's counters rise: `packets_received`, `sessions_completed`,
`total_processed`. Re-run terminal B as many times as you like — each
mission opens a fresh session.

**Bonus — capture the actual wire packets with tcpdump.** Open a third
terminal while both processes are running:

```bash
sudo tcpdump -i lo -X 'udp port 5005'
```

You'll see the 32-byte `RPAD` header + binary TLV payload + 32-byte HMAC
tag for each packet. Useful evidence for a project report — proves the
bytes are real and binary, not JSON.

### Option 3 — Two machines (or two VMs)

Only worth it if you want to demonstrate **real network conditions**
(latency, MTU, real packet loss). Setup:

| Step | What to do |
|---|---|
| 1 | Both machines on the same LAN / WiFi / VPN, or two VMs / containers on one host |
| 2 | On the **interceptor** machine: run the same Terminal A command from Option 2. The default `host='0.0.0.0'` already accepts external traffic. |
| 3 | Find the interceptor machine's LAN IP: `ip addr show` (Linux) or `ipconfig` (Windows) — e.g. `192.168.1.10` |
| 4 | On the **drone** machine: change `interceptor_host='127.0.0.1'` to `interceptor_host='192.168.1.10'` |
| 5 | Open UDP/5005 in the interceptor machine's firewall: `sudo ufw allow 5005/udp` (Ubuntu) |
| 6 | Make sure the same `key_store` secrets are present on both machines (HMAC must match) |
| 7 | Run terminal A on machine 1, terminal B on machine 2 |

Same protocol, same code path — only the destination IP changes.

### Which one should I use?

| Use case | Option |
|---|---|
| Smoke test the pipeline / CI / regression | Option 1 |
| BTP demo, instructor review, project report | **Option 2** + tcpdump capture |
| Demonstrate real network conditions to a sponsor | Option 3 |

---

## Module layout

```
ingestion_interceptor/
├── __init__.py              public API surface (re-exports)
├── config.py                InterceptorConfig dataclass
├── models.py                6 typed dataclasses for the data flow
├── validator.py             Stage 1 — structure & constraint validation
├── authenticator.py         Stage 2 — device registry + HMAC signature verify
├── metadata_extractor.py    Stage 3 — mission, geo, telemetry extraction
├── payload_analyzer.py      Stage 4 — 9-point security heuristic
├── checksum_verifier.py     Stage 5 — SHA-256 file integrity
├── artifact_manager.py      Stage 6 — artifact ID + storage pointer
├── interceptor.py           Stage 7 — orchestrator (process, batch, listener)
├── packet_receiver.py       Stage 0 — UDP listener + reassembly buffer
├── protocol/                Wire protocol subpackage
│   ├── packet.py              32-byte fixed binary header
│   ├── codec.py               encode/decode/HMAC verify
│   ├── submission_codec.py    binary TLV marshaller
│   └── errors.py              codec exception hierarchy
├── uplink.py                Control center uplink command handling
├── run_demo.py              Standalone in-process demo
└── tests/                   75 unit tests
```

---

## Key configuration knobs

`InterceptorConfig` defaults are field-deployment safe. Override anything
via constructor. The full table is in §11 of the design doc.

| Knob                              | Default       | What it does                                              |
|-----------------------------------|---------------|-----------------------------------------------------------|
| `require_signature`               | `False`       | Force every submission to carry an HMAC signature         |
| `max_payload_size_bytes`          | `500_000_000` | Hard cap per individual file (500 MB)                     |
| `max_payloads_per_submission`     | `50`          | Reject submissions with more than this many files         |
| `unknown_device_policy`           | `"flag"`      | `flag` / `reject` / `allow` for unregistered drones       |
| `verify_checksums`                | `True`        | Compute SHA-256 of files referenced by `uri` (if local)   |
| `packet_listener_port`            | `5005`        | UDP port for the wire-mode listener                       |
| `packet_max_session_chunks`       | `256`         | Memory cap on a single fragmented submission              |
| `packet_max_concurrent_sessions`  | `100`         | Per-drone concurrent session cap (DoS bound)              |
| `packet_session_timeout_seconds`  | `30.0`        | Drop half-open sessions after this many seconds           |
| `packet_hmac_required`            | `True`        | Reject packets without a valid HMAC tag                   |

---

## Operational stats

Live counters once the interceptor is running:

```python
interceptor.stats
# {'total_processed': N, 'total_rejected': N, 'total_flagged': N}

interceptor.packet_stats.to_dict()
# {'packets_received': N,
#  'packets_dropped_malformed': N,        # bad magic/version/length → attack indicator
#  'packets_dropped_hmac': N,             # HMAC verify failed → tampering
#  'packets_dropped_unknown_drone': N,    # no key configured → unauthorised device
#  'packets_dropped_replay': N,           # duplicate seq within session → replay attack
#  'packets_dropped_orphaned': N,         # CHUNK without SESSION_START → benign loss
#  'packets_dropped_session_overflow': N, # too many sessions per drone → DoS
#  'sessions_started': N,
#  'sessions_completed': N,
#  'sessions_expired': N,                 # GC drained
#  'sessions_truncated': N,               # SESSION_END with missing chunks
#  'submissions_decoded': N,
#  'submissions_decode_failed': N}
```

Recommended production wiring: scrape these via Prometheus / StatsD,
alert on `total_rejected`, `packets_dropped_hmac`, and `sessions_truncated`
spikes — they are the highest-signal attack indicators.

---

## Troubleshooting

| Symptom                                          | Likely cause / fix                                                                 |
|--------------------------------------------------|------------------------------------------------------------------------------------|
| `packets_dropped_unknown_drone` keeps climbing   | No HMAC key configured for the drone — add it to `key_store` at construction time |
| `packets_dropped_hmac` keeps climbing            | Drone and interceptor have different keys — verify both ends use the same secret  |
| `packets_dropped_orphaned` > 0 in a clean network| SESSION_START packet was lost → bump retry on the sender, or check MTU             |
| `sessions_truncated` > 0                         | CHUNKs missing at SESSION_END time → packet loss or truncation attack — investigate |
| Listener thread doesn't start                    | Port already in use — pass `port=0` to bind to an ephemeral port                   |
| Tests fail with `Address already in use`         | Stale process holding port 5005 — tests use ephemeral ports, but a previous demo  may not have called `stop_packet_listener()`. Restart the shell.                  |
| `auth_result == "untrusted"` after wire transit  | The drone is in `transport_mode="packet"` but `signing_enabled=True` — that's fine, packet HMAC is the wire authentication; the application-level signature is intentionally skipped in packet mode |

---

## See also

- `docs/design_ingestion_interceptor.md` — full architecture, sequence
  diagrams, security defenses, requirements traceability, risk register
- `drone/README.md` — drone simulator usage, anomaly injection, fleet
  operations
- `drone/run_demo.py` — side-by-side in_process vs wire transport demo
