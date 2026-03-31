# full_run_all_samples.py
import math
from typing import List, Dict, Any

# ------------------ CONFIG (tuneable) ------------------
alpha = 0.5
beta = 0.3
gamma = 0.2
delta = 0.0
eps = 1e-3

kappa = 0.8
lambda_blend = 0.9
th_low = 0.4
th_high = 0.7

DSR_base = {'signature': 0.70, 'ml': 0.85, 'sandbox': 0.95}
C_d = {'signature': 1.0, 'ml': 3.0, 'sandbox': 6.0}
C_a = {'inject': 2.0, 'no_inject': 0.0}

defender_strats = ['signature', 'ml', 'sandbox']
attacker_actions = ['inject', 'no_inject']

type_risk_map = {'telemetry': 0.1, 'text': 0.2, 'image': 0.5, 'video': 0.9, 'archive': 0.8}

# ------------------ UTILITIES ------------------
def clamp(x: float, a: float = 1e-3, b: float = 1.0 - 1e-3) -> float:
    return max(a, min(b, x))

def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

# ------------------ IMPACT / DSR ------------------
def compute_I_base(artifact_records: List[Dict[str, Any]], ingest_metadata: Dict[str, Any]) -> float:
    sizes = [a.get('size_bytes', 0) for a in artifact_records]
    avg_size_mb = (sum(sizes) / len(sizes)) / 1e6 if sizes else 0.0
    type_risks = [type_risk_map.get(a.get('type', 'other'), 0.4) for a in artifact_records]
    type_risk = max(type_risks) if type_risks else 0.2

    mission_sens = 0.0
    ms = (
        ingest_metadata.get('additional_metadata', {}) .get('mission_sensitivity')
        or ingest_metadata.get('notes')
        or ingest_metadata.get('additional_metadata', {}).get('mission_sensitivity_level')
    )
    if ms:
        ms_s = str(ms).lower()
        if ms_s.startswith('crit'):
            mission_sens = 2.0
        elif ms_s.startswith('high'):
            mission_sens = 1.5
        elif ms_s.startswith('med'):
            mission_sens = 1.0

    I_base = 3.0 + (avg_size_mb * 3.0) + (type_risk * 3.0) + mission_sens
    return round(max(0.0, min(10.0, I_base)), 6)

def compute_I_prime(I_base: float, R: float, Z: float) -> float:
    return I_base * (1 + alpha * (1 - R)) * (1 + beta * Z)

def compute_DSR_primes(DSR_base_local: Dict[str, float], H: float, TI: float) -> Dict[str, float]:
    DSR_prime: Dict[str, float] = {}
    for s, base in DSR_base_local.items():
        val = base * (1 - gamma * H) * (1 + delta * TI)
        DSR_prime[s] = clamp(val, eps, 1.0 - eps)
    return DSR_prime

# ------------------ PAYOFF MATRICES (conservative) ------------------
def build_payoff_matrices(I_prime: float, DSR_prime: Dict[str, float]) -> (List[List[float]], List[List[float]]):
    U_a: List[List[float]] = []
    U_d: List[List[float]] = []
    for s in defender_strats:
        dsr = DSR_prime[s]
        asp = 1.0 - dsr
        row_a: List[float] = []
        row_d: List[float] = []
        for a in attacker_actions:
            # Attacker payoff: conservative -> no_inject payoff = 0
            if a == 'no_inject':
                ua = 0.0
            else:
                ua = asp * I_prime - C_a.get(a, 0.0)
            # Defender payoff: conservative -> no_inject = -C_d[s]
            if a == 'no_inject':
                ud = - C_d[s]
            else:
                ud = dsr * I_prime - C_d[s]
            row_a.append(round(ua, 6))
            row_d.append(round(ud, 6))
        U_a.append(row_a)
        U_d.append(row_d)
    return U_a, U_d

# ------------------ STACKELBERG SOLVER (pure strategies) ------------------
def solve_stackelberg_pure(U_a: List[List[float]], U_d: List[List[float]]) -> Dict[str, Any]:
    best_def = None
    for i, row in enumerate(U_a):
        # Attacker best response(s)
        max_ua = max(row)
        candidates = [j for j, v in enumerate(row) if abs(v - max_ua) < 1e-12]
        if len(candidates) == 1:
            j_best = candidates[0]
        else:
            # attacker tie-breaker: pick action that minimizes U_d (hurts defender)
            j_best = min(candidates, key=lambda j: U_d[i][j])
        ua = row[j_best]
        ud = U_d[i][j_best]
        if best_def is None or ud > best_def['ud']:
            best_def = {'di': i, 'aj': j_best, 'ud': ud, 'ua': ua}
        elif abs(ud - best_def['ud']) < 1e-12:
            # defender tie-breaker: prefer lower-cost strategy (choose one with smaller C_d)
            current_cost = C_d[defender_strats[i]]
            best_cost = C_d[defender_strats[best_def['di']]]
            if current_cost < best_cost:
                best_def = {'di': i, 'aj': j_best, 'ud': ud, 'ua': ua}
    if best_def is None:
        raise ValueError("Empty payoff matrices")
    return {
        'defender_index': best_def['di'],
        'attacker_index': best_def['aj'],
        'defender_strategy': defender_strats[best_def['di']],
        'attacker_action': attacker_actions[best_def['aj']],
        'U_d_eq': round(best_def['ud'], 6),
        'U_a_eq': round(best_def['ua'], 6)
    }

# ------------------ THREAT SCORE MAPPING ------------------
def compute_threat_score(U_a_eq: float, U_d_eq: float, R: float) -> Dict[str, Any]:
    raw = U_a_eq - U_d_eq
    T_raw = sigmoid(kappa * raw)
    T_S = lambda_blend * T_raw + (1.0 - lambda_blend) * (1.0 - R)
    T_S = max(0.0, min(1.0, T_S))
    if T_S < th_low:
        level = "Low"
    elif T_S < th_high:
        level = "Medium"
    else:
        level = "High"
    return {"raw": round(raw, 6), "T_raw": round(T_raw, 6), "T_S": round(T_S, 6), "inspection_level": level}

# ------------------ SAMPLES (exact from your code) ------------------
sampleA = {
  "ingest_metadata": {
    "ingest_id": "ingest_9f1a2b3c4d",
    "drone_id": "DRN-001",
    "timestamp": "2025-10-13T03:00:12Z",
    "mission_id": "MSN-142",
    "mission_zone": "zone-a",
    "geo": { "lat": 12.971598, "lon": 77.594566, "alt": 120 },
    "operator_id": "OP-12",
    "firmware_version": "v1.2.0",
    "num_files": 2,
    "insecure_flags": [],
    "auth_result": "ok",
    "notes": "normal video+image feed"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://a3f8e9b2c1d4",
      "filename": "drn001_fpv_001.mp4",
      "type": "video",
      "mime": "video/mp4",
      "size_bytes": 4500000,
      "encryption": False,
      "container": False,
      "thumbnail": "thumb://6d7a8b9c0d",
      "pointer_storage": "s3://forensics/artifacts/a3f8e9b2c1d4"
    },
    {
      "artifact_id": "artifact://b4c5d6e7f8a9",
      "filename": "drn001_cam_001.jpg",
      "type": "image",
      "mime": "image/jpeg",
      "size_bytes": 320000,
      "encryption": False,
      "container": False,
      "thumbnail": "thumb://1a2b3c4d5e",
      "pointer_storage": "s3://forensics/artifacts/b4c5d6e7f8a9"
    }
  ]
}

sampleB = {
  "ingest_metadata": {
    "ingest_id": "ingest_c7d6e5f4a3",
    "drone_id": "DRN-002",
    "timestamp": "2025-10-13T03:05:45Z",
    "mission_id": "MSN-143",
    "mission_zone": "zone-c",
    "geo": { "lat": 13.035542, "lon": 77.597100, "alt": 85 },
    "operator_id": "OP-23",
    "firmware_version": "v1.1.9",
    "num_files": 2,
    "insecure_flags": ["encrypted_payload", "nested_archive"],
    "auth_result": "unknown",
    "notes": "encrypted ZIP with nested contents — flag for deferred analysis"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://c1d2e3f4a5b6",
      "filename": "payload_bundle.zip",
      "type": "archive",
      "mime": "application/zip",
      "size_bytes": 4200000,
      "encryption": True,
      "container": True,
      "thumbnail": None,
      "pointer_storage": "s3://forensics/artifacts/c1d2e3f4a5b6"
    },
    {
      "artifact_id": "artifact://d7e8f9a0b1c2",
      "filename": "notes.txt",
      "type": "text",
      "mime": "text/plain",
      "size_bytes": 2048,
      "encryption": False,
      "container": False,
      "thumbnail": None,
      "pointer_storage": "s3://forensics/artifacts/d7e8f9a0b1c2"
    }
  ]
}

sampleC = {
  "ingest_metadata": {
    "ingest_id": "ingest_e8f7g6h5i4",
    "drone_id": "DRN-003",
    "timestamp": "2025-10-13T03:10:03Z",
    "mission_id": "MSN-144",
    "mission_zone": "zone-b",
    "geo": { "lat": 12.967800, "lon": 77.601200, "alt": 35 },
    "operator_id": "OP-33",
    "firmware_version": "v1.2.3",
    "num_files": 1,
    "insecure_flags": [],
    "auth_result": "ok",
    "notes": "telemetry-only — low risk"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://e9f0g1h2i3j4",
      "filename": "telemetry_snapshot.json",
      "type": "telemetry",
      "mime": "application/json",
      "size_bytes": 1500,
      "encryption": False,
      "container": False,
      "thumbnail": None,
      "pointer_storage": "s3://forensics/artifacts/e9f0g1h2i3j4"
    }
  ]
}

sampleD = {
  "ingest_metadata": {
    "ingest_id": "ingest_f1e2d3c4b5",  # kept original value
    "drone_id": "DRN-004",
    "timestamp": "2025-10-13T03:15:22Z",
    "mission_id": "MSN-145",
    "mission_zone": "zone-a",
    "geo": { "lat": 12.975000, "lon": 77.590000, "alt": 200 },
    "operator_id": "OP-05",
    "firmware_version": "v2.0.0",
    "num_files": 2,
    "insecure_flags": [],
    "auth_result": "ok",
    "notes": "large survey video — mission sensitivity: critical"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://f2e3d4c5b6a7",
      "filename": "survey_coverage_long.mp4",
      "type": "video",
      "mime": "video/mp4",
      "size_bytes": 12500000,
      "encryption": False,
      "container": False,
      "thumbnail": "thumb://abc123def456",
      "pointer_storage": "s3://forensics/artifacts/f2e3d4c5b6a7"
    },
    {
      "artifact_id": "artifact://g3h4i5j6k7l8",
      "filename": "survey_frame_2345.jpg",
      "type": "image",
      "mime": "image/jpeg",
      "size_bytes": 550000,
      "encryption": False,
      "container": False,
      "thumbnail": "thumb://789xyz456",
      "pointer_storage": "s3://forensics/artifacts/g3h4i5j6k7l8"
    }
  ]
}

# Fix the small duplicate-assignment you had for sampleHighRisk:
sampleHighRisk = {
  "ingest_metadata": {
    "ingest_id": "ingest_high_999",
    "drone_id": "DRN-999",
    "timestamp": "2025-10-14T04:45:00Z",
    "mission_id": "MSN-999",
    "mission_zone": "zone-x",
    "geo": { "lat": 27.175, "lon": 78.042, "alt": 250 },
    "operator_id": "OP-99",
    "firmware_version": "v0.9.1",
    "num_files": 3,
    "insecure_flags": ["encrypted_payload", "nested_archive"],
    "auth_result": "fail",
    "notes": "critical mission, unverified source, encrypted nested archive payload"
  },
  "artifact_records": [
    {
      "artifact_id": "artifact://risk001",
      "filename": "payload_secure_bundle.zip",
      "type": "archive",
      "mime": "application/zip",
      "size_bytes": 18000000,   # 18 MB
      "encryption": True,
      "container": True,
      "thumbnail": None,
      "pointer_storage": "s3://forensics/highrisk/payload_secure_bundle.zip"
    },
    {
      "artifact_id": "artifact://risk002",
      "filename": "readme.txt",
      "type": "text",
      "mime": "text/plain",
      "size_bytes": 4000,
      "encryption": False,
      "container": False,
      "thumbnail": None,
      "pointer_storage": "s3://forensics/highrisk/readme.txt"
    }
  ]
}

# ------------------ RUNNER / PRINTER ------------------
def print_line():
    print("=" * 100)

def print_kv(k, v):
    print(f"{k:<35}: {v}")

def compute_I_base_details(artifact_records: List[Dict[str, Any]], ingest_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Compute I_base and return intermediate values for printing."""
    sizes = [a.get('size_bytes', 0) for a in artifact_records]
    total_size = sum(sizes)
    count = len(sizes)
    avg_size_mb = (total_size / count) / 1e6 if count else 0.0
    type_risks = [type_risk_map.get(a.get('type', 'other'), 0.4) for a in artifact_records]
    type_risk = max(type_risks) if type_risks else 0.2

    mission_sens = 0.0
    ms = (
        ingest_metadata.get('additional_metadata', {}) .get('mission_sensitivity')
        or ingest_metadata.get('notes')
        or ingest_metadata.get('additional_metadata', {}).get('mission_sensitivity_level')
    )
    ms_text = None
    if ms:
        ms_text = str(ms).lower()
        if ms_text.startswith('crit'):
            mission_sens = 2.0
        elif ms_text.startswith('high'):
            mission_sens = 1.5
        elif ms_text.startswith('med'):
            mission_sens = 1.0

    I_base = 3.0 + (avg_size_mb * 3.0) + (type_risk * 3.0) + mission_sens
    I_base = round(max(0.0, min(10.0, I_base)), 6)
    return {
        "total_size_bytes": total_size,
        "count": count,
        "avg_size_mb": round(avg_size_mb, 6),
        "type_risks": type_risks,
        "type_risk": type_risk,
        "mission_sensitivity_text": ms_text,
        "mission_sensitivity_score": mission_sens,
        "I_base": I_base
    }

def print_matrix(name: str, M: List[List[float]]):
    print(f"\n{name}")
    print("Rows = [signature, ml, sandbox]")
    print("Cols = [inject, no_inject]")
    for s, row in zip(defender_strats, M):
        print(f"{s:<10} -> {row}")

def attacker_best_response_row(row: List[float], ud_row: List[float]) -> Dict[str, Any]:
    """Return best attacker action index(es) and chosen by tie-break rule (min defender payoff)."""
    max_ua = max(row)
    candidates = [j for j, v in enumerate(row) if abs(v - max_ua) < 1e-12]
    if len(candidates) == 1:
        chosen = candidates[0]
    else:
        # choose the candidate that minimizes defender payoff
        chosen = min(candidates, key=lambda j: ud_row[j])
    return {"candidates": candidates, "chosen": chosen, "value": row[chosen]}

def run_on_sample(name: str, sample: Dict[str, Any], R: float, Z: float, H: float, TI: float):
    print_line()
    print(f"RUNNING SAMPLE: {name}")
    print_line()

    # print ingest metadata & artifacts
    print("\n-- INGEST METADATA --")
    for k, v in sample['ingest_metadata'].items():
        print_kv(k, v)

    print("\n-- ARTIFACT RECORDS --")
    for i, a in enumerate(sample['artifact_records'], 1):
        print(f"\nArtifact #{i}")
        for k, v in a.items():
            print_kv(k, v)

    # compute I_base with details
    details = compute_I_base_details(sample['artifact_records'], sample['ingest_metadata'])
    print("\n-- I_base DETAILS --")
    for k, v in details.items():
        print_kv(k, v)

    I_base = details['I_base']
    I_prime = compute_I_prime(I_base, R, Z)
    DSR_prime = compute_DSR_primes(DSR_base, H, TI)
    print("\n-- MODEL INPUTS --")
    print_kv("R (reputation)", R)
    print_kv("Z (zone risk)", Z)
    print_kv("H (history)", H)
    print_kv("TI (threat intel)", TI)
    print_kv("I_base", I_base)
    print_kv("I_prime (computed)", round(I_prime, 6))
    print("\n-- DSR_prime --")
    for k, v in DSR_prime.items():
        print_kv(k, round(v, 6))

    # build matrices
    U_a, U_d = build_payoff_matrices(I_prime, DSR_prime)
    print_matrix("U_a (attacker payoff)", U_a)
    print_matrix("U_d (defender payoff)", U_d)

    # attacker best responses per defender strategy
    print("\n-- ATTACKER BEST RESPONSES (per defender row) --")
    for i, (row_a, row_d) in enumerate(zip(U_a, U_d)):
        resp = attacker_best_response_row(row_a, row_d)
        print_kv(f"defender_row_index ({i}) strategy", defender_strats[i])
        print_kv("  attacker_candidates_indices", resp['candidates'])
        print_kv("  attacker_chosen_index", resp['chosen'])
        print_kv("  attacker_chosen_action", attacker_actions[resp['chosen']])
        print_kv("  attacker_payoff_at_chosen", resp['value'])

    # solve Stackelberg
    eq = solve_stackelberg_pure(U_a, U_d)
    print("\n-- STACKELBERG EQUILIBRIUM --")
    for k, v in eq.items():
        print_kv(k, v)

    # threat score
    threat = compute_threat_score(eq['U_a_eq'], eq['U_d_eq'], R)
    print("\n-- THREAT SCORE --")
    for k, v in threat.items():
        print_kv(k, v)

    print("\nFINAL INSPECTION LEVEL:", threat['inspection_level'])
    print_line()
    print("\n\n")

# ------------------ RUN ALL SAMPLES ------------------
if __name__ == "__main__":
    # Print global configuration (all parameters)
    print_line()
    print("GLOBAL CONFIGURATION")
    print_line()
    print_kv("alpha", alpha)
    print_kv("beta", beta)
    print_kv("gamma", gamma)
    print_kv("delta", delta)
    print_kv("eps", eps)
    print_kv("kappa", kappa)
    print_kv("lambda_blend", lambda_blend)
    print_kv("th_low", th_low)
    print_kv("th_high", th_high)
    print_kv("DSR_base", DSR_base)
    print_kv("C_d", C_d)
    print_kv("C_a", C_a)
    print_kv("defender_strats", defender_strats)
    print_kv("attacker_actions", attacker_actions)
    print_kv("type_risk_map", type_risk_map)
    print_line()
    print("\n")

    # runtime variables (you can change these per-sample or pass from external)
    R_default = 0.8
    Z_default = 0.5
    H_default = 0.0
    TI_default = 0.0

    samples = [
        ("Sample A - Video + Image", sampleA),
        ("Sample B - Encrypted Archive", sampleB),
        ("Sample C - Telemetry Only", sampleC),
        ("Sample D - Mission Critical", sampleD),
        ("Sample HIGH RISK", sampleHighRisk),
    ]

    for name, samp in samples:
        run_on_sample(name, samp, R_default, Z_default, H_default, TI_default)

