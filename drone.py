#!/usr/bin/env python3
import os
import sys
import json
import uuid
import time
import shutil
import random
import hashlib
import argparse
import pathlib
from datetime import datetime, timezone

# -------------------------
# Config
# -------------------------
ROOT = pathlib.Path.cwd()

IMAGES_DIR = ROOT / "images"
VIDEOS_DIR = ROOT / "videos"

REMOTE_STORAGE = ROOT / "drone_remote_store"
LOCAL_JSON = ROOT / "drone_local_storage"

IMAGES_DIR.mkdir(exist_ok=True)
VIDEOS_DIR.mkdir(exist_ok=True)
REMOTE_STORAGE.mkdir(exist_ok=True)
LOCAL_JSON.mkdir(exist_ok=True)

# -------------------------
# Utils
# -------------------------
def now_iso_z():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def rand_mission_id():
    return f"MSN-{random.randint(100,999)}"

def rand_operator():
    return f"OP-{random.randint(1,99):02d}"

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def random_geo(center=(12.971598, 77.594566), max_offset_km=5):
    lat0, lon0 = center
    delta = max_offset_km / 111.0
    return {
        "lat": round(lat0 + random.uniform(-delta, delta), 6),
        "lon": round(lon0 + random.uniform(-delta, delta), 6),
        "alt": round(random.uniform(10,300),1)
    }

def random_telemetry():
    return {
        "speed": round(random.uniform(0,20),2),
        "heading": round(random.uniform(0,360),1),
        "battery": round(random.uniform(10,100),1),
        "signal_strength": round(random.uniform(30,100),1)
    }

def ensure_dir(p):
    p.mkdir(parents=True, exist_ok=True)
    return p

# -------------------------
# Drone
# -------------------------
class Drone:
    def __init__(self, drone_id="DRN-001", storage_prefix="file://"):
        self.drone_id = drone_id
        self.storage_prefix = storage_prefix.rstrip("/") + "/"
        self.remote_dir = ensure_dir(REMOTE_STORAGE / drone_id)
        self.json_dir = ensure_dir(LOCAL_JSON / drone_id)

    def capture_image(self):
        images = list(IMAGES_DIR.glob("*"))
        if not images:
            raise RuntimeError("No images found in /images")

        chosen = random.choice(images)
        filename = f"{self.drone_id}_img_{int(time.time())}_{uuid.uuid4().hex[:6]}{chosen.suffix}"
        dest = self.remote_dir / filename
        shutil.copy2(chosen, dest)

        return {
            "filename": filename,
            "mime": "image/jpeg",
            "size_bytes": dest.stat().st_size,
            "checksum": sha256_of_file(dest),
            "uri": self.storage_prefix + str(dest.resolve())
        }

    def capture_video(self):
        videos = list(VIDEOS_DIR.glob("*.mp4"))
        if not videos:
            raise RuntimeError("No videos found in /videos")

        chosen = random.choice(videos)
        filename = f"{self.drone_id}_vid_{int(time.time())}_{uuid.uuid4().hex[:6]}.mp4"
        dest = self.remote_dir / filename
        shutil.copy2(chosen, dest)

        return {
            "filename": filename,
            "mime": "video/mp4",
            "size_bytes": dest.stat().st_size,
            "checksum": sha256_of_file(dest),
            "uri": self.storage_prefix + str(dest.resolve())
        }

    def _choose_payloads(self):
        x = random.randint(1,1000)
        payloads = []

        if x % 2 == 0:
            img = self.capture_image()
            payloads.append({**img,"type":"image","encryption":False,"container":False})

        if x % 3 == 0:
            vid = self.capture_video()
            payloads.append({**vid,"type":"video","encryption":False,"container":False})

        if not payloads:
            payloads.append({
                "type":"telemetry",
                "filename":"tele.json",
                "mime":"application/json",
                "size_bytes":512,
                "encryption":False,
                "container":False,
                "checksum": hashlib.sha256(os.urandom(20)).hexdigest()
            })

        return payloads

    def run(self):
        obj = {
            "drone_id": self.drone_id,
            "timestamp": now_iso_z(),
            "mission_id": rand_mission_id(),
            "mission_zone": random.choice(["zone-a","zone-b","zone-c"]),
            "geo": random_geo(),
            "payloads": self._choose_payloads(),
            "telemetry": random_telemetry(),
            "signature": None,
            "firmware_version": f"v{random.randint(1,3)}.{random.randint(0,9)}",
            "operator_id": rand_operator()
        }

        json_name = f"{self.drone_id}_{int(time.time())}_{uuid.uuid4().hex[:6]}.json"
        with open(self.json_dir / json_name,"w") as f:
            json.dump(obj,f,indent=2)

        return obj

# -------------------------
# CLI
# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--drone-id", default="DRN-001")
    args = ap.parse_args()

    d = Drone(drone_id=args.drone_id)

    for _ in range(args.count):
        print(json.dumps(d.run(),indent=2))
        print("----")

if __name__ == "__main__":
    main()
