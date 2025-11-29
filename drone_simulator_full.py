#!/usr/bin/env python3
"""
drone_simulator_full.py

Provides a Drone class that can capture images/videos/files, "upload" them,
and emit JSON payloads similar to the samples you provided.

Usage:
    pip install requests opencv-python numpy
    python drone_simulator_full.py --count 3

Outputs printed JSON objects (one per run).
"""

import os
import io
import sys
import json
import uuid
import time
import shutil
import random
import string
import hashlib
import argparse
import pathlib
import requests
from datetime import datetime, timezone

# Optional: video generation
try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except Exception:
    HAS_OPENCV = False

# -------------------------
# Config
# -------------------------
ROOT = pathlib.Path.cwd()
LOCAL_MEDIA = ROOT / "drone_local_storage"    # where raw captures are saved
REMOTE_STORAGE = ROOT / "drone_remote_store"  # simulated upload store (files copied here)
LOCAL_MEDIA.mkdir(parents=True, exist_ok=True)
REMOTE_STORAGE.mkdir(parents=True, exist_ok=True)

PICSUM_URL = "https://picsum.photos/200"  # random image generator

# -------------------------
# Utils
# -------------------------
def now_iso_z():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def rand_mission_id():
    return f"MSN-{random.randint(100,999)}"

def rand_operator():
    return f"OP-{random.randint(1,99):02d}"

def sha256_of_file(path: pathlib.Path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def random_geo(center=(12.971598, 77.594566), max_offset_km=5.0):
    # crude random lat/lon within ~max_offset_km
    lat0, lon0 = center
    # approx degrees for given km: 1 deg lat ~111 km
    delta_deg = max_offset_km / 111.0
    lat = lat0 + random.uniform(-delta_deg, delta_deg)
    lon = lon0 + random.uniform(-delta_deg, delta_deg)
    alt = random.uniform(10, 300)
    return {"lat": round(lat, 6), "lon": round(lon, 6), "alt": round(alt, 1)}

def random_telemetry():
    return {
        "speed": round(random.uniform(0, 20), 2),
        "heading": round(random.uniform(0, 359.9), 1),
        "battery": round(random.uniform(10, 100), 1),
        "signal_strength": round(random.uniform(30, 100), 1),
    }

def ensure_dir(p: pathlib.Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

# -------------------------
# Drone class
# -------------------------
class Drone:
    def __init__(self, drone_id: str = "DRN-001", storage_prefix: str = "file://"):
        self.drone_id = drone_id
        self.storage_prefix = storage_prefix.rstrip("/") + "/"
        self.local_dir = ensure_dir(LOCAL_MEDIA / drone_id)
        self.remote_dir = ensure_dir(REMOTE_STORAGE / drone_id)

    # -------- capture functions --------
    def capture_image(self) -> dict:
        """
        Fetch a fresh random image from picsum, save locally, return metadata.
        """
        filename = f"{self.drone_id}_img_{int(time.time())}_{uuid.uuid4().hex[:6]}.jpg"
        local_path = self.local_dir / filename

        # fetch
        resp = requests.get(PICSUM_URL, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch image: {resp.status_code}")
        with open(local_path, "wb") as f:
            f.write(resp.content)

        meta = {
            "path": str(local_path.resolve()),
            "filename": filename,
            "mime": "image/jpeg",
            "size_bytes": local_path.stat().st_size,
            "checksum": sha256_of_file(local_path),
        }
        return meta

    def capture_video(self, seconds: int = 3) -> dict:
        """
        Create a short synthetic mp4 file (requires opencv). If opencv is not available,
        create a small placeholder binary file.
        """
        filename = f"{self.drone_id}_vid_{int(time.time())}_{uuid.uuid4().hex[:6]}.mp4"
        local_path = self.local_dir / filename

        if HAS_OPENCV:
            # create a short synthetic video with moving shapes
            fps = 15
            w, h = 320, 180
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            out = cv2.VideoWriter(str(local_path), fourcc, fps, (w, h))
            frames = max(1, fps * seconds)
            x, y = random.randint(20, w-20), random.randint(20, h-20)
            vx, vy = random.choice([-3, -2, -1, 1, 2, 3]), random.choice([-2, -1, 1, 2])
            for i in range(frames):
                frame = (np.random.rand(h, w, 3) * 255).astype("uint8")
                cv2.circle(frame, (abs(x)%w, abs(y)%h), 20, (int(255*random.random()), int(255*random.random()), int(255*random.random())), -1)
                x += vx; y += vy
                if x < 0 or x > w: vx *= -1
                if y < 0 or y > h: vy *= -1
                cv2.putText(frame, f"{self.drone_id} VID {i+1}", (10, h-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255,255,255), 1)
                out.write(frame)
            out.release()
        else:
            # fallback: create a random binary file to simulate a video
            with open(local_path, "wb") as f:
                f.write(os.urandom(1000 * seconds + random.randint(0, 5000)))

        meta = {
            "path": str(local_path.resolve()),
            "filename": filename,
            "mime": "video/mp4",
            "size_bytes": local_path.stat().st_size,
            "checksum": sha256_of_file(local_path),
        }
        return meta

    def capture_file(self, kind: str = "text") -> dict:
        """
        Create a small file: text or binary.
        """
        ext = "txt" if kind == "text" else "bin"
        filename = f"{self.drone_id}_file_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"
        local_path = self.local_dir / filename
        if kind == "text":
            content = f"notes: {uuid.uuid4().hex}\nrandom: {random.randint(0,999999)}\n"
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            with open(local_path, "wb") as f:
                f.write(os.urandom(2048 + random.randint(0, 8192)))

        meta = {
            "path": str(local_path.resolve()),
            "filename": filename,
            "mime": "text/plain" if kind == "text" else "application/octet-stream",
            "size_bytes": local_path.stat().st_size,
            "checksum": sha256_of_file(local_path),
        }
        return meta

    # -------- upload function (simulated) --------
    def upload(self, local_meta: dict) -> dict:
        """
        Simulate upload by copying to remote_dir and returning a pointer URL in JSON.
        Pointer is storage_prefix + remote_path (by default 'file://').
        """
        src = pathlib.Path(local_meta["path"])
        if not src.exists():
            raise FileNotFoundError(f"Local file missing: {src}")
        dest_name = src.name
        dest = self.remote_dir / dest_name
        shutil.copy2(src, dest)

        # pointer URL; by default using file://, but you can set storage_prefix to other schemes
        pointer = f"{self.storage_prefix}{str(dest.resolve())}"
        return {
            "uri": pointer,
            "filename": local_meta["filename"],
            "mime": local_meta.get("mime", "application/octet-stream"),
            "size_bytes": local_meta.get("size_bytes", dest.stat().st_size),
            "checksum": local_meta.get("checksum", sha256_of_file(dest)),
        }

    # -------- compose payloads and run --------
    def _choose_payloads(self, seed_x: int = None) -> list:
        """
        Decide payload types by a simple random/divisibility scheme:
        - if x % 2 == 0 -> include images
        - if x % 3 == 0 -> include videos
        - if x % 5 == 0 -> include a file archive/text
        - always include telemetry occasionally
        """
        if seed_x is None:
            seed_x = random.randint(1, 1000)
        x = seed_x
        payloads = []

        if x % 2 == 0:
            # include 1..3 images
            for _ in range(random.randint(1, 3)):
                img_local = self.capture_image()
                img_remote = self.upload(img_local)
                payloads.append({
                    "type": "image",
                    "filename": img_remote["filename"],
                    "mime": img_remote["mime"],
                    "size_bytes": img_remote["size_bytes"],
                    "encryption": False,
                    "container": False,
                    "checksum": img_remote["checksum"],
                    "uri": img_remote["uri"],
                })

        if x % 3 == 0:
            # include 1 video
            vid_local = self.capture_video(seconds=random.randint(2,5))
            vid_remote = self.upload(vid_local)
            payloads.append({
                "type": "video",
                "filename": vid_remote["filename"],
                "mime": vid_remote["mime"],
                "size_bytes": vid_remote["size_bytes"],
                "encryption": False,
                "container": False,
                "checksum": vid_remote["checksum"],
                "uri": vid_remote["uri"],
            })

        if x % 5 == 0:
            # include a file (text or binary)
            kind = random.choice(["text", "binary"])
            f_local = self.capture_file(kind="text" if kind == "text" else "binary")
            f_remote = self.upload(f_local)
            payloads.append({
                "type": "archive" if kind == "binary" else "text",
                "filename": f_remote["filename"],
                "mime": f_remote["mime"],
                "size_bytes": f_remote["size_bytes"],
                "encryption": False if kind == "text" else random.choice([True, False]),
                "container": True if kind == "binary" else False,
                "checksum": f_remote["checksum"],
                "uri": f_remote["uri"],
            })

        # 10% chance to include telemetry payload as separate payload entry
        if random.random() < 0.1:
            telemetry_blob = {"type": "telemetry_snapshot", "filename": f"tele_{int(time.time())}.json", "mime": "application/json",
                              "size_bytes": 512, "encryption": False, "container": False, "checksum": hashlib.sha256(os.urandom(20)).hexdigest()}
            payloads.append(telemetry_blob)

        # If nothing chosen, always include at least one telemetry entry
        if not payloads:
            telemetry_blob = {"type": "telemetry", "filename": f"tele_{int(time.time())}.json", "mime": "application/json",
                              "size_bytes": 512, "encryption": False, "container": False, "checksum": hashlib.sha256(os.urandom(20)).hexdigest()}
            payloads.append(telemetry_blob)

        return payloads

    def run_drone(self, mission_id: str = None, mission_zone: str = None, seed_x: int = None) -> dict:
        """
        Produce a JSON payload similar to the sample format you provided.
        """
        timestamp = now_iso_z()
        mission_id = mission_id or rand_mission_id()
        mission_zone = mission_zone or random.choice(["zone-a", "zone-b", "zone-c"])
        geo = random_geo()
        telemetry = random_telemetry()

        payloads = self._choose_payloads(seed_x=seed_x)

        obj = {
            "drone_id": self.drone_id,
            "timestamp": timestamp,
            "mission_id": mission_id,
            "mission_zone": mission_zone,
            "geo": geo,
            "payloads": payloads,
            "telemetry": telemetry,
            "signature": None,  # placeholder; sign externally if needed
            "firmware_version": f"v{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}",
            "operator_id": rand_operator(),
            "additional_metadata": {
                "camera_model": random.choice(["CAM-X1000", "CAM-PRO-4k", "CAM-STD-1"]),
                "frame_rate": random.choice([15, 25, 30])
            }
        }
        return obj

# -------------------------
# Example CLI
# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--drone-id", default="DRN-001")
    ap.add_argument("--count", type=int, default=1, help="How many sample payloads to generate")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--storage-prefix", default="file://", help="Prefix used for returned pointer URIs")
    args = ap.parse_args()

    random.seed(args.seed)
    d = Drone(drone_id=args.drone_id, storage_prefix=args.storage_prefix)

    for i in range(args.count):
        seed_x = None if args.seed is None else (args.seed + i)
        sample = d.run_drone(seed_x=seed_x)
        print(json.dumps(sample, indent=2))
        print("----")

if __name__ == "__main__":
    main()
