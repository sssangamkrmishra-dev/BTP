"""
Sensor suite: camera, video recorder, telemetry logger, file generators.
Creates actual files on disk with realistic content and checksums.
"""

import hashlib
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import DroneConfig
from .models import CapturedPayload, DroneState


class SensorSuite:
    """
    Simulates onboard sensors that capture payloads during flight.

    Sensors:
        - Still camera: generates JPEG-like image files
        - Video camera: generates MP4-like video files
        - Telemetry logger: generates JSON telemetry snapshots
        - Text logger: generates mission log files
        - Archive bundler: generates ZIP-like archive files
    """

    def __init__(self, config: DroneConfig):
        self.config = config
        self._storage_dir = os.path.join(config.storage_base_path, config.drone_id)
        os.makedirs(self._storage_dir, exist_ok=True)
        self._capture_count = 0

    # ── Image capture ──────────────────────────────────────────────────

    def capture_image(self, state: DroneState) -> CapturedPayload:
        """
        Simulate capturing a still image.
        Creates a real file on disk with JPEG-like header and random content.
        """
        self._capture_count += 1
        ts = int(time.time())
        filename = f"{self.config.drone_id}_img_{ts}_{uuid.uuid4().hex[:6]}.jpg"
        filepath = os.path.join(self._storage_dir, filename)

        # Generate realistic-sized image content with JPEG magic bytes
        min_size, max_size = self.config.image_size_bytes_range
        target_size = random.randint(min_size, max_size)

        content = bytearray()
        # JPEG magic bytes (SOI marker)
        content.extend(b'\xff\xd8\xff\xe0')
        # JFIF header stub
        content.extend(b'\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
        # Simulated EXIF with GPS (this is what the metadata sanitizer would clean)
        exif_comment = json.dumps({
            "GPS": {"lat": state.position.lat, "lon": state.position.lon, "alt": state.position.alt},
            "Camera": self.config.camera_model,
            "DateTime": datetime.now(timezone.utc).isoformat(),
            "Software": f"DroneOS/{self.config.firmware_version}",
        }).encode()
        content.extend(exif_comment)
        # Fill to target size with random data (simulates image pixel data)
        remaining = target_size - len(content) - 2
        if remaining > 0:
            content.extend(os.urandom(remaining))
        # JPEG EOI marker
        content.extend(b'\xff\xd9')

        with open(filepath, "wb") as f:
            f.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        uri = f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}"

        return CapturedPayload(
            type="image",
            filename=filename,
            mime="image/jpeg",
            size_bytes=len(content),
            encryption=False,
            container=False,
            checksum=checksum,
            uri=uri,
            local_path=filepath,
        )

    # ── Video capture ──────────────────────────────────────────────────

    def capture_video(self, state: DroneState, duration_sec: int = 5) -> CapturedPayload:
        """
        Simulate recording a video segment.
        Creates a file with MP4-like header and sized proportional to duration.
        """
        self._capture_count += 1
        ts = int(time.time())
        filename = f"{self.config.drone_id}_vid_{ts}_{uuid.uuid4().hex[:6]}.mp4"
        filepath = os.path.join(self._storage_dir, filename)

        target_size = self.config.video_size_bytes_per_sec * duration_sec
        # Add some variance
        target_size = int(target_size * random.uniform(0.8, 1.2))

        content = bytearray()
        # MP4 ftyp box header
        content.extend(b'\x00\x00\x00\x1c')  # box size
        content.extend(b'ftypisom')            # box type + brand
        content.extend(b'\x00\x00\x02\x00')   # minor version
        content.extend(b'isomiso2mp41')        # compatible brands
        # moov box stub
        content.extend(b'\x00\x00\x00\x08moov')
        # Fill to target size (simulates mdat)
        remaining = target_size - len(content)
        if remaining > 0:
            content.extend(os.urandom(remaining))

        with open(filepath, "wb") as f:
            f.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        uri = f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}"

        return CapturedPayload(
            type="video",
            filename=filename,
            mime="video/mp4",
            size_bytes=len(content),
            encryption=False,
            container=False,
            checksum=checksum,
            uri=uri,
            local_path=filepath,
        )

    # ── Telemetry snapshot ─────────────────────────────────────────────

    def capture_telemetry(self, state: DroneState) -> CapturedPayload:
        """
        Generate a telemetry snapshot as a JSON file.
        Contains full drone state at the moment of capture.
        """
        self._capture_count += 1
        ts = int(time.time())
        filename = f"{self.config.drone_id}_telem_{ts}_{uuid.uuid4().hex[:6]}.json"
        filepath = os.path.join(self._storage_dir, filename)

        telemetry_data = {
            "drone_id": self.config.drone_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "position": state.position.to_dict(),
            "telemetry": state.telemetry_dict(),
            "status": state.status.value,
            "uptime_sec": round(state.uptime_sec, 1),
            "total_distance_m": round(state.total_distance_m, 1),
            "payloads_captured": state.payloads_captured,
            "firmware": self.config.firmware_version,
            "warnings": state.warnings,
        }

        content = json.dumps(telemetry_data, indent=2).encode("utf-8")
        with open(filepath, "wb") as f:
            f.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        uri = f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}"

        return CapturedPayload(
            type="telemetry",
            filename=filename,
            mime="application/json",
            size_bytes=len(content),
            encryption=False,
            container=False,
            checksum=checksum,
            uri=uri,
            local_path=filepath,
        )

    # ── Text log ───────────────────────────────────────────────────────

    def capture_log(self, state: DroneState, entries: Optional[List[str]] = None) -> CapturedPayload:
        """Generate a mission log file."""
        self._capture_count += 1
        ts = int(time.time())
        filename = f"{self.config.drone_id}_log_{ts}_{uuid.uuid4().hex[:6]}.txt"
        filepath = os.path.join(self._storage_dir, filename)

        if entries is None:
            entries = [
                f"[{datetime.now(timezone.utc).isoformat()}] Mission active",
                f"Position: {state.position.lat:.6f}, {state.position.lon:.6f}, alt={state.position.alt:.1f}m",
                f"Battery: {state.battery_pct:.1f}%, Speed: {state.speed_ms:.1f} m/s",
                f"Heading: {state.heading_deg:.1f} deg, Signal: {state.signal_strength_pct:.1f}%",
                f"Payloads captured: {state.payloads_captured}",
            ]

        content = "\n".join(entries).encode("utf-8")
        with open(filepath, "wb") as f:
            f.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        uri = f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}"

        return CapturedPayload(
            type="text",
            filename=filename,
            mime="text/plain",
            size_bytes=len(content),
            encryption=False,
            container=False,
            checksum=checksum,
            uri=uri,
            local_path=filepath,
        )

    @property
    def capture_count(self) -> int:
        return self._capture_count
