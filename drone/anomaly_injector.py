"""
Anomaly injection for testing the detection pipeline.
Simulates compromised drone behavior: spoofed GPS, injected executables,
encrypted payloads, path traversal, etc.
"""

import hashlib
import os
import random
from typing import Any, Dict, List

from .config import DroneConfig
from .models import CapturedPayload, DroneState


class AnomalyInjector:
    """
    Injects realistic anomalies into drone state or payloads.

    Used to test the ingestion interceptor's ability to detect:
        - Spoofed telemetry (GPS jumps, negative speed, battery overflow)
        - Malicious payloads (executables, double extensions, path traversal)
        - Encrypted/container payloads that need deferred analysis
        - Oversized metadata fields (potential payload carriers)
    """

    def __init__(self, config: DroneConfig):
        self.config = config
        self._injected: List[str] = []

    def maybe_inject_telemetry(self, state: DroneState) -> DroneState:
        """Randomly inject telemetry anomalies into drone state."""
        if not self.config.inject_anomalies:
            return state
        if random.random() > self.config.anomaly_probability:
            return state

        anomaly = random.choice([
            "spoofed_gps", "negative_speed", "battery_overflow", "signal_dropout",
        ])

        if anomaly == "spoofed_gps":
            state.position.lat += random.uniform(-5, 5)  # huge GPS jump
            state.position.lon += random.uniform(-5, 5)
            self._injected.append("spoofed_gps")

        elif anomaly == "negative_speed":
            state.speed_ms = random.uniform(-10, -1)
            self._injected.append("negative_speed")

        elif anomaly == "battery_overflow":
            state.battery_pct = random.uniform(101, 200)
            self._injected.append("battery_overflow")

        elif anomaly == "signal_dropout":
            state.signal_strength_pct = 0.0
            self._injected.append("signal_dropout")

        return state

    def maybe_inject_payload(self, payloads: List[CapturedPayload]) -> List[CapturedPayload]:
        """Randomly inject a malicious payload into the list."""
        if not self.config.inject_anomalies:
            return payloads
        if random.random() > self.config.anomaly_probability:
            return payloads

        anomaly = random.choice([
            "executable_injection", "encrypted_payload",
            "path_traversal", "double_extension",
        ])

        storage_dir = os.path.join(self.config.storage_base_path, self.config.drone_id)
        os.makedirs(storage_dir, exist_ok=True)

        if anomaly == "executable_injection":
            filename = "update_patch.exe"
            filepath = os.path.join(storage_dir, filename)
            content = b"MZ" + os.urandom(5000)  # PE header magic bytes
            with open(filepath, "wb") as f:
                f.write(content)
            payloads.append(CapturedPayload(
                type="archive",
                filename=filename,
                mime="application/x-msdownload",
                size_bytes=len(content),
                encryption=False,
                container=False,
                checksum=hashlib.sha256(content).hexdigest(),
                uri=f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}",
                local_path=filepath,
            ))
            self._injected.append("executable_injection")

        elif anomaly == "encrypted_payload":
            filename = f"encrypted_data_{random.randint(100,999)}.zip"
            filepath = os.path.join(storage_dir, filename)
            content = os.urandom(50000)
            with open(filepath, "wb") as f:
                f.write(content)
            payloads.append(CapturedPayload(
                type="archive",
                filename=filename,
                mime="application/zip",
                size_bytes=len(content),
                encryption=True,
                container=True,
                checksum=hashlib.sha256(content).hexdigest(),
                uri=f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}",
                local_path=filepath,
            ))
            self._injected.append("encrypted_payload")

        elif anomaly == "path_traversal":
            filename = "../../../etc/shadow"
            payloads.append(CapturedPayload(
                type="text",
                filename=filename,
                mime="text/plain",
                size_bytes=1024,
                encryption=False,
                container=False,
                checksum=hashlib.sha256(b"fake").hexdigest(),
            ))
            self._injected.append("path_traversal")

        elif anomaly == "double_extension":
            filename = "mission_report.pdf.exe"
            filepath = os.path.join(storage_dir, filename)
            content = b"MZ" + os.urandom(3000)
            with open(filepath, "wb") as f:
                f.write(content)
            payloads.append(CapturedPayload(
                type="archive",
                filename=filename,
                mime="application/octet-stream",
                size_bytes=len(content),
                encryption=False,
                container=False,
                checksum=hashlib.sha256(content).hexdigest(),
                uri=f"{self.config.storage_uri_prefix}{os.path.abspath(filepath)}",
                local_path=filepath,
            ))
            self._injected.append("double_extension")

        return payloads

    def maybe_inject_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Inject oversized or dangerous metadata fields."""
        if not self.config.inject_anomalies:
            return metadata
        if random.random() > self.config.anomaly_probability:
            return metadata

        anomaly = random.choice(["oversized_metadata"])

        if anomaly == "oversized_metadata":
            metadata["__debug_dump"] = "A" * 50_000  # 50 KB field
            self._injected.append("oversized_metadata")

        return metadata

    @property
    def injected_anomalies(self) -> List[str]:
        return list(self._injected)

    def reset(self) -> None:
        self._injected.clear()
