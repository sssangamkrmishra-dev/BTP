"""
Reputation persistence for the threat estimator.

Provides an `InMemoryReputationStore` suitable for tests, demos, and
in-process deployments. Production deployments should subclass it and
override the four public methods — typically backed by Redis or
Postgres (see "Integration Points" in the design doc).

NOTE: this module intentionally mirrors the dict-backed registry
pattern used by `ingestion_interceptor.authenticator.DeviceRegistry`.
The host process injects concrete instances into the main
`GameTheoreticThreatEstimator` via constructor DI.
"""

import json
import logging
import threading
from typing import Dict, List, Optional

from .models import ReputationProfile, ReputationSource, _utc_now_iso

logger = logging.getLogger(__name__)


class InMemoryReputationStore:
    """
    Thread-safe in-memory reputation store.

    Initial seed values can be supplied as a `{drone_id: reputation}`
    dict or loaded from a JSON file. In production, replace with a
    real-backend subclass (Redis, Postgres, etc.) that implements
    `get`, `put`, `delete`, and `list_drones`.
    """

    # ── Construction ──────────────────────────────────────────────────
    def __init__(
        self,
        initial: Optional[Dict[str, float]] = None,
        path: Optional[str] = None,
    ):
        self._lock = threading.RLock()
        self._store: Dict[str, ReputationProfile] = {}

        if initial is not None:
            for drone_id, value in initial.items():
                self._store[drone_id] = ReputationProfile(
                    drone_id=drone_id,
                    value=float(value),
                    source=ReputationSource.HISTORY.value,
                )
        elif path:
            self._load_from_file(path)

    def _load_from_file(self, path: str) -> None:
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("failed to load reputation store from %s: %s", path, exc)
            return
        for drone_id, record in data.items():
            if isinstance(record, (int, float)):
                value = float(record)
                self._store[drone_id] = ReputationProfile(
                    drone_id=drone_id,
                    value=value,
                    source=ReputationSource.HISTORY.value,
                )
            elif isinstance(record, dict) and "value" in record:
                self._store[drone_id] = ReputationProfile(
                    drone_id=drone_id,
                    value=float(record["value"]),
                    source=record.get("source", ReputationSource.HISTORY.value),
                    updated_at=record.get("updated_at", _utc_now_iso()),
                    sample_count=int(record.get("sample_count", 0)),
                    last_verdict=record.get("last_verdict"),
                )

    # ── Public API ────────────────────────────────────────────────────
    def get(self, drone_id: str) -> Optional[ReputationProfile]:
        with self._lock:
            profile = self._store.get(drone_id)
            # Return a shallow copy so callers cannot mutate the store.
            if profile is None:
                return None
            return ReputationProfile(
                drone_id=profile.drone_id,
                value=profile.value,
                source=profile.source,
                updated_at=profile.updated_at,
                sample_count=profile.sample_count,
                last_verdict=profile.last_verdict,
            )

    def put(self, profile: ReputationProfile) -> None:
        if not 0.0 <= profile.value <= 1.0:
            raise ValueError(
                f"reputation must be in [0, 1]; got {profile.value} for {profile.drone_id}"
            )
        with self._lock:
            self._store[profile.drone_id] = profile

    def delete(self, drone_id: str) -> bool:
        with self._lock:
            return self._store.pop(drone_id, None) is not None

    def list_drones(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())

    def __contains__(self, drone_id: str) -> bool:
        with self._lock:
            return drone_id in self._store

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def snapshot(self) -> Dict[str, Dict]:
        """Serialise the full store — useful for persistence or audit."""
        with self._lock:
            return {
                drone_id: profile.to_dict()
                for drone_id, profile in self._store.items()
            }
