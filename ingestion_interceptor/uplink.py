"""
Uplink communication module for receiving commands from the control center.
Supports receiving quarantine orders, parameter updates, and feedback loop data.

In production, this would use gRPC, MQTT, or a REST polling mechanism.
Currently provides a local command queue for demonstration and testing.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CommandType(Enum):
    QUARANTINE = "quarantine"
    RELEASE = "release"
    UPDATE_CONFIG = "update_config"
    REVOKE_DEVICE = "revoke_device"
    UPDATE_ZONE_RISK = "update_zone_risk"
    FORCE_RESCAN = "force_rescan"


@dataclass
class UplinkCommand:
    command_type: CommandType
    target: str  # drone_id, ingest_id, or "*" for broadcast
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    command_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_type": self.command_type.value,
            "target": self.target,
            "parameters": self.parameters,
            "timestamp": self.timestamp,
            "command_id": self.command_id,
        }


class UplinkReceiver:
    """
    Receives and queues commands from the control center.

    Modes:
    - file: Watches a JSON file for new commands (for testing/demo)
    - memory: In-memory queue (for unit testing)

    In production, replace with gRPC/MQTT client.
    """

    def __init__(self, mode: str = "memory", command_file: Optional[str] = None):
        self._mode = mode
        self._command_file = command_file
        self._queue: List[UplinkCommand] = []
        self._processed_ids: set = set()

    def push_command(self, command: UplinkCommand) -> None:
        """Push a command directly into the queue (for testing or internal use)."""
        self._queue.append(command)

    def poll_commands(self) -> List[UplinkCommand]:
        """Poll for new commands. Returns list of unprocessed commands."""
        if self._mode == "file" and self._command_file:
            self._load_from_file()

        new_commands = [c for c in self._queue if c.command_id not in self._processed_ids]
        return new_commands

    def acknowledge(self, command_id: str) -> None:
        """Mark a command as processed."""
        self._processed_ids.add(command_id)

    def _load_from_file(self) -> None:
        """Load commands from a JSON file."""
        if not self._command_file or not os.path.exists(self._command_file):
            return
        try:
            with open(self._command_file, "r") as f:
                data = json.load(f)
            for entry in data:
                cmd = UplinkCommand(
                    command_type=CommandType(entry["command_type"]),
                    target=entry.get("target", "*"),
                    parameters=entry.get("parameters", {}),
                    timestamp=entry.get("timestamp", time.time()),
                    command_id=entry.get("command_id", ""),
                )
                if cmd.command_id not in self._processed_ids:
                    self._queue.append(cmd)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error("Failed to load uplink commands: %s", e)


class UplinkCommandHandler:
    """
    Processes uplink commands and applies them to the interceptor state.
    """

    def __init__(self, authenticator=None, zone_risk_lookup: Optional[Dict[str, float]] = None):
        self._authenticator = authenticator
        self._zone_risk = zone_risk_lookup or {}
        self._quarantined_ingests: set = set()

    @property
    def quarantined_ingests(self) -> set:
        return set(self._quarantined_ingests)

    @property
    def zone_risk_lookup(self) -> Dict[str, float]:
        return dict(self._zone_risk)

    def handle(self, command: UplinkCommand) -> Dict[str, Any]:
        """Process a single uplink command. Returns result dict."""
        handler_map = {
            CommandType.QUARANTINE: self._handle_quarantine,
            CommandType.RELEASE: self._handle_release,
            CommandType.REVOKE_DEVICE: self._handle_revoke_device,
            CommandType.UPDATE_ZONE_RISK: self._handle_update_zone_risk,
        }

        handler = handler_map.get(command.command_type)
        if handler is None:
            return {"status": "unsupported", "command_type": command.command_type.value}

        return handler(command)

    def _handle_quarantine(self, cmd: UplinkCommand) -> Dict[str, Any]:
        self._quarantined_ingests.add(cmd.target)
        logger.info("Quarantined ingest: %s", cmd.target)
        return {"status": "quarantined", "target": cmd.target}

    def _handle_release(self, cmd: UplinkCommand) -> Dict[str, Any]:
        self._quarantined_ingests.discard(cmd.target)
        logger.info("Released ingest: %s", cmd.target)
        return {"status": "released", "target": cmd.target}

    def _handle_revoke_device(self, cmd: UplinkCommand) -> Dict[str, Any]:
        if self._authenticator and hasattr(self._authenticator, "_registry"):
            self._authenticator._registry.revoke_device(cmd.target)
            logger.info("Revoked device: %s", cmd.target)
            return {"status": "revoked", "target": cmd.target}
        return {"status": "no_registry", "target": cmd.target}

    def _handle_update_zone_risk(self, cmd: UplinkCommand) -> Dict[str, Any]:
        zone = cmd.parameters.get("zone")
        risk = cmd.parameters.get("risk")
        if zone and risk is not None:
            self._zone_risk[zone] = float(risk)
            logger.info("Updated zone risk: %s = %s", zone, risk)
            return {"status": "updated", "zone": zone, "risk": risk}
        return {"status": "invalid_params"}
