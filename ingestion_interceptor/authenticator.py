"""
Device authentication for the Ingestion Interceptor.
Supports pluggable backends: registry (dict-based), JWT, and mTLS stubs.
"""

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class AuthResult:
    status: str  # "authenticated", "untrusted", "unknown", "rejected", "error"
    drone_id: str
    reputation: Optional[float] = None
    trusted: bool = False
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"status": self.status, "drone_id": self.drone_id, "trusted": self.trusted}
        if self.reputation is not None:
            d["reputation"] = self.reputation
        if self.details:
            d["details"] = self.details
        return d


class DeviceRegistry:
    """
    In-memory device registry backed by a dict or a JSON file.
    In production, this would be replaced by a database or external service call.
    """

    def __init__(self, registry: Optional[Dict[str, Dict[str, Any]]] = None, registry_path: Optional[str] = None):
        if registry is not None:
            self._registry = dict(registry)
        elif registry_path:
            self._registry = self._load_from_file(registry_path)
        else:
            self._registry = {}

    @staticmethod
    def _load_from_file(path: str) -> Dict[str, Dict[str, Any]]:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("Failed to load device registry from %s: %s", path, e)
            return {}

    def lookup(self, drone_id: str) -> Optional[Dict[str, Any]]:
        return self._registry.get(drone_id)

    def register_device(self, drone_id: str, info: Dict[str, Any]) -> None:
        self._registry[drone_id] = info

    def revoke_device(self, drone_id: str) -> bool:
        if drone_id in self._registry:
            self._registry[drone_id]["trusted"] = False
            self._registry[drone_id]["revoked"] = True
            return True
        return False

    def list_devices(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._registry)


class SignatureVerifier:
    """
    Verifies cryptographic signatures on drone submissions.
    Currently supports HMAC-SHA256 for demo purposes.
    In production, use Ed25519 or similar asymmetric scheme.
    """

    def __init__(self, key_store: Optional[Dict[str, str]] = None):
        # key_store: drone_id -> shared secret (for HMAC) or public key
        self._key_store = key_store or {}

    def verify(self, drone_id: str, signature: Optional[str], payload_hash: str) -> Dict[str, Any]:
        """
        Verify a drone's signature against the payload hash.
        Returns {"valid": bool, "reason": str}
        """
        if not signature:
            return {"valid": False, "reason": "no_signature_provided"}

        secret = self._key_store.get(drone_id)
        if not secret:
            return {"valid": False, "reason": "no_key_for_device"}

        # Parse signature format: "hmac-sha256:<hex>" or "ed25519:<hex>"
        if ":" in signature:
            scheme, sig_hex = signature.split(":", 1)
        else:
            scheme, sig_hex = "unknown", signature

        if scheme == "hmac-sha256":
            expected = hmac.new(secret.encode(), payload_hash.encode(), hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(expected, sig_hex)
            return {"valid": valid, "reason": "hmac_verified" if valid else "hmac_mismatch"}

        # For ed25519 and other schemes, we'd use a real crypto library.
        # For now, log and accept with a warning.
        logger.warning("Signature scheme '%s' not fully implemented; marking as unverified", scheme)
        return {"valid": False, "reason": f"unsupported_scheme:{scheme}"}


class Authenticator:
    """
    Orchestrates device authentication by combining registry lookup and signature verification.
    """

    def __init__(
        self,
        device_registry: Optional[DeviceRegistry] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
        unknown_device_policy: str = "flag",
    ):
        self._registry = device_registry or DeviceRegistry()
        self._sig_verifier = signature_verifier or SignatureVerifier()
        self._unknown_policy = unknown_device_policy

    def authenticate(self, drone_id: str, signature: Optional[str] = None, payload_hash: str = "") -> AuthResult:
        """
        Authenticate a drone device.

        Steps:
        1. Look up drone in device registry.
        2. If found, check trust status and reputation.
        3. If signature provided, verify it.
        4. Apply unknown device policy if not in registry.
        """
        reg_info = self._registry.lookup(drone_id)

        if reg_info is None:
            logger.info("Device %s not found in registry (policy: %s)", drone_id, self._unknown_policy)
            if self._unknown_policy == "reject":
                return AuthResult(
                    status="rejected",
                    drone_id=drone_id,
                    details={"reason": "device_not_registered"},
                )
            return AuthResult(
                status="unknown",
                drone_id=drone_id,
                details={"reason": "device_not_in_registry", "policy_applied": self._unknown_policy},
            )

        if reg_info.get("revoked"):
            return AuthResult(
                status="rejected",
                drone_id=drone_id,
                reputation=reg_info.get("reputation", 0.0),
                details={"reason": "device_revoked"},
            )

        trusted = reg_info.get("trusted", False)
        reputation = reg_info.get("reputation")

        # Verify signature if provided
        sig_result = None
        if signature:
            sig_result = self._sig_verifier.verify(drone_id, signature, payload_hash)
            if sig_result["valid"]:
                logger.info("Signature verified for %s", drone_id)
            else:
                logger.warning("Signature verification failed for %s: %s", drone_id, sig_result["reason"])
                # Downgrade trust if signature fails
                trusted = False

        status = "authenticated" if trusted else "untrusted"

        return AuthResult(
            status=status,
            drone_id=drone_id,
            reputation=reputation,
            trusted=trusted,
            details={
                "registry_trusted": reg_info.get("trusted", False),
                "signature_check": sig_result,
                "firmware_whitelist": reg_info.get("firmware_whitelist"),
            },
        )
