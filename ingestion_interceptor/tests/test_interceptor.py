"""
Tests for the Ingestion Interceptor pipeline.
Run with: python -m pytest ingestion_interceptor/tests/ -v
      or: python -m unittest ingestion_interceptor.tests.test_interceptor -v
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ingestion_interceptor import (
    IngestionInterceptor,
    InterceptorConfig,
    ingestion_interceptor,
    validate_submission,
)
from ingestion_interceptor.authenticator import AuthResult, Authenticator, DeviceRegistry
from ingestion_interceptor.payload_analyzer import analyze_payload, compute_payload_risk_score
from ingestion_interceptor.models import PayloadEntry
from ingestion_interceptor.checksum_verifier import compute_bytes_checksum, resolve_file_path
from ingestion_interceptor.uplink import CommandType, UplinkCommand, UplinkReceiver


def _make_sample(overrides=None):
    """Create a minimal valid drone submission."""
    base = {
        "drone_id": "DRN-001",
        "timestamp": "2025-10-13T03:00:12Z",
        "payloads": [
            {"type": "image", "filename": "test.jpg", "mime": "image/jpeg",
             "size_bytes": 50000, "encryption": False, "container": False},
        ],
    }
    if overrides:
        base.update(overrides)
    return base


class TestValidator(unittest.TestCase):

    def test_valid_submission(self):
        config = InterceptorConfig()
        errors, warnings = validate_submission(_make_sample(), config)
        self.assertEqual(errors, [])

    def test_missing_drone_id(self):
        sample = _make_sample()
        del sample["drone_id"]
        config = InterceptorConfig()
        errors, _ = validate_submission(sample, config)
        self.assertIn("missing_field:drone_id", errors)

    def test_missing_payloads(self):
        sample = _make_sample()
        del sample["payloads"]
        config = InterceptorConfig()
        errors, _ = validate_submission(sample, config)
        self.assertIn("missing_field:payloads", errors)

    def test_empty_payloads(self):
        sample = _make_sample({"payloads": []})
        config = InterceptorConfig()
        errors, _ = validate_submission(sample, config)
        self.assertIn("invalid_payloads:must_be_nonempty_list", errors)

    def test_invalid_timestamp(self):
        sample = _make_sample({"timestamp": "not-a-date"})
        config = InterceptorConfig()
        errors, _ = validate_submission(sample, config)
        self.assertIn("invalid_timestamp:not_iso8601", errors)

    def test_missing_signature_when_required(self):
        sample = _make_sample()
        config = InterceptorConfig(require_signature=True)
        errors, _ = validate_submission(sample, config)
        self.assertIn("missing_signature", errors)

    def test_path_traversal_blocked(self):
        sample = _make_sample({
            "payloads": [
                {"type": "text", "filename": "../../../etc/passwd", "mime": "text/plain",
                 "size_bytes": 100, "encryption": False, "container": False},
            ]
        })
        config = InterceptorConfig()
        errors, _ = validate_submission(sample, config)
        self.assertTrue(any("path_traversal" in e for e in errors))

    def test_oversized_payload_rejected(self):
        sample = _make_sample({
            "payloads": [
                {"type": "video", "filename": "big.mp4", "mime": "video/mp4",
                 "size_bytes": 600_000_000, "encryption": False, "container": False},
            ]
        })
        config = InterceptorConfig(max_payload_size_bytes=500_000_000)
        errors, _ = validate_submission(sample, config)
        self.assertTrue(any("exceeds_max_size" in e for e in errors))


class TestPayloadAnalyzer(unittest.TestCase):

    def _make_payload(self, **kwargs):
        defaults = {"type": "image", "filename": "test.jpg", "mime": "image/jpeg",
                     "size_bytes": 50000, "encryption": False, "container": False}
        defaults.update(kwargs)
        return PayloadEntry(**defaults)

    def test_clean_payload(self):
        p = self._make_payload()
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertEqual(flags, [])

    def test_encrypted_flag(self):
        p = self._make_payload(encryption=True)
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertIn("encrypted_payload", flags)

    def test_large_binary_flag(self):
        p = self._make_payload(size_bytes=15_000_000)
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertIn("large_binary", flags)

    def test_executable_flag(self):
        p = self._make_payload(filename="malware.exe", mime="application/x-msdownload")
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertIn("executable_file", flags)
        self.assertIn("suspicious_mime", flags)

    def test_double_extension(self):
        p = self._make_payload(filename="photo.jpg.exe")
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertIn("double_extension", flags)

    def test_mime_mismatch(self):
        p = self._make_payload(filename="test.png", mime="image/jpeg")
        config = InterceptorConfig()
        flags = analyze_payload(p, config)
        self.assertIn("mime_extension_mismatch", flags)

    def test_risk_score_clean(self):
        score = compute_payload_risk_score([])
        self.assertEqual(score, 0.0)

    def test_risk_score_critical(self):
        score = compute_payload_risk_score(["executable_file", "suspicious_mime"])
        self.assertGreater(score, 0.5)


class TestAuthenticator(unittest.TestCase):

    def test_known_trusted_device(self):
        registry = DeviceRegistry(registry={"DRN-001": {"trusted": True, "reputation": 0.9}})
        auth = Authenticator(device_registry=registry)
        result = auth.authenticate("DRN-001")
        self.assertEqual(result.status, "authenticated")
        self.assertEqual(result.reputation, 0.9)

    def test_known_untrusted_device(self):
        registry = DeviceRegistry(registry={"DRN-002": {"trusted": False, "reputation": 0.4}})
        auth = Authenticator(device_registry=registry)
        result = auth.authenticate("DRN-002")
        self.assertEqual(result.status, "untrusted")

    def test_unknown_device_flag_policy(self):
        registry = DeviceRegistry(registry={})
        auth = Authenticator(device_registry=registry, unknown_device_policy="flag")
        result = auth.authenticate("DRN-999")
        self.assertEqual(result.status, "unknown")

    def test_unknown_device_reject_policy(self):
        registry = DeviceRegistry(registry={})
        auth = Authenticator(device_registry=registry, unknown_device_policy="reject")
        result = auth.authenticate("DRN-999")
        self.assertEqual(result.status, "rejected")

    def test_revoked_device(self):
        registry = DeviceRegistry(registry={"DRN-001": {"trusted": True, "reputation": 0.9}})
        registry.revoke_device("DRN-001")
        auth = Authenticator(device_registry=registry)
        result = auth.authenticate("DRN-001")
        self.assertEqual(result.status, "rejected")


class TestInterceptorPipeline(unittest.TestCase):

    def _make_interceptor(self, **kwargs):
        return IngestionInterceptor(
            device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
            zone_risk_lookup={"zone-a": 0.6},
            **kwargs,
        )

    def test_normal_submission(self):
        interceptor = self._make_interceptor()
        result = interceptor.process(_make_sample({
            "mission_zone": "zone-a",
            "operator_id": "OP-12",
        }))
        self.assertTrue(result.success)
        self.assertEqual(result.ingest_metadata.auth_result, "authenticated")
        self.assertEqual(result.ingest_metadata.reputation, 0.9)
        self.assertEqual(result.ingest_metadata.zone_risk, 0.6)
        self.assertEqual(len(result.artifact_records), 1)

    def test_suspicious_submission(self):
        interceptor = self._make_interceptor()
        result = interceptor.process(_make_sample({
            "drone_id": "DRN-001",
            "payloads": [
                {"type": "archive", "filename": "bundle.zip", "mime": "application/zip",
                 "size_bytes": 15000000, "encryption": True, "container": True},
            ],
        }))
        self.assertTrue(result.success)
        flags = result.ingest_metadata.insecure_flags
        self.assertIn("encrypted_payload", flags)
        self.assertIn("nested_archive", flags)
        self.assertIn("large_binary", flags)

    def test_backward_compatible_api(self):
        output = ingestion_interceptor(
            _make_sample(),
            device_registry={"DRN-001": {"trusted": True, "reputation": 0.9}},
            zone_risk_lookup={"zone-a": 0.6},
        )
        self.assertIn("ingest_metadata", output)
        self.assertIn("artifact_records", output)

    def test_invalid_submission_returns_error(self):
        interceptor = self._make_interceptor()
        result = interceptor.process({"drone_id": "DRN-001"})
        self.assertFalse(result.success)
        self.assertTrue(len(result.errors) > 0)

    def test_stats_tracking(self):
        interceptor = self._make_interceptor()
        interceptor.process(_make_sample())
        interceptor.process({"drone_id": "X"})  # invalid
        self.assertEqual(interceptor.stats["total_processed"], 1)
        self.assertEqual(interceptor.stats["total_rejected"], 1)


class TestUplink(unittest.TestCase):

    def test_push_and_poll(self):
        receiver = UplinkReceiver(mode="memory")
        cmd = UplinkCommand(
            command_type=CommandType.QUARANTINE,
            target="ingest_abc123",
            command_id="cmd-001",
        )
        receiver.push_command(cmd)
        commands = receiver.poll_commands()
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].target, "ingest_abc123")

    def test_acknowledge(self):
        receiver = UplinkReceiver(mode="memory")
        cmd = UplinkCommand(
            command_type=CommandType.QUARANTINE, target="x", command_id="cmd-001"
        )
        receiver.push_command(cmd)
        receiver.acknowledge("cmd-001")
        commands = receiver.poll_commands()
        self.assertEqual(len(commands), 0)


class TestChecksumVerifier(unittest.TestCase):

    def test_compute_bytes_checksum(self):
        result = compute_bytes_checksum(b"hello world", "sha256")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 64)

    def test_resolve_file_uri(self):
        path = resolve_file_path("file:/home/user/test.jpg")
        self.assertEqual(path, "/home/user/test.jpg")

    def test_resolve_s3_uri(self):
        path = resolve_file_path("s3://bucket/key")
        self.assertIsNone(path)


if __name__ == "__main__":
    unittest.main()
