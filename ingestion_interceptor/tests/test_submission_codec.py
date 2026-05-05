"""
Tests for the binary submission codec (TLV marshaller).
Run with: python -m unittest ingestion_interceptor.tests.test_submission_codec -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ingestion_interceptor.protocol import (
    SUBMISSION_MAGIC,
    decode_submission,
    encode_submission,
)
from ingestion_interceptor.protocol.errors import (
    MalformedSubmission,
    SubmissionCodecError,
)


def _full_submission():
    return {
        "drone_id": "DRN-001",
        "timestamp": "2025-10-13T03:00:12Z",
        "mission_id": "MSN-142",
        "mission_zone": "zone-alpha",
        "geo": {"lat": 12.971598, "lon": 77.594566, "alt": 120.0},
        "telemetry": {
            "speed": 12.5, "heading": 145.2,
            "battery": 78.4, "signal_strength": 92.0,
            "vertical_speed": 0.5, "temperature": 25.0,
        },
        "signature": "hmac-sha256:abcdef0123",
        "firmware_version": "v2.1.0",
        "operator_id": "OP-12",
        "additional_metadata": {
            "camera_model": "CAM-X1000",
            "frame_rate": 30,
            "mission_sensitivity": "high",
        },
        "payloads": [
            {"type": "video", "filename": "drn001_v1.mp4",
             "mime": "video/mp4", "size_bytes": 4500000,
             "encryption": False, "container": False,
             "checksum": "b5bb9d8014a0", "uri": "file:/tmp/v1.mp4"},
            {"type": "image", "filename": "drn001_i1.jpg",
             "mime": "image/jpeg", "size_bytes": 2100000,
             "encryption": True, "container": False,
             "checksum": "deadbeef"},
        ],
    }


class TestSubmissionCodec(unittest.TestCase):

    def test_round_trip_full_submission(self):
        sub = _full_submission()
        wire = encode_submission(sub)
        out = decode_submission(wire)
        self.assertEqual(out["drone_id"], "DRN-001")
        self.assertEqual(out["timestamp"], "2025-10-13T03:00:12Z")
        self.assertEqual(out["mission_id"], "MSN-142")
        self.assertEqual(out["mission_zone"], "zone-alpha")
        self.assertEqual(out["firmware_version"], "v2.1.0")
        self.assertEqual(out["operator_id"], "OP-12")
        self.assertEqual(out["signature"], "hmac-sha256:abcdef0123")

    def test_round_trip_geo(self):
        sub = _full_submission()
        out = decode_submission(encode_submission(sub))
        self.assertAlmostEqual(out["geo"]["lat"], 12.971598)
        self.assertAlmostEqual(out["geo"]["lon"], 77.594566)
        self.assertAlmostEqual(out["geo"]["alt"], 120.0)

    def test_round_trip_telemetry(self):
        sub = _full_submission()
        out = decode_submission(encode_submission(sub))
        self.assertAlmostEqual(out["telemetry"]["speed"], 12.5)
        self.assertAlmostEqual(out["telemetry"]["battery"], 78.4)
        self.assertAlmostEqual(out["telemetry"]["signal_strength"], 92.0)
        self.assertAlmostEqual(out["telemetry"]["temperature"], 25.0, places=4)

    def test_round_trip_payloads(self):
        sub = _full_submission()
        out = decode_submission(encode_submission(sub))
        self.assertEqual(len(out["payloads"]), 2)
        p1, p2 = out["payloads"]
        self.assertEqual(p1["type"], "video")
        self.assertEqual(p1["filename"], "drn001_v1.mp4")
        self.assertEqual(p1["mime"], "video/mp4")
        self.assertEqual(p1["size_bytes"], 4500000)
        self.assertFalse(p1["encryption"])
        self.assertEqual(p1["checksum"], "b5bb9d8014a0")
        self.assertEqual(p1["uri"], "file:/tmp/v1.mp4")
        self.assertEqual(p2["type"], "image")
        self.assertTrue(p2["encryption"])
        # uri was not provided for p2 — should be absent
        self.assertNotIn("uri", p2)

    def test_round_trip_additional_metadata_coerces_to_strings(self):
        # frame_rate=30 (int) should come back as "30" (string)
        sub = _full_submission()
        out = decode_submission(encode_submission(sub))
        self.assertEqual(out["additional_metadata"]["camera_model"], "CAM-X1000")
        self.assertEqual(out["additional_metadata"]["frame_rate"], "30")
        self.assertEqual(out["additional_metadata"]["mission_sensitivity"], "high")

    def test_minimal_submission(self):
        minimal = {
            "drone_id": "DRN-XYZ",
            "timestamp": "2025-01-01T00:00:00Z",
            "payloads": [
                {"type": "telemetry", "filename": "t.json", "mime": "application/json",
                 "size_bytes": 100, "encryption": False, "container": False},
            ],
        }
        wire = encode_submission(minimal)
        out = decode_submission(wire)
        self.assertEqual(out["drone_id"], "DRN-XYZ")
        self.assertEqual(len(out["payloads"]), 1)
        self.assertEqual(out["payloads"][0]["type"], "telemetry")
        self.assertNotIn("mission_id", out)
        self.assertNotIn("geo", out)

    def test_missing_drone_id_rejected_at_encode(self):
        with self.assertRaises(SubmissionCodecError):
            encode_submission({"timestamp": "2025-01-01T00:00:00Z", "payloads": []})

    def test_missing_timestamp_rejected_at_encode(self):
        with self.assertRaises(SubmissionCodecError):
            encode_submission({"drone_id": "DRN-X", "payloads": []})

    def test_bad_magic_rejected_at_decode(self):
        with self.assertRaises(MalformedSubmission):
            decode_submission(b"XXXX" + b"\x01\x00\x00\x00" + b"\x00\x00")

    def test_truncated_envelope_rejected_at_decode(self):
        with self.assertRaises(MalformedSubmission):
            decode_submission(b"DSUB\x01")

    def test_truncated_tlv_rejected_at_decode(self):
        sub = {
            "drone_id": "DRN-X",
            "timestamp": "2025-01-01T00:00:00Z",
            "payloads": [],
        }
        wire = encode_submission(sub)
        # Lop off the last few bytes of the value of the timestamp TLV
        with self.assertRaises(MalformedSubmission):
            decode_submission(wire[:-3])

    def test_unicode_strings_round_trip(self):
        sub = {
            "drone_id": "DRN-001",
            "timestamp": "2025-10-13T03:00:12Z",
            "operator_id": "オペレーター-12",
            "additional_metadata": {"camera_model": "カメラ-X"},
            "payloads": [
                {"type": "image", "filename": "图像_001.jpg",
                 "mime": "image/jpeg", "size_bytes": 100,
                 "encryption": False, "container": False},
            ],
        }
        out = decode_submission(encode_submission(sub))
        self.assertEqual(out["operator_id"], "オペレーター-12")
        self.assertEqual(out["payloads"][0]["filename"], "图像_001.jpg")
        self.assertEqual(out["additional_metadata"]["camera_model"], "カメラ-X")

    def test_envelope_starts_with_magic(self):
        sub = {"drone_id": "DRN-X", "timestamp": "2025-01-01T00:00:00Z", "payloads": []}
        wire = encode_submission(sub)
        self.assertEqual(wire[:4], SUBMISSION_MAGIC)


if __name__ == "__main__":
    unittest.main()
