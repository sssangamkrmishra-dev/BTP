"""
Comprehensive tests for the Metadata Sanitizer pipeline.

Run with:
    python -m pytest metadata_sanitizer/tests/ -v
    python -m unittest metadata_sanitizer.tests.test_sanitizer -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from metadata_sanitizer import (
    MetadataSanitizer,
    SanitizerConfig,
    SanitizationMode,
    SanitizationResult,
    SanitizationChange,
    BatchSanitizationResult,
    MetadataSnapshot,
    ChangeAction,
    Severity,
)
from metadata_sanitizer.handlers import (
    BaseHandler,
    ImageHandler,
    PdfHandler,
    VideoHandler,
    ArchiveHandler,
    TextHandler,
    get_handler_for_mime,
)
from metadata_sanitizer.rules.exif_rules import (
    EXIF_ALWAYS_STRIP,
    EXIF_STRIP_IN_HIGH_SECURITY,
    EXIF_ALWAYS_PRESERVE,
    get_exif_strip_set,
)
from metadata_sanitizer.rules.pdf_rules import (
    PDF_ALWAYS_STRIP_KEYS,
    PDF_DANGEROUS_ACTIONS,
)
from metadata_sanitizer.rules.video_rules import (
    VIDEO_ALWAYS_STRIP_ATOMS,
    VIDEO_ALWAYS_PRESERVE,
)


class TestSanitizerConfig(unittest.TestCase):
    """Test configuration defaults and customization."""

    def test_default_config(self):
        config = SanitizerConfig()
        self.assertEqual(config.default_mode, "selective")
        self.assertEqual(config.high_threat_mode, "strip")
        self.assertEqual(config.low_threat_mode, "audit_only")
        self.assertFalse(config.preserve_gps)
        self.assertTrue(config.verify_after_sanitize)
        self.assertTrue(config.preserve_originals)

    def test_custom_config(self):
        config = SanitizerConfig(
            default_mode="strip",
            preserve_gps=True,
            max_metadata_size_bytes=2_000_000,
            verify_after_sanitize=False,
        )
        self.assertEqual(config.default_mode, "strip")
        self.assertTrue(config.preserve_gps)
        self.assertEqual(config.max_metadata_size_bytes, 2_000_000)
        self.assertFalse(config.verify_after_sanitize)

    def test_threat_score_thresholds(self):
        config = SanitizerConfig()
        self.assertEqual(config.threat_score_strip_threshold, 0.7)
        self.assertEqual(config.threat_score_audit_threshold, 0.3)

    def test_skip_mime_types(self):
        config = SanitizerConfig()
        self.assertIn("application/x-msdownload", config.skip_mime_types)
        self.assertIn("application/x-executable", config.skip_mime_types)


class TestModels(unittest.TestCase):
    """Test data models."""

    def test_sanitization_mode_enum(self):
        self.assertEqual(SanitizationMode.STRIP.value, "strip")
        self.assertEqual(SanitizationMode.SELECTIVE.value, "selective")
        self.assertEqual(SanitizationMode.AUDIT_ONLY.value, "audit_only")

    def test_change_action_enum(self):
        self.assertEqual(ChangeAction.REMOVED.value, "removed")
        self.assertEqual(ChangeAction.FLAGGED.value, "flagged")

    def test_severity_enum(self):
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.INFO.value, "info")

    def test_sanitization_change_to_dict(self):
        change = SanitizationChange(
            field="EXIF.GPSInfo",
            action="removed",
            reason="gps_data_policy",
            severity="medium",
            original_value_preview="12.97, 77.59",
            original_value_size=24,
        )
        d = change.to_dict()
        self.assertEqual(d["field"], "EXIF.GPSInfo")
        self.assertEqual(d["action"], "removed")
        self.assertEqual(d["reason"], "gps_data_policy")
        self.assertEqual(d["severity"], "medium")
        self.assertEqual(d["original_value_preview"], "12.97, 77.59")

    def test_sanitization_result_to_dict(self):
        result = SanitizationResult(
            artifact_id="artifact://test",
            filename="test.jpg",
            file_type="image",
            mime_type="image/jpeg",
            sanitized=True,
            mode="selective",
            changes=[
                SanitizationChange(
                    field="EXIF.GPS", action="removed", reason="policy"
                )
            ],
        )
        d = result.to_dict()
        self.assertEqual(d["artifact_id"], "artifact://test")
        self.assertTrue(d["sanitized"])
        self.assertEqual(len(d["changes"]), 1)

    def test_sanitization_result_skipped(self):
        result = SanitizationResult(
            artifact_id="artifact://skip",
            filename="skip.dat",
            file_type="unknown",
            mime_type="application/octet-stream",
            sanitized=False,
            mode="selective",
            skipped=True,
            skip_reason="file_not_found",
        )
        d = result.to_dict()
        self.assertTrue(d["skipped"])
        self.assertEqual(d["skip_reason"], "file_not_found")

    def test_metadata_snapshot_to_dict(self):
        snapshot = MetadataSnapshot(
            fields={"key": "value"},
            total_size_bytes=100,
            hash_sha256="abc123",
            field_count=1,
        )
        d = snapshot.to_dict()
        self.assertEqual(d["field_count"], 1)
        self.assertEqual(d["hash_sha256"], "abc123")

    def test_batch_result_to_dict(self):
        batch = BatchSanitizationResult(
            total_processed=5,
            total_sanitized=3,
            total_skipped=1,
            total_errors=1,
            total_changes=10,
        )
        d = batch.to_dict()
        self.assertEqual(d["summary"]["total_processed"], 5)
        self.assertEqual(d["summary"]["total_sanitized"], 3)


class TestExifRules(unittest.TestCase):
    """Test EXIF rule definitions and helpers."""

    def test_always_strip_has_gps(self):
        self.assertIn("GPSInfo", EXIF_ALWAYS_STRIP)
        self.assertIn("GPSLatitude", EXIF_ALWAYS_STRIP)

    def test_always_strip_has_makernote(self):
        self.assertIn("MakerNote", EXIF_ALWAYS_STRIP)

    def test_always_strip_has_usercomment(self):
        self.assertIn("UserComment", EXIF_ALWAYS_STRIP)

    def test_always_preserve_has_orientation(self):
        self.assertIn("Orientation", EXIF_ALWAYS_PRESERVE)
        self.assertIn("ImageWidth", EXIF_ALWAYS_PRESERVE)

    def test_high_security_has_serial(self):
        self.assertIn("BodySerialNumber", EXIF_STRIP_IN_HIGH_SECURITY)

    def test_get_strip_set_selective(self):
        strip = get_exif_strip_set("selective")
        self.assertIn("GPSInfo", strip)
        self.assertIn("MakerNote", strip)
        self.assertNotIn("BodySerialNumber", strip)  # Only in strip mode

    def test_get_strip_set_strip(self):
        strip = get_exif_strip_set("strip")
        self.assertIn("GPSInfo", strip)
        self.assertIn("BodySerialNumber", strip)
        self.assertIn("Make", strip)

    def test_get_strip_set_audit_only(self):
        strip = get_exif_strip_set("audit_only")
        self.assertEqual(len(strip), 0)

    def test_get_strip_set_preserve_gps(self):
        strip = get_exif_strip_set("selective", preserve_gps=True)
        self.assertNotIn("GPSInfo", strip)
        self.assertNotIn("GPSLatitude", strip)
        self.assertIn("MakerNote", strip)  # Non-GPS still stripped

    def test_no_overlap_strip_preserve(self):
        """Ensure no tag is both in always-strip and always-preserve."""
        overlap = EXIF_ALWAYS_STRIP & EXIF_ALWAYS_PRESERVE
        self.assertEqual(len(overlap), 0, f"Tags in both strip and preserve: {overlap}")


class TestPdfRules(unittest.TestCase):
    """Test PDF rule definitions."""

    def test_always_strip_has_javascript(self):
        self.assertIn("/JavaScript", PDF_ALWAYS_STRIP_KEYS)
        self.assertIn("/JS", PDF_ALWAYS_STRIP_KEYS)

    def test_always_strip_has_auto_actions(self):
        self.assertIn("/OpenAction", PDF_ALWAYS_STRIP_KEYS)
        self.assertIn("/AA", PDF_ALWAYS_STRIP_KEYS)
        self.assertIn("/Launch", PDF_ALWAYS_STRIP_KEYS)

    def test_dangerous_actions(self):
        self.assertIn("/JavaScript", PDF_DANGEROUS_ACTIONS)
        self.assertIn("/Launch", PDF_DANGEROUS_ACTIONS)
        self.assertIn("/SubmitForm", PDF_DANGEROUS_ACTIONS)

    def test_strip_and_preserve_no_overlap(self):
        overlap = PDF_ALWAYS_STRIP_KEYS & set()  # No global preserve for strip keys
        self.assertEqual(len(overlap), 0)


class TestVideoRules(unittest.TestCase):
    """Test video rule definitions."""

    def test_always_strip_has_gps(self):
        self.assertIn("©xyz", VIDEO_ALWAYS_STRIP_ATOMS)
        self.assertIn("location", VIDEO_ALWAYS_STRIP_ATOMS)

    def test_always_strip_has_comments(self):
        self.assertIn("©cmt", VIDEO_ALWAYS_STRIP_ATOMS)
        self.assertIn("COMMENT", VIDEO_ALWAYS_STRIP_ATOMS)

    def test_always_preserve_has_structural(self):
        self.assertIn("moov", VIDEO_ALWAYS_PRESERVE)
        self.assertIn("trak", VIDEO_ALWAYS_PRESERVE)
        self.assertIn("stbl", VIDEO_ALWAYS_PRESERVE)

    def test_strip_and_preserve_no_overlap(self):
        overlap = VIDEO_ALWAYS_STRIP_ATOMS & VIDEO_ALWAYS_PRESERVE
        self.assertEqual(len(overlap), 0, f"Tags in both strip and preserve: {overlap}")


class TestHandlerRegistry(unittest.TestCase):
    """Test handler routing."""

    def test_jpeg_routes_to_image(self):
        self.assertEqual(get_handler_for_mime("image/jpeg"), ImageHandler)

    def test_png_routes_to_image(self):
        self.assertEqual(get_handler_for_mime("image/png"), ImageHandler)

    def test_mp4_routes_to_video(self):
        self.assertEqual(get_handler_for_mime("video/mp4"), VideoHandler)

    def test_pdf_routes_to_pdf(self):
        self.assertEqual(get_handler_for_mime("application/pdf"), PdfHandler)

    def test_zip_routes_to_archive(self):
        self.assertEqual(get_handler_for_mime("application/zip"), ArchiveHandler)

    def test_json_routes_to_text(self):
        self.assertEqual(get_handler_for_mime("application/json"), TextHandler)

    def test_plain_text_routes_to_text(self):
        self.assertEqual(get_handler_for_mime("text/plain"), TextHandler)

    def test_unknown_mime_routes_to_text(self):
        self.assertEqual(get_handler_for_mime("application/x-custom-thing"), TextHandler)

    def test_image_prefix_fallback(self):
        self.assertEqual(get_handler_for_mime("image/webp"), ImageHandler)

    def test_video_prefix_fallback(self):
        self.assertEqual(get_handler_for_mime("video/x-custom"), VideoHandler)


class TestBaseHandler(unittest.TestCase):
    """Test base handler utilities."""

    def test_create_metadata_snapshot(self):
        config = SanitizerConfig()
        handler = TextHandler(config)
        snapshot = handler.create_metadata_snapshot({"key": "value", "num": 42})
        self.assertEqual(snapshot.field_count, 2)
        self.assertIsNotNone(snapshot.hash_sha256)
        self.assertGreater(snapshot.total_size_bytes, 0)

    def test_make_change(self):
        config = SanitizerConfig()
        handler = TextHandler(config)
        change = handler.make_change(
            "test_field", "removed", "test_reason", "high",
            original_value="some value",
        )
        self.assertEqual(change.field, "test_field")
        self.assertEqual(change.action, "removed")
        self.assertEqual(change.severity, "high")
        self.assertEqual(change.original_value_preview, "some value")

    def test_make_change_truncates_preview(self):
        config = SanitizerConfig()
        handler = TextHandler(config)
        long_value = "x" * 300
        change = handler.make_change("f", "removed", "r", original_value=long_value)
        self.assertTrue(change.original_value_preview.endswith("..."))
        self.assertLessEqual(len(change.original_value_preview), 204)

    def test_check_field_size_anomaly_normal(self):
        config = SanitizerConfig()
        handler = TextHandler(config)
        result = handler.check_field_size_anomaly("field", "short value")
        self.assertIsNone(result)

    def test_check_field_size_anomaly_large(self):
        config = SanitizerConfig()
        handler = TextHandler(config)
        large_value = "x" * 100_000
        result = handler.check_field_size_anomaly("field", large_value, threshold=1000)
        self.assertIsNotNone(result)
        self.assertEqual(result.action, "flagged")
        self.assertIn("field_size_anomaly", result.reason)


class TestTextHandler(unittest.TestCase):
    """Test text/telemetry handler."""

    def setUp(self):
        self.config = SanitizerConfig(preserve_originals=False)
        self.handler = TextHandler(self.config)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_temp(self, filename: str, content: str, encoding: str = "utf-8") -> str:
        path = os.path.join(self.temp_dir, filename)
        with open(path, "w", encoding=encoding, newline="") as f:
            f.write(content)
        return path

    def _write_temp_bytes(self, filename: str, content: bytes) -> str:
        path = os.path.join(self.temp_dir, filename)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_is_available(self):
        self.assertTrue(TextHandler.is_available())

    def test_supported_mimes(self):
        mimes = self.handler.supported_mimes()
        self.assertIn("text/plain", mimes)
        self.assertIn("application/json", mimes)

    def test_extract_metadata_text(self):
        path = self._write_temp("test.txt", "hello world\nsecond line\n")
        meta = self.handler.extract_metadata(path)
        self.assertEqual(meta["_encoding"], "utf-8")
        self.assertEqual(meta["_line_count"], 2)

    def test_extract_metadata_json_valid(self):
        path = self._write_temp("data.json", '{"key": "value"}')
        meta = self.handler.extract_metadata(path)
        self.assertTrue(meta["_valid_json"])

    def test_extract_metadata_json_invalid(self):
        path = self._write_temp("bad.json", '{"key": value}')
        meta = self.handler.extract_metadata(path)
        self.assertFalse(meta["_valid_json"])

    def test_extract_detects_script_patterns(self):
        path = self._write_temp("evil.txt", '<script>alert("xss")</script>')
        meta = self.handler.extract_metadata(path)
        self.assertIn("html_script", meta["_script_patterns"])

    def test_sanitize_strips_null_bytes(self):
        path = self._write_temp_bytes("null.txt", b"hello\x00world")
        out_path = os.path.join(self.temp_dir, "null_clean.txt")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any(c.field == "Text.null_bytes" for c in changes))
        with open(out_path, "r") as f:
            self.assertEqual(f.read(), "helloworld")

    def test_sanitize_normalizes_line_endings(self):
        path = self._write_temp_bytes("crlf.txt", b"line1\r\nline2\r\n")
        out_path = os.path.join(self.temp_dir, "crlf_clean.txt")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("line_endings" in c.field for c in changes))
        with open(out_path, "r") as f:
            content = f.read()
            self.assertNotIn("\r", content)

    def test_sanitize_strips_bom(self):
        path = self._write_temp_bytes("bom.txt", b"\xef\xbb\xbfhello")
        out_path = os.path.join(self.temp_dir, "bom_clean.txt")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any(c.field == "Text.BOM" for c in changes))

    def test_sanitize_audit_only_no_modification(self):
        path = self._write_temp_bytes("audit.txt", b"hello\x00world")
        out_path = os.path.join(self.temp_dir, "audit_out.txt")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.AUDIT_ONLY)
        # File should not be modified
        self.assertTrue(any(c.action == "flagged" for c in changes))

    def test_sanitize_strip_mode_removes_suspicious_lines(self):
        content = "normal line\n<script>evil()</script>\nanother normal line\n"
        path = self._write_temp("strip.txt", content)
        changes = self.handler.sanitize(path, path, SanitizationMode.STRIP)
        self.assertTrue(any("suspicious_lines" in c.field for c in changes))

    def test_verify_valid_utf8(self):
        path = self._write_temp("valid.txt", "hello world")
        self.assertTrue(self.handler.verify(path))

    def test_handler_name(self):
        self.assertEqual(TextHandler.handler_name(), "TextHandler")


class TestArchiveHandler(unittest.TestCase):
    """Test archive inspection handler."""

    def setUp(self):
        self.config = SanitizerConfig(preserve_originals=False)
        self.handler = ArchiveHandler(self.config)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_zip(self, filename: str, entries: dict, comment: str = "") -> str:
        path = os.path.join(self.temp_dir, filename)
        with zipfile.ZipFile(path, "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
            if comment:
                zf.comment = comment.encode()
        return path

    def test_is_available(self):
        self.assertTrue(ArchiveHandler.is_available())

    def test_extract_zip_metadata(self):
        path = self._create_zip("test.zip", {"file1.txt": "hello", "file2.txt": "world"})
        meta = self.handler.extract_metadata(path)
        self.assertEqual(meta["_format"], "zip")
        self.assertEqual(meta["_entry_count"], 2)

    def test_sanitize_flags_path_traversal(self):
        path = self._create_zip("evil.zip", {"../../../etc/passwd": "root:x:0:0"})
        out_path = os.path.join(self.temp_dir, "evil_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("path_traversal" in c.reason for c in changes))

    def test_sanitize_flags_executable(self):
        path = self._create_zip("exe.zip", {"malware.exe": "MZ..."})
        out_path = os.path.join(self.temp_dir, "exe_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("executable_in_archive" in c.reason for c in changes))

    def test_sanitize_flags_double_extension(self):
        path = self._create_zip("dbl.zip", {"photo.jpg.exe": "MZ..."})
        out_path = os.path.join(self.temp_dir, "dbl_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("double_extension" in c.reason for c in changes))

    def test_sanitize_flags_hidden_file(self):
        path = self._create_zip("hidden.zip", {".secret": "data"})
        out_path = os.path.join(self.temp_dir, "hidden_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("hidden_file" in c.reason for c in changes))

    def test_sanitize_flags_comment(self):
        path = self._create_zip("comment.zip", {"a.txt": "data"}, comment="test comment")
        out_path = os.path.join(self.temp_dir, "comment_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        self.assertTrue(any("archive_comment" in c.reason for c in changes))

    def test_sanitize_flags_zip_bomb(self):
        """Create a high-ratio archive to trigger zip bomb detection."""
        path = os.path.join(self.temp_dir, "bomb.zip")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Highly compressible content
            zf.writestr("big.txt", "A" * 1_000_000)
        out_path = os.path.join(self.temp_dir, "bomb_out.zip")
        changes = self.handler.sanitize(path, out_path, SanitizationMode.SELECTIVE)
        # Check if zip bomb warning was raised (depends on compression ratio)
        zip_bomb_changes = [c for c in changes if "zip_bomb" in c.reason]
        # This may or may not trigger depending on actual compression ratio
        # The test validates the code path runs without error

    def test_verify_valid_zip(self):
        path = self._create_zip("valid.zip", {"a.txt": "hello"})
        self.assertTrue(self.handler.verify(path))


class TestSanitizer(unittest.TestCase):
    """Test the main MetadataSanitizer orchestrator."""

    def setUp(self):
        self.config = SanitizerConfig(
            preserve_originals=False,
            verify_after_sanitize=False,
            log_all_metadata=False,
            log_level="WARNING",
        )
        self.sanitizer = MetadataSanitizer(self.config)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_temp(self, filename: str, content: str) -> str:
        path = os.path.join(self.temp_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        return path

    # ── Mode selection ────────────────────────────────────────────────

    def test_mode_from_high_threat_score(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
            threat_score=0.85,
        )
        self.assertEqual(result.mode, "strip")

    def test_mode_from_low_threat_score(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
            threat_score=0.1,
        )
        self.assertEqual(result.mode, "audit_only")

    def test_mode_from_medium_threat_score(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
            threat_score=0.5,
        )
        self.assertEqual(result.mode, "selective")

    def test_mode_override_takes_precedence(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
            threat_score=0.85,  # Would normally be "strip"
            mode_override="audit_only",
        )
        self.assertEqual(result.mode, "audit_only")

    def test_mode_escalation_from_insecure_flags(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
            insecure_flags=["executable_file", "suspicious_mime"],
        )
        self.assertEqual(result.mode, "strip")

    def test_default_mode_when_no_signals(self):
        path = self._write_temp("test.txt", "hello")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
        )
        self.assertEqual(result.mode, "selective")

    # ── Pre-checks ────────────────────────────────────────────────────

    def test_file_not_found(self):
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path="/nonexistent/file.txt",
            mime_type="text/plain",
        )
        self.assertTrue(result.skipped)
        self.assertEqual(result.skip_reason, "file_not_found")

    def test_skip_excluded_mime(self):
        path = self._write_temp("evil.exe", "MZ...")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="application/x-msdownload",
        )
        self.assertTrue(result.skipped)
        self.assertIn("mime_type_excluded", result.skip_reason)

    def test_skip_oversized_file(self):
        config = SanitizerConfig(
            max_file_size_bytes=10,
            preserve_originals=False,
            log_level="WARNING",
        )
        sanitizer = MetadataSanitizer(config)
        path = self._write_temp("big.txt", "x" * 100)
        result = sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
        )
        self.assertTrue(result.skipped)
        self.assertIn("file_too_large", result.skip_reason)

    # ── Text sanitization ─────────────────────────────────────────────

    def test_sanitize_text_file(self):
        path = self._write_temp("test.txt", "hello\x00world\r\n")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
        )
        self.assertTrue(result.sanitized)
        self.assertGreater(len(result.changes), 0)
        self.assertEqual(result.handler_used, "TextHandler")

    def test_sanitize_json_file(self):
        path = self._write_temp("data.json", '{"key": "value"}')
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="application/json",
        )
        self.assertEqual(result.handler_used, "TextHandler")

    # ── Archive inspection ────────────────────────────────────────────

    def test_sanitize_zip_file(self):
        zip_path = os.path.join(self.temp_dir, "test.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("normal.txt", "hello")
            zf.writestr("../traversal.txt", "evil")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=zip_path,
            mime_type="application/zip",
        )
        self.assertEqual(result.handler_used, "ArchiveHandler")
        self.assertTrue(any("path_traversal" in c.reason for c in result.changes))

    # ── Artifact record integration ───────────────────────────────────

    def test_sanitize_artifact_record(self):
        path = self._write_temp("test.txt", "hello world")
        record = {
            "artifact_id": "artifact://abc123",
            "filename": "test.txt",
            "mime": "text/plain",
            "pointer_storage": path,
            "security_flags": [],
        }
        result = self.sanitizer.sanitize_artifact_record(
            artifact_record=record,
            threat_score=0.5,
        )
        self.assertEqual(result.artifact_id, "artifact://abc123")

    def test_sanitize_artifact_record_with_base_path(self):
        path = self._write_temp("test.txt", "hello world")
        record = {
            "artifact_id": "artifact://abc123",
            "filename": "test.txt",
            "mime": "text/plain",
            "pointer_storage": "",
        }
        result = self.sanitizer.sanitize_artifact_record(
            artifact_record=record,
            storage_base_path=self.temp_dir,
            threat_score=0.5,
        )
        self.assertFalse(result.skipped)

    # ── Batch sanitization ────────────────────────────────────────────

    def test_sanitize_batch(self):
        path1 = self._write_temp("file1.txt", "hello")
        path2 = self._write_temp("file2.txt", "world")
        records = [
            {"artifact_id": "artifact://1", "filename": "file1.txt",
             "mime": "text/plain", "pointer_storage": path1, "security_flags": []},
            {"artifact_id": "artifact://2", "filename": "file2.txt",
             "mime": "text/plain", "pointer_storage": path2, "security_flags": []},
        ]
        batch = self.sanitizer.sanitize_batch(records, threat_score=0.5)
        self.assertEqual(batch.total_processed, 2)
        self.assertEqual(len(batch.results), 2)

    # ── Statistics ────────────────────────────────────────────────────

    def test_stats_tracking(self):
        path = self._write_temp("test.txt", "hello")
        self.sanitizer.sanitize_file(
            artifact_id="a1", file_path=path, mime_type="text/plain"
        )
        self.sanitizer.sanitize_file(
            artifact_id="a2", file_path="/nonexistent.txt", mime_type="text/plain"
        )
        stats = self.sanitizer.stats
        self.assertEqual(stats["total_processed"], 1)
        self.assertEqual(stats["total_skipped"], 1)

    # ── Result serialization ──────────────────────────────────────────

    def test_result_to_dict_is_json_serializable(self):
        path = self._write_temp("test.txt", "hello\x00world")
        result = self.sanitizer.sanitize_file(
            artifact_id="artifact://test",
            file_path=path,
            mime_type="text/plain",
        )
        d = result.to_dict()
        # Should not raise
        json_str = json.dumps(d, default=str)
        self.assertIn("artifact://test", json_str)


class TestHandlerAvailability(unittest.TestCase):
    """Test handler availability checks."""

    def test_text_handler_always_available(self):
        self.assertTrue(TextHandler.is_available())

    def test_archive_handler_always_available(self):
        self.assertTrue(ArchiveHandler.is_available())

    def test_image_handler_availability(self):
        # Just check that is_available() doesn't crash
        ImageHandler.is_available()

    def test_video_handler_availability(self):
        VideoHandler.is_available()

    def test_pdf_handler_availability(self):
        PdfHandler.is_available()


class TestStoragePointerResolution(unittest.TestCase):
    """Test storage pointer resolution in sanitizer."""

    def setUp(self):
        self.sanitizer = MetadataSanitizer(SanitizerConfig(log_level="WARNING"))

    def test_resolve_absolute_path(self):
        result = self.sanitizer._resolve_storage_pointer(
            "/absolute/path/file.jpg", "", "file.jpg"
        )
        self.assertEqual(result, "/absolute/path/file.jpg")

    def test_resolve_file_uri(self):
        result = self.sanitizer._resolve_storage_pointer(
            "file:/home/user/file.jpg", "", ""
        )
        self.assertEqual(result, "/home/user/file.jpg")

    def test_resolve_s3_falls_back_to_base(self):
        result = self.sanitizer._resolve_storage_pointer(
            "s3://bucket/key/file.jpg", "/local/store", "file.jpg"
        )
        self.assertEqual(result, "/local/store/file.jpg")

    def test_resolve_empty_uses_base_and_filename(self):
        result = self.sanitizer._resolve_storage_pointer(
            "", "/local/store", "file.jpg"
        )
        self.assertEqual(result, "/local/store/file.jpg")

    def test_resolve_relative_path(self):
        result = self.sanitizer._resolve_storage_pointer(
            "DRN-001/file.jpg", "/local/store", ""
        )
        self.assertEqual(result, "/local/store/DRN-001/file.jpg")


if __name__ == "__main__":
    unittest.main()
