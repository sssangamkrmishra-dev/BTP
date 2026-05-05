"""
Tests for the Sandbox Analyzer.

Run with:
    python -m unittest sandbox_analyzer.tests.test_analyzer -v
or:
    python -m pytest sandbox_analyzer/tests/ -v
"""

import json
import os
import platform
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sandbox_analyzer import (
    ArchiveResult,
    FeedbackSink,
    FileCategory,
    IOCResult,
    LocalThreatIntelClient,
    LoggingFeedbackSink,
    MonitorEvent,
    MonitorName,
    RoutingDecision,
    SandboxAnalyzer,
    SandboxConfig,
    SandboxReport,
    ScoreBreakdown,
    ThreatIntelClient,
    Verdict,
    action_for,
    build_sink,
    check_double_extension,
    compute_file_hash,
    compute_risk_score,
    correlate_iocs,
    determine_verdict,
    extract_network_iocs,
    handle_archive,
    is_encrypted_zip,
    route_file,
)

IS_LINUX = platform.system() == "Linux"


# ── 1. Config ───────────────────────────────────────────────────────

class TestSandboxConfig(unittest.TestCase):

    def test_defaults(self):
        cfg = SandboxConfig()
        self.assertEqual(cfg.memory_bytes, 128 * 1024 * 1024)
        self.assertEqual(cfg.cpu_seconds, 20)
        self.assertEqual(cfg.wall_timeout_seconds, 30)
        self.assertEqual(cfg.suspicious_threshold, 25)
        self.assertEqual(cfg.malicious_threshold, 60)
        self.assertTrue(cfg.skip_safe_files)
        self.assertIn("bash", cfg.shell_processes)
        self.assertIn("/tmp", cfg.suspicious_paths)
        self.assertIn("file_write_executable", cfg.behavior_weights)

    def test_override(self):
        cfg = SandboxConfig(
            memory_bytes=64 * 1024 * 1024,
            suspicious_threshold=15,
            malicious_threshold=50,
        )
        self.assertEqual(cfg.memory_bytes, 64 * 1024 * 1024)
        self.assertEqual(cfg.suspicious_threshold, 15)
        self.assertEqual(cfg.malicious_threshold, 50)

    def test_rejects_inverted_thresholds(self):
        with self.assertRaises(ValueError):
            SandboxConfig(suspicious_threshold=60, malicious_threshold=40)

    def test_rejects_zero_limits(self):
        for kw in ("memory_bytes", "cpu_seconds", "file_bytes",
                   "max_processes", "wall_timeout_seconds"):
            with self.assertRaises(ValueError):
                SandboxConfig(**{kw: 0})

    def test_rejects_bad_zip_ratio(self):
        with self.assertRaises(ValueError):
            SandboxConfig(zip_bomb_ratio=0)
        with self.assertRaises(ValueError):
            SandboxConfig(zip_bomb_ratio=1.5)

    def test_rejects_bad_poll_interval(self):
        with self.assertRaises(ValueError):
            SandboxConfig(poll_interval_seconds=0)

    def test_rejects_negative_weight(self):
        with self.assertRaises(ValueError):
            SandboxConfig(behavior_weights={"x": -1})


# ── 2. File Router ─────────────────────────────────────────────────

class TestFileRouter(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="router_t_")

    def _write(self, name, body_bytes):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(body_bytes)
        return path

    def test_magic_bytes_override_extension(self):
        # A file named .jpg but starting with #! is a SCRIPT.
        p = self._write("photo.jpg", b"#!/bin/bash\necho hi\n")
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.SCRIPT)
        self.assertTrue(r.magic_match)

    def test_csv_is_safe_and_skipped(self):
        p = self._write("telemetry.csv", b"a,b\n1,2\n")
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.SAFE)
        self.assertTrue(r.should_skip)

    def test_windows_pe_flagged(self):
        p = self._write("payload.exe", b"MZ" + b"\x00" * 20)
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.WINDOWS)
        self.assertTrue(r.magic_match)

    def test_zip_detected_from_magic(self):
        p = os.path.join(self.dir, "pkg.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("a.txt", "x")
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.ARCHIVE)
        self.assertTrue(r.magic_match)

    def test_python_interpreter_selected(self):
        p = self._write("script.py", b"print(1)\n")   # no shebang → falls to extension
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.SCRIPT)
        self.assertEqual(r.interpreter, "python3")

    def test_unknown_type(self):
        p = self._write("blob.xyz", b"\x00\x01\x02")
        r = route_file(p)
        self.assertEqual(r.category, FileCategory.UNKNOWN)
        self.assertFalse(r.magic_match)


# ── 3. Archive handler ─────────────────────────────────────────────

class TestArchiveHandler(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="archive_t_")
        self.cfg = SandboxConfig()

    def test_plain_archive_extracts(self):
        p = os.path.join(self.dir, "plain.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("telemetry.csv", "lat,lon\n28,77")
            zf.writestr("config.json", "{}")
        r = handle_archive(p, os.path.join(self.dir, "out"), self.cfg)
        self.assertTrue(r.success)
        self.assertFalse(r.was_encrypted)
        self.assertEqual(r.extra_risk_score, 0)
        self.assertEqual(len(r.extracted_files), 2)

    def test_encrypted_no_key_flagged(self):
        # Python's stdlib zipfile cannot write a real encrypted archive
        # (setpassword + writestr does NOT set the encryption flag). We
        # test the handler's *behaviour* when encryption is detected by
        # patching the detection helper — a real deployment uses real
        # encrypted ZIPs so the flag-bit check fires naturally.
        p = os.path.join(self.dir, "enc.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("payload.py", b"print(1)")
        with patch("sandbox_analyzer.archive_handler.is_encrypted_zip", return_value=True):
            r = handle_archive(p, os.path.join(self.dir, "enc_out"), self.cfg)
        self.assertTrue(r.was_encrypted)
        self.assertEqual(r.decryption_source, "")
        self.assertEqual(r.extra_risk_score, self.cfg.encrypted_no_key_score)
        self.assertFalse(r.success)
        self.assertIn("Encrypted", r.error or "")

    def test_encrypted_with_metadata_key_proceeds(self):
        p = os.path.join(self.dir, "enc2.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("payload.py", b"print(1)")
        # Provided password + simulated encryption flag → decryption_source set.
        with patch("sandbox_analyzer.archive_handler.is_encrypted_zip", return_value=True):
            r = handle_archive(
                p, os.path.join(self.dir, "enc2_out"), self.cfg,
                provided_password="sekret",
            )
        self.assertTrue(r.was_encrypted)
        self.assertEqual(r.decryption_source, "metadata_key")
        # No "encrypted-no-key" bonus because a key was declared.
        self.assertEqual(r.extra_risk_score, 0)

    def test_double_extension_flagged(self):
        p = os.path.join(self.dir, "tricky.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("recon.jpg.sh", "#!/bin/sh\nid")
            zf.writestr("normal.jpg", b"\xff\xd8\xff" + b"\x00" * 5)
        r = handle_archive(p, os.path.join(self.dir, "tricky_out"), self.cfg)
        self.assertIn("recon.jpg.sh", r.double_extensions)
        self.assertEqual(r.extra_risk_score, self.cfg.double_extension_score)

    def test_check_double_extension_true(self):
        self.assertTrue(check_double_extension("recon.jpg.sh"))
        self.assertTrue(check_double_extension("doc.pdf.exe"))

    def test_check_double_extension_false(self):
        self.assertFalse(check_double_extension("normal.jpg"))
        self.assertFalse(check_double_extension("archive.tar.gz"))

    def test_depth_limit_respected(self):
        p = os.path.join(self.dir, "outer.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("a.txt", "x")
        cfg = SandboxConfig(max_extract_depth=0)
        # Direct extraction is depth 0; recursion beyond should be blocked.
        r = handle_archive(p, os.path.join(self.dir, "d0"), cfg, depth=0)
        self.assertTrue(r.success)
        # At depth 1 (beyond limit 0) the handler returns with error
        r2 = handle_archive(p, os.path.join(self.dir, "d1"), cfg, depth=1)
        self.assertIn("Max extraction depth", r2.error or "")


# ── 4. Scoring & verdict ──────────────────────────────────────────

class TestScoringAndVerdict(unittest.TestCase):

    def setUp(self):
        self.cfg = SandboxConfig()

    def _sim(self, categories):
        return [MonitorEvent(0.0, "Simulated", cat, "detail")
                for cat in categories]

    def test_empty_events_zero_score(self):
        sb = compute_risk_score([], self.cfg)
        self.assertEqual(sb.total_score, 0)
        self.assertEqual(sb.top_factors, [])

    def test_clean_single_fs_write(self):
        sb = compute_risk_score(self._sim(["file_system_write"]), self.cfg)
        self.assertEqual(sb.total_score, 5)
        self.assertEqual(determine_verdict(sb.total_score, self.cfg), Verdict.CLEAN)

    def test_suspicious_band(self):
        sb = compute_risk_score(
            self._sim(["process_spawn", "network_connect", "shell_command"]),
            self.cfg,
        )
        # 10 + 25 + 25 = 60 → right at malicious boundary
        self.assertEqual(sb.total_score, 60)
        self.assertEqual(determine_verdict(sb.total_score, self.cfg), Verdict.MALICIOUS)

    def test_malicious_band(self):
        sb = compute_risk_score(
            self._sim([
                "network_connect", "shell_command", "file_write_executable",
                "privilege_escalation", "self_replication", "memory_inject",
            ]),
            self.cfg,
        )
        self.assertGreaterEqual(sb.total_score, self.cfg.malicious_threshold)
        self.assertEqual(determine_verdict(sb.total_score, self.cfg), Verdict.MALICIOUS)

    def test_unknown_categories_contribute_zero(self):
        sb = compute_risk_score(self._sim(["bogus_category"]), self.cfg)
        self.assertEqual(sb.total_score, 0)

    def test_top_factors_ordered(self):
        sb = compute_risk_score(
            self._sim(["file_system_write"] * 3 + ["network_connect"] * 2),
            self.cfg,
        )
        # network_connect contributes 50 vs file_system_write 15 → network first
        self.assertIn("network_connect", sb.top_factors[0])


# ── 5. IOC correlation ─────────────────────────────────────────────

class TestIOC(unittest.TestCase):

    def setUp(self):
        self.cfg = SandboxConfig()

    def test_local_client_hash_match(self):
        known = "a" * 64
        tic = LocalThreatIntelClient(hashes={known})
        resp = tic.query(known, set(), set())
        self.assertEqual(resp["matched_hashes"], [known])
        self.assertTrue(resp["any_match"])

    def test_local_client_ip_match(self):
        tic = LocalThreatIntelClient(ips={"203.0.113.42"})
        resp = tic.query("", {"203.0.113.42"}, set())
        self.assertIn("203.0.113.42", resp["matched_ips"])
        self.assertTrue(resp["any_match"])

    def test_extract_network_iocs_from_events(self):
        ev = MonitorEvent(0.0, MonitorName.NETWORK.value, "network_connect",
                          "Outbound connection: 127.0.0.1:80 → 198.51.100.9:4444",
                          {"remote": "198.51.100.9"})
        iocs = extract_network_iocs([ev])
        self.assertIn("198.51.100.9", iocs["ips"])
        self.assertNotIn("0.0.0.0", iocs["ips"])
        # Loopback is discarded.
        self.assertNotIn("127.0.0.1", iocs["ips"])

    def test_domain_regex_does_not_match_filenames(self):
        # A filename like "photo.jpg" must not be treated as a domain;
        # only multi-label FQDNs with a real TLD should match.
        ev_noise = MonitorEvent(0.0, MonitorName.NETWORK.value, "network_connect",
                                 "Reading photo.jpg from disk", {})
        ev_real = MonitorEvent(0.0, MonitorName.NETWORK.value, "network_connect",
                                "Resolved evil-c2.example.com", {})
        iocs = extract_network_iocs([ev_noise, ev_real])
        self.assertNotIn("photo.jpg", iocs["domains"])
        self.assertIn("evil-c2.example.com", iocs["domains"])

    def test_correlate_applies_bonus(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        open(p, "wb").write(b"data")
        tic = LocalThreatIntelClient(ips={"198.51.100.9"})
        events = [MonitorEvent(0.0, MonitorName.NETWORK.value, "network_connect",
                                "→ 198.51.100.9:4444", {"remote": "198.51.100.9"})]
        r = correlate_iocs(p, events, self.cfg, tic)
        self.assertTrue(r.any_match)
        self.assertEqual(r.bonus_score, self.cfg.ioc_match_bonus)

    def test_correlate_disabled(self):
        cfg = SandboxConfig(enable_ioc_correlation=False)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        open(p, "wb").write(b"")
        r = correlate_iocs(p, [], cfg)
        self.assertFalse(r.any_match)
        self.assertEqual(r.source, "disabled")

    def test_correlate_swallows_client_errors(self):
        class Broken(ThreatIntelClient):
            source = "broken"
            def query(self, *a, **k):
                raise RuntimeError("backend down")
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        open(p, "wb").write(b"")
        r = correlate_iocs(p, [], self.cfg, Broken())
        self.assertFalse(r.any_match)
        self.assertEqual(r.source, "broken")


# ── 6. Feedback sinks ──────────────────────────────────────────────

class TestFeedbackSinks(unittest.TestCase):

    def test_base_sink_is_noop(self):
        sink = FeedbackSink()
        # Should not raise.
        sink.notify_response_manager(self._make_report())
        sink.notify_dashboard(self._make_report())
        sink.queue_for_ml(self._make_report())

    def test_logging_sink_does_not_raise(self):
        sink = LoggingFeedbackSink()
        sink.notify_response_manager(self._make_report())
        sink.notify_dashboard(self._make_report())
        sink.queue_for_ml(self._make_report())

    def test_build_sink_uses_injected_callables(self):
        calls = []
        s = build_sink(
            response_manager=lambda r: calls.append(("resp", r.report_id)),
            dashboard=lambda r: calls.append(("dash", r.report_id)),
            ml_queue=lambda r: calls.append(("ml", r.report_id)),
        )
        rep = self._make_report()
        s.notify_response_manager(rep)
        s.notify_dashboard(rep)
        s.queue_for_ml(rep)
        self.assertEqual([c[0] for c in calls], ["resp", "dash", "ml"])

    @staticmethod
    def _make_report():
        return SandboxReport(
            report_id="sbx_test",
            file_path="/tmp/x",
            file_hash="",
            drone_id="DRN-X",
            verdict=Verdict.CLEAN,
            action="forward",
        )


# ── 7. End-to-end (static stages, no execution) ───────────────────

class TestAnalyzerStatic(unittest.TestCase):
    """Tests that do NOT require Linux execution — verify routing/archive/skip paths."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sbx_static_")
        self.sa = SandboxAnalyzer()

    def test_clean_csv_returns_clean_and_skipped(self):
        p = os.path.join(self.dir, "t.csv")
        open(p, "w").write("a,b\n1,2")
        rep = self.sa.analyze(p, drone_id="DRN-001")
        self.assertEqual(rep.verdict, Verdict.CLEAN)
        self.assertTrue(rep.skipped)
        self.assertEqual(rep.risk_score, 0)
        self.assertEqual(rep.file_category, FileCategory.SAFE.value)

    def test_windows_exe_flagged_suspicious_not_forwarded(self):
        # Production semantics: a Windows PE that reaches the sandbox
        # has already scored HIGH upstream. We cannot execute it here,
        # but the action MUST NOT be "forward to operational network" —
        # it should be quarantined for analyst review.
        p = os.path.join(self.dir, "mal.exe")
        with open(p, "wb") as f:
            f.write(b"MZ" + b"\x00" * 20)
        rep = self.sa.analyze(p, drone_id="DRN-002")
        self.assertTrue(rep.skipped)
        self.assertIn("Windows", rep.skip_reason or "")
        self.assertEqual(rep.verdict, Verdict.SUSPICIOUS)
        self.assertIn("Quarantine", rep.action)

    def test_archive_double_extension_contributes_risk(self):
        # Plain (unencrypted) archive with a double-extension member.
        # The static handler must add double_extension_score even
        # without execution.
        p = os.path.join(self.dir, "tricky.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("recon.jpg.sh", b"#!/bin/sh\nid")
            zf.writestr("normal.csv", b"a,b\n1,2")
        rep = self.sa.analyze(p, drone_id="DRN-003")
        self.assertIsNotNone(rep.archive_result)
        self.assertIn("recon.jpg.sh", rep.archive_result.double_extensions)
        self.assertGreaterEqual(rep.risk_score, SandboxConfig().double_extension_score)

    def test_to_dict_is_json_serializable(self):
        p = os.path.join(self.dir, "t.csv")
        open(p, "w").write("a,b\n1,2")
        rep = self.sa.analyze(p, drone_id="DRN-004")
        payload = rep.to_dict(include_events=True)
        json.dumps(payload)   # must not raise

    def test_feedback_hooks_invoked(self):
        calls = {"resp": 0, "dash": 0, "ml": 0}

        class CountingSink(FeedbackSink):
            def notify_response_manager(self, r):
                calls["resp"] += 1
            def notify_dashboard(self, r):
                calls["dash"] += 1
            def queue_for_ml(self, r):
                calls["ml"] += 1

        sa = SandboxAnalyzer(feedback_sink=CountingSink())
        p = os.path.join(self.dir, "t.csv")
        open(p, "w").write("a,b\n1,2")
        sa.analyze(p, drone_id="DRN-005")
        self.assertEqual(calls, {"resp": 1, "dash": 1, "ml": 1})

    def test_feedback_exception_isolated(self):
        class Broken(FeedbackSink):
            def notify_dashboard(self, r):
                raise RuntimeError("boom")

        sa = SandboxAnalyzer(feedback_sink=Broken())
        p = os.path.join(self.dir, "t.csv")
        open(p, "w").write("a,b\n1,2")
        # Must not propagate.
        rep = sa.analyze(p, drone_id="DRN-006")
        self.assertEqual(rep.verdict, Verdict.CLEAN)

    def test_stats_track_counts(self):
        sa = SandboxAnalyzer()
        p = os.path.join(self.dir, "t.csv")
        open(p, "w").write("a,b\n1,2")
        sa.analyze(p, drone_id="DRN-007")
        sa.analyze(p, drone_id="DRN-008")
        s = sa.stats
        self.assertEqual(s["total_analyzed"], 2)
        self.assertEqual(s["total_skipped"], 2)
        self.assertEqual(s["total_clean"], 2)

    def test_windows_pe_bumps_suspicious_counter(self):
        sa = SandboxAnalyzer()
        p = os.path.join(self.dir, "payload.exe")
        with open(p, "wb") as f:
            f.write(b"MZ" + b"\x00" * 20)
        sa.analyze(p, drone_id="DRN-W")
        s = sa.stats
        self.assertEqual(s["total_skipped"], 1)
        self.assertEqual(s["total_suspicious"], 1)
        self.assertEqual(s["total_clean"], 0)


# ── 8. End-to-end execution (Linux-only integration) ──────────────

@unittest.skipUnless(IS_LINUX, "sandbox execution requires Linux /proc + setrlimit")
class TestAnalyzerLive(unittest.TestCase):
    """Real-execution integration tests. Skipped on non-Linux CI."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sbx_live_")
        self.sa = SandboxAnalyzer()

    def test_benign_script_returns_clean_or_low(self):
        p = os.path.join(self.dir, "hello.py")
        open(p, "w").write('print("ok")')
        rep = self.sa.analyze(p, drone_id="DRN-L01")
        self.assertIn(rep.verdict, (Verdict.CLEAN, Verdict.SUSPICIOUS))
        self.assertLess(rep.risk_score, 60)
        self.assertTrue(len(rep.execution_results) >= 1)


# ── 9. Miscellaneous helpers ──────────────────────────────────────

class TestHelpers(unittest.TestCase):

    def test_compute_file_hash_stable(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.bin")
        open(p, "wb").write(b"hello world")
        h = compute_file_hash(p)
        self.assertEqual(len(h), 64)
        self.assertEqual(h, compute_file_hash(p))

    def test_compute_file_hash_missing_file(self):
        self.assertEqual(compute_file_hash("/tmp/does-not-exist-12345"), "")

    def test_is_encrypted_zip_false_on_plain(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "p.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("a", b"b")
        self.assertFalse(is_encrypted_zip(p))

    def test_is_encrypted_zip_true_on_encryption_flag(self):
        # The stdlib can't produce a real encrypted ZIP. We write one with
        # the encryption flag bit set by editing the raw central-directory
        # byte, then confirm is_encrypted_zip picks it up.
        d = tempfile.mkdtemp()
        p = os.path.join(d, "p.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("a", b"body")
        # Flip the encryption flag in both the local file header and the
        # central directory. Local header: offset 6; central directory
        # header: offset 8 from the start of the central dir entry.
        with open(p, "r+b") as fh:
            raw = fh.read()
        # Local header signature PK\x03\x04 — flags at offset +6 (2 bytes, little-endian).
        idx = raw.find(b"PK\x03\x04")
        self.assertGreaterEqual(idx, 0)
        flags_off = idx + 6
        patched = (
            raw[:flags_off]
            + bytes([raw[flags_off] | 0x01]) + raw[flags_off + 1:]
        )
        # Central directory signature PK\x01\x02 — flags at offset +8.
        cd_idx = patched.find(b"PK\x01\x02")
        self.assertGreaterEqual(cd_idx, 0)
        cd_flags_off = cd_idx + 8
        patched = (
            patched[:cd_flags_off]
            + bytes([patched[cd_flags_off] | 0x01]) + patched[cd_flags_off + 1:]
        )
        with open(p, "wb") as fh:
            fh.write(patched)
        self.assertTrue(is_encrypted_zip(p))

    def test_action_for(self):
        self.assertIn("Forward", action_for(Verdict.CLEAN))
        self.assertIn("Quarantine", action_for(Verdict.SUSPICIOUS))
        self.assertIn("Block", action_for(Verdict.MALICIOUS))


if __name__ == "__main__":
    unittest.main()
