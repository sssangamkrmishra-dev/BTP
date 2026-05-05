"""
Main Sandbox Analyzer orchestrator.

Chains the eight stages (router → archive → execution + monitors →
scoring → IOC → verdict → feedback) into a single `analyze()` call.
Consumed by the Inspection Strategy Selector inside the Multi-Layer
Malware Detection Engine when the Threat Score is HIGH.
"""

import logging
import os
import platform
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from .archive_handler import handle_archive
from .config import SandboxConfig
from .execution import SANDBOX_EXECUTION_AVAILABLE, execute_file
from .feedback import FeedbackSink, LoggingFeedbackSink
from .ioc import (
    LocalThreatIntelClient,
    ThreatIntelClient,
    compute_file_hash,
    correlate_iocs,
)
from .models import (
    ArchiveResult,
    ExecutionResult,
    FileCategory,
    MonitorEvent,
    MonitorName,
    RoutingDecision,
    SandboxReport,
    ScoreBreakdown,
    Verdict,
    new_report_id,
)
from .monitors import EventLog, build_monitors
from .router import route_file
from .scoring import compute_risk_score
from .verdict import action_for, determine_verdict

logger = logging.getLogger(__name__)


class SandboxAnalyzer:
    """
    Orchestrator for the Sandbox Analyzer pipeline.

    Pipeline position:
        Ingestion Interceptor → Game-Theoretic Threat Estimator
            → Inspection Strategy Selector → **Sandbox Analyzer**
            → Response & Quarantine Manager → Security Dashboard

    Integration seams (all injected via the constructor, all have
    reference implementations that are safe to run in isolation):

      threat_intel_client : queried by Stage 6 (IOC correlation)
      feedback_sink       : receives verdict / dashboard / ML callbacks after Stage 7

    Thread-safety:
      A single `SandboxAnalyzer` instance is intended to be invoked from
      one request-handling thread at a time. The injected
      `ThreatIntelClient` and `FeedbackSink` implementations must be
      thread-safe if the host shares them across multiple analyzers.

    Platform:
      Stages 3 and 4 require Linux and the POSIX `resource` module. On
      other platforms, `analyze()` returns a report with the routing
      decision, static archive findings, and an explicit warning — no
      execution takes place.
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        threat_intel_client: Optional[ThreatIntelClient] = None,
        feedback_sink: Optional[FeedbackSink] = None,
    ):
        self.config = config or SandboxConfig()
        self._setup_logging()

        self.threat_intel_client = threat_intel_client or LocalThreatIntelClient()
        self.feedback_sink = feedback_sink or LoggingFeedbackSink()

        self._stats = {
            "total_analyzed":       0,
            "total_clean":          0,
            "total_suspicious":     0,
            "total_malicious":      0,
            "total_skipped":        0,
            "total_archive_runs":   0,
            "total_execution_runs": 0,
            "total_errors":         0,
            "last_report_id":       None,
        }

    def _setup_logging(self) -> None:
        pkg_logger = logging.getLogger("sandbox_analyzer")
        level = getattr(logging, self.config.log_level, logging.INFO)
        pkg_logger.setLevel(level)

    # ── Public API ────────────────────────────────────────────────

    def analyze(
        self,
        file_path: str,
        drone_id: str = "UNKNOWN",
        artifact_id: Optional[str] = None,
        archive_password: Optional[str] = None,
        threat_score: Optional[float] = None,
    ) -> SandboxReport:
        """
        Run all eight stages on one artifact.

        Args:
            file_path: Absolute path to the artifact on disk.
            drone_id: Originating drone ID (propagated into the report
                and downstream callbacks).
            artifact_id: Optional `artifact://…` ID from the Ingestion
                Interceptor; carried through for cross-module correlation.
            archive_password: Key from feed metadata for encrypted
                archives. `None` means "not declared" — encrypted
                archives without a key are flagged as suspicious.
            threat_score: Optional Threat Score from the Game-Theoretic
                Threat Estimator; recorded in the report for audit but
                does not short-circuit any stage.

        Returns:
            SandboxReport with the full audit trail (routing, archive
            findings, per-file execution results, monitor events, score
            breakdown, IOC result, verdict, action).
        """
        start = time.time()
        warnings: List[str] = []
        errors: List[str] = []

        report = SandboxReport(
            report_id=new_report_id(),
            file_path=file_path,
            file_hash="",
            drone_id=drone_id,
            artifact_id=artifact_id,
        )
        self._stats["total_analyzed"] += 1
        self._stats["last_report_id"] = report.report_id

        # Stage 1 — routing.
        routing: RoutingDecision = route_file(
            file_path,
            skip_safe_files=self.config.skip_safe_files,
        )
        report.routing = routing
        report.file_category = routing.category.value
        logger.info(
            "sandbox: drone=%s file=%s category=%s magic=%s",
            drone_id, os.path.basename(file_path),
            routing.category.value, routing.magic_match,
        )

        report.file_hash = compute_file_hash(file_path)

        if routing.should_skip:
            self._finalise_skipped(
                report=report,
                routing=routing,
                reason="SAFE file type — skipping deep analysis",
                start=start,
                increment_counter="total_skipped",
            )
            return report

        if (
            self.config.flag_windows_executables
            and routing.category == FileCategory.WINDOWS
        ):
            # A Windows PE that reaches the sandbox has already scored HIGH
            # upstream. We cannot execute it here, but that is not evidence
            # of safety — mark SUSPICIOUS so the Response & Quarantine
            # Manager routes it to analyst review, not to the operational
            # network.
            self._finalise_skipped(
                report=report,
                routing=routing,
                reason="Windows executable — flagged for manual review (not executed on Linux)",
                start=start,
                increment_counter="total_skipped",
                verdict=Verdict.SUSPICIOUS,
            )
            return report

        # Stage 2 — archive handling (if applicable).
        files_to_analyze: List[str] = [file_path]
        archive_extra_score = 0
        if routing.category == FileCategory.ARCHIVE:
            arc_out = tempfile.mkdtemp(prefix="sandbox_arc_")
            arc_result: ArchiveResult = handle_archive(
                file_path, arc_out, self.config, provided_password=archive_password
            )
            report.archive_result = arc_result
            archive_extra_score = arc_result.extra_risk_score
            self._stats["total_archive_runs"] += 1

            # Materialise the archive's suspicious findings as
            # MonitorEvents so they participate in scoring uniformly.
            for flag_text in arc_result.suspicious_flags:
                category = (
                    "file_write_executable"
                    if "extension" in flag_text.lower()
                    else "high_entropy_write"
                )
                report.events.append(MonitorEvent(
                    timestamp=time.time(),
                    monitor=MonitorName.ARCHIVE.value,
                    category=category,
                    detail=flag_text,
                ))
            if arc_result.error:
                errors.append(f"archive: {arc_result.error}")
            if arc_result.success:
                files_to_analyze = list(arc_result.extracted_files) or [file_path]

        # Stages 3 & 4 — execute each extracted file and monitor.
        if SANDBOX_EXECUTION_AVAILABLE:
            for fpath in files_to_analyze:
                exec_result = self._execute_and_monitor(fpath, report.events, errors)
                if exec_result is not None:
                    report.execution_results.append(exec_result)
        else:
            warnings.append(
                f"execution/monitoring skipped: sandbox requires Linux + POSIX resource "
                f"(host is {platform.system()}); static stages still ran"
            )

        # Stage 5 — scoring.
        behaviour_score = compute_risk_score(report.events, self.config)
        report.score_breakdown = behaviour_score

        # Stage 6 — IOC correlation.
        ioc_result = correlate_iocs(
            file_path, report.events, self.config, self.threat_intel_client
        )
        report.ioc_result = ioc_result

        total_score = (
            behaviour_score.total_score
            + archive_extra_score
            + (ioc_result.bonus_score if ioc_result else 0)
        )
        report.risk_score = total_score

        # Stage 7 — verdict.
        verdict = determine_verdict(total_score, self.config)
        report.verdict = verdict
        report.action = action_for(verdict)
        self._bump_verdict_counter(verdict)

        # Finalise.
        report.warnings = warnings
        report.errors = errors
        report.duration_sec = time.time() - start
        report.config_snapshot = self._config_snapshot()

        # Stage 8 — feedback (hooks).
        if self.config.enable_feedback_hooks:
            self._dispatch_feedback(report)

        return report

    # ── Introspection ────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, Any]:
        return {**self._stats}

    # ── Internals ────────────────────────────────────────────────

    def _execute_and_monitor(
        self,
        fpath: str,
        event_sink: List[MonitorEvent],
        errors: List[str],
    ) -> Optional[ExecutionResult]:
        """Execute one file and run monitors on it in the same thread."""
        # Re-route per-file (extracted files may have different types).
        fr = route_file(fpath, skip_safe_files=self.config.skip_safe_files)
        if fr.should_skip or fr.category == FileCategory.WINDOWS:
            return None
        # Only SCRIPT / EXECUTABLE get executed. Images / docs / unknown
        # are already represented in the archive / router events — we do
        # not attempt to execute them.
        if fr.category not in (FileCategory.SCRIPT, FileCategory.EXECUTABLE):
            return None

        log = EventLog()
        monitors_ref = {"list": None, "log": log}
        poll_stop = threading.Event()

        def _on_pid(pid: int) -> None:
            monitors_ref["list"] = build_monitors(pid, log, self.config)

        def _poller() -> None:
            while not poll_stop.is_set():
                mon_list = monitors_ref["list"]
                if mon_list:
                    for m in mon_list:
                        try:
                            m.poll()
                        except Exception:
                            logger.exception("monitor poll raised")
                time.sleep(self.config.poll_interval_seconds)

        poll_thread = threading.Thread(target=_poller, daemon=True)
        poll_thread.start()

        try:
            self._stats["total_execution_runs"] += 1
            exec_result = execute_file(
                fpath,
                self.config,
                interpreter=fr.interpreter,
                on_pid=_on_pid,
            )
        except RuntimeError as exc:
            errors.append(f"execution: {exc}")
            self._stats["total_errors"] += 1
            return None
        finally:
            poll_stop.set()
            poll_thread.join(timeout=1.0)

        # Final sweep to catch late events before cleanup.
        mon_list = monitors_ref["list"] or []
        for m in mon_list:
            try:
                m.poll()
            except Exception:
                logger.exception("final monitor poll raised")

        event_sink.extend(log.all_events())
        return exec_result

    def _finalise_skipped(
        self,
        report: SandboxReport,
        routing: RoutingDecision,
        reason: str,
        start: float,
        increment_counter: str,
        verdict: Verdict = Verdict.CLEAN,
    ) -> None:
        report.skipped = True
        report.skip_reason = reason
        report.score_breakdown = ScoreBreakdown(0, {}, {}, [])
        report.risk_score = 0
        report.verdict = verdict
        report.action = action_for(verdict)
        report.duration_sec = time.time() - start
        report.config_snapshot = self._config_snapshot()
        self._stats[increment_counter] += 1
        self._bump_verdict_counter(verdict)
        if self.config.enable_feedback_hooks:
            self._dispatch_feedback(report)

    def _dispatch_feedback(self, report: SandboxReport) -> None:
        """Call every feedback channel, isolating exceptions per-channel."""
        for method_name in ("notify_response_manager",
                            "notify_dashboard",
                            "queue_for_ml"):
            try:
                getattr(self.feedback_sink, method_name)(report)
            except Exception:
                logger.exception("feedback channel %s raised", method_name)

    def _bump_verdict_counter(self, verdict: Verdict) -> None:
        if verdict == Verdict.MALICIOUS:
            self._stats["total_malicious"] += 1
        elif verdict == Verdict.SUSPICIOUS:
            self._stats["total_suspicious"] += 1
        else:
            self._stats["total_clean"] += 1

    def _config_snapshot(self) -> Dict[str, Any]:
        c = self.config
        return {
            "memory_bytes": c.memory_bytes,
            "cpu_seconds": c.cpu_seconds,
            "wall_timeout_seconds": c.wall_timeout_seconds,
            "max_processes": c.max_processes,
            "suspicious_threshold": c.suspicious_threshold,
            "malicious_threshold": c.malicious_threshold,
            "poll_interval_seconds": c.poll_interval_seconds,
            "max_extract_depth": c.max_extract_depth,
            "zip_bomb_ratio": c.zip_bomb_ratio,
            "enable_ioc_correlation": c.enable_ioc_correlation,
        }
