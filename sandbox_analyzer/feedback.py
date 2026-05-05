"""
Stage 8 — Feedback / post-verdict callbacks.

Three integration seams exposed via the `FeedbackSink` contract:

1. **Response & Quarantine Manager** — receives the final verdict and
   action (allow / quarantine / block).
2. **Security Dashboard & Feedback Loop** — receives the full
   `SandboxReport` for logging, analytics, and analyst review.
3. **ML retraining queue** — receives the behavioural trace + label so
   the AI/ML classifier can learn from sandbox verdicts.

Reference implementations log to the Python logger. Production hosts
subclass `FeedbackSink` — or compose three callables via `build_sink()`
— and hand the result to `SandboxAnalyzer` at construction time.
"""

import logging
from typing import Callable, List, Optional

from .models import SandboxReport, Verdict

logger = logging.getLogger(__name__)


# ── Contract ──────────────────────────────────────────────────────

class FeedbackSink:
    """
    Host-injectable sink for the three post-verdict feedback channels.
    Override any combination of the three methods; unoverridden methods
    are no-ops so partial integrations do not need to stub the rest.
    """

    def notify_response_manager(self, report: SandboxReport) -> None:
        """Hand the verdict to the Response & Quarantine Manager."""

    def notify_dashboard(self, report: SandboxReport) -> None:
        """Log the full report to the Security Dashboard / Feedback Loop."""

    def queue_for_ml(self, report: SandboxReport) -> None:
        """Send the behavioural trace + label to the ML retraining queue."""


# ── Reference implementation ──────────────────────────────────────

class LoggingFeedbackSink(FeedbackSink):
    """
    Default sink used when the host has not wired real modules yet.
    Every method produces structured log lines instead of side effects.
    Safe to use in production behind a real log aggregator.
    """

    source = "logging_stub"

    def notify_response_manager(self, report: SandboxReport) -> None:
        logger.info(
            "response_manager verdict=%s score=%d file=%s drone=%s action=%s",
            report.verdict.value, report.risk_score,
            report.file_path, report.drone_id, report.action,
        )

    def notify_dashboard(self, report: SandboxReport) -> None:
        logger.info(
            "dashboard report_id=%s drone=%s verdict=%s score=%d events=%d",
            report.report_id, report.drone_id,
            report.verdict.value, report.risk_score, len(report.events),
        )
        if report.ioc_result and report.ioc_result.any_match:
            logger.info(
                "dashboard ioc matches hashes=%s ips=%s domains=%s",
                report.ioc_result.matched_hashes,
                report.ioc_result.matched_ips,
                report.ioc_result.matched_domains,
            )

    def queue_for_ml(self, report: SandboxReport) -> None:
        trace: List[str] = [ev.category for ev in report.events]
        label = 1 if report.verdict == Verdict.MALICIOUS else 0
        logger.info(
            "ml_retraining drone=%s label=%d trace_len=%d trace=%s",
            report.drone_id, label, len(trace), trace,
        )


# ── Convenience builder ───────────────────────────────────────────

def build_sink(
    response_manager: Optional[Callable[[SandboxReport], None]] = None,
    dashboard: Optional[Callable[[SandboxReport], None]] = None,
    ml_queue: Optional[Callable[[SandboxReport], None]] = None,
) -> FeedbackSink:
    """
    Construct a sink from three callables without subclassing. Any
    argument left None falls back to the logging default.
    """
    base = LoggingFeedbackSink()

    class _Composed(FeedbackSink):
        def notify_response_manager(self, report: SandboxReport) -> None:
            (response_manager or base.notify_response_manager)(report)

        def notify_dashboard(self, report: SandboxReport) -> None:
            (dashboard or base.notify_dashboard)(report)

        def queue_for_ml(self, report: SandboxReport) -> None:
            (ml_queue or base.queue_for_ml)(report)

    return _Composed()
