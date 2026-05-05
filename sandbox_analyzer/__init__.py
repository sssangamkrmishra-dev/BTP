"""
Sandbox Analyzer Package
=========================

Dynamic behavioural analysis layer of the Multi-Layer Malware Detection
Engine. Executes suspicious drone/RPA payloads inside a kernel-limited
Linux sandbox, watches them via four /proc monitors, correlates findings
against threat intelligence, and emits a three-level verdict
(CLEAN / SUSPICIOUS / MALICIOUS) with a complete behavioural trace.

Pipeline Position:
    Ingestion Interceptor → Game-Theoretic Threat Estimator
        → Inspection Strategy Selector → **Sandbox Analyzer**
        → Metadata Sanitizer → Threat Intelligence Correlator
        → Response & Quarantine Manager → Security Dashboard & Feedback Loop

Main entry points:
    - SandboxAnalyzer: class-based API with full configuration and DI seams
    - Supporting helpers (route_file, handle_archive, compute_risk_score, ...)

Usage:
    from sandbox_analyzer import SandboxAnalyzer, SandboxConfig

    analyzer = SandboxAnalyzer(SandboxConfig())
    report = analyzer.analyze(file_path, drone_id="DRN-001")
    print(report.verdict.value, report.risk_score)

    # Swap the reference Threat Intel client for a production one
    from sandbox_analyzer import ThreatIntelClient
    class MyCorrelator(ThreatIntelClient):
        source = "threat_intelligence_correlator"
        def query(self, file_hash, ips, domains):
            return requests.post("https://tic.internal/query", json={...}).json()

    analyzer = SandboxAnalyzer(
        SandboxConfig(),
        threat_intel_client=MyCorrelator(),
    )
"""

from .analyzer import SandboxAnalyzer
from .archive_handler import (
    check_double_extension,
    handle_archive,
    is_encrypted_zip,
)
from .config import (
    DEFAULT_BEHAVIOR_WEIGHTS,
    DEFAULT_EXECUTABLE_EXTENSIONS,
    DEFAULT_SHELL_PROCESSES,
    DEFAULT_SUSPICIOUS_PATHS,
    DEFAULT_SUSPICIOUS_PROCESSES,
    SandboxConfig,
)
from .execution import SANDBOX_EXECUTION_AVAILABLE, execute_file
from .feedback import FeedbackSink, LoggingFeedbackSink, build_sink
from .ioc import (
    LocalThreatIntelClient,
    ThreatIntelClient,
    compute_file_hash,
    correlate_iocs,
    extract_network_iocs,
)
from .models import (
    ArchiveResult,
    ExecutionResult,
    FileCategory,
    IOCResult,
    MonitorEvent,
    MonitorName,
    RoutingDecision,
    SandboxReport,
    ScoreBreakdown,
    Verdict,
    new_report_id,
)
from .monitors import (
    EventLog,
    FileSystemMonitor,
    NetworkMonitor,
    PrivilegeMonitor,
    ProcessMonitor,
    build_monitors,
)
from .router import EXTENSION_MAP, INTERPRETER_MAP, MAGIC_BYTES, route_file
from .scoring import compute_risk_score
from .verdict import VERDICT_ACTIONS, action_for, determine_verdict

__all__ = [
    # Core
    "SandboxAnalyzer",
    "SandboxConfig",
    # Stage entry points
    "route_file",
    "handle_archive",
    "execute_file",
    "compute_risk_score",
    "correlate_iocs",
    "determine_verdict",
    "action_for",
    "check_double_extension",
    "is_encrypted_zip",
    "compute_file_hash",
    "extract_network_iocs",
    # Monitors
    "EventLog",
    "FileSystemMonitor",
    "NetworkMonitor",
    "ProcessMonitor",
    "PrivilegeMonitor",
    "build_monitors",
    # Models
    "SandboxReport",
    "RoutingDecision",
    "ArchiveResult",
    "ExecutionResult",
    "MonitorEvent",
    "MonitorName",
    "ScoreBreakdown",
    "IOCResult",
    "Verdict",
    "FileCategory",
    "new_report_id",
    # Integration seams
    "ThreatIntelClient",
    "LocalThreatIntelClient",
    "FeedbackSink",
    "LoggingFeedbackSink",
    "build_sink",
    # Platform capability flag
    "SANDBOX_EXECUTION_AVAILABLE",
    # Constants exposed for host tuning
    "MAGIC_BYTES",
    "EXTENSION_MAP",
    "INTERPRETER_MAP",
    "VERDICT_ACTIONS",
    "DEFAULT_BEHAVIOR_WEIGHTS",
    "DEFAULT_SUSPICIOUS_PATHS",
    "DEFAULT_SUSPICIOUS_PROCESSES",
    "DEFAULT_SHELL_PROCESSES",
    "DEFAULT_EXECUTABLE_EXTENSIONS",
]
