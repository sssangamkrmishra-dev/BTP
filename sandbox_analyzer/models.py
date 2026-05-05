"""
Data models for the Sandbox Analyzer pipeline.
Dataclasses with `to_dict()` serialisers for structured logging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_id(prefix: str, length: int = 12) -> str:
    return f"{prefix}{uuid.uuid4().hex[:length]}"


def new_report_id() -> str:
    return _generate_id("sbx_", 12)


# ── Enums ──────────────────────────────────────────────────────────

class FileCategory(Enum):
    """Coarse classification produced by the File Router."""
    EXECUTABLE = "executable"   # Linux ELF binary
    SCRIPT     = "script"       # .py, .sh, .rb, .pl ...
    ARCHIVE    = "archive"      # .zip, .tar, .gz
    IMAGE      = "image"        # .jpg, .png, ...
    DOCUMENT   = "document"     # .pdf
    SAFE       = "safe"         # .txt, .csv — skip deep analysis
    WINDOWS    = "windows"      # .exe, .dll — flag only; not executed
    UNKNOWN    = "unknown"      # treat as suspicious


class Verdict(Enum):
    CLEAN      = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS  = "MALICIOUS"


class MonitorName(Enum):
    FILESYSTEM    = "FileSystem"
    NETWORK       = "Network"
    PROCESS       = "Process"
    PRIVILEGE     = "Privilege"
    ARCHIVE       = "ArchiveHandler"
    ROUTER        = "Router"
    EXECUTION     = "Execution"


# ── Router ─────────────────────────────────────────────────────────

@dataclass
class RoutingDecision:
    """Output of the File Router."""
    category: FileCategory
    interpreter: Optional[str] = None   # e.g. "python3"
    should_skip: bool = False           # True for SAFE
    magic_match: bool = False           # type confirmed by magic bytes
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "interpreter": self.interpreter,
            "should_skip": self.should_skip,
            "magic_match": self.magic_match,
            "details": self.details,
        }


# ── Archive ────────────────────────────────────────────────────────

@dataclass
class ArchiveResult:
    """Findings from the Archive Handler."""
    success: bool = False
    extracted_files: List[str] = field(default_factory=list)
    was_encrypted: bool = False
    decryption_source: str = ""         # "metadata_key" | ""
    double_extensions: List[str] = field(default_factory=list)
    zip_bomb_detected: bool = False
    error: Optional[str] = None
    suspicious_flags: List[str] = field(default_factory=list)
    extra_risk_score: int = 0
    depth_reached: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "extracted_file_count": len(self.extracted_files),
            "was_encrypted": self.was_encrypted,
            "decryption_source": self.decryption_source,
            "double_extensions": list(self.double_extensions),
            "zip_bomb_detected": self.zip_bomb_detected,
            "error": self.error,
            "suspicious_flags": list(self.suspicious_flags),
            "extra_risk_score": self.extra_risk_score,
            "depth_reached": self.depth_reached,
        }


# ── Execution ──────────────────────────────────────────────────────

@dataclass
class ExecutionResult:
    """Observable outcome of executing a single file under resource limits."""
    pid: Optional[int] = None
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_sec: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_sec": round(self.duration_sec, 3),
            "error": self.error,
        }


# ── Monitor events ─────────────────────────────────────────────────

@dataclass
class MonitorEvent:
    """One observation from a monitor; rows of this list become the audit trail."""
    timestamp: float
    monitor: str                        # MonitorName value
    category: str                       # risk-scoring key (see BEHAVIOR_WEIGHTS)
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 3),
            "monitor": self.monitor,
            "category": self.category,
            "detail": self.detail,
            "data": dict(self.data),
        }


# ── Scoring ────────────────────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    """Per-category aggregate of risk-scored events."""
    total_score: int
    by_category: Dict[str, int]
    event_count: Dict[str, int]
    top_factors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "by_category": dict(self.by_category),
            "event_count": dict(self.event_count),
            "top_factors": list(self.top_factors),
        }


# ── IOC correlation ────────────────────────────────────────────────

@dataclass
class IOCResult:
    """Threat-intel-correlator response, normalised."""
    any_match: bool = False
    matched_hashes: List[str] = field(default_factory=list)
    matched_ips: List[str] = field(default_factory=list)
    matched_domains: List[str] = field(default_factory=list)
    bonus_score: int = 0
    source: str = "stub"                # "stub" | "threat_intelligence_correlator" | etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "any_match": self.any_match,
            "matched_hashes": list(self.matched_hashes),
            "matched_ips": list(self.matched_ips),
            "matched_domains": list(self.matched_domains),
            "bonus_score": self.bonus_score,
            "source": self.source,
        }


# ── Final report ───────────────────────────────────────────────────

@dataclass
class SandboxReport:
    """
    Complete output of one sandbox run. This is the stable contract
    consumed by the Response & Quarantine Manager, the Security
    Dashboard, and the ML retraining pipeline.
    """

    # Identity
    report_id: str
    file_path: str
    file_hash: str
    drone_id: str
    artifact_id: Optional[str] = None

    # Classification & routing
    file_category: str = FileCategory.UNKNOWN.value
    routing: Optional[RoutingDecision] = None
    skipped: bool = False
    skip_reason: Optional[str] = None

    # Stage outputs
    archive_result: Optional[ArchiveResult] = None
    execution_results: List[ExecutionResult] = field(default_factory=list)
    events: List[MonitorEvent] = field(default_factory=list)
    score_breakdown: Optional[ScoreBreakdown] = None
    ioc_result: Optional[IOCResult] = None

    # Final outputs
    risk_score: int = 0
    verdict: Verdict = Verdict.CLEAN
    action: str = ""

    # Audit
    created_at: str = field(default_factory=_utc_now_iso)
    duration_sec: float = 0.0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    config_snapshot: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_events: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "report_id": self.report_id,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "drone_id": self.drone_id,
            "artifact_id": self.artifact_id,
            "file_category": self.file_category,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "risk_score": self.risk_score,
            "verdict": self.verdict.value,
            "action": self.action,
            "created_at": self.created_at,
            "duration_sec": round(self.duration_sec, 3),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
        if self.routing is not None:
            d["routing"] = self.routing.to_dict()
        if self.archive_result is not None:
            d["archive_result"] = self.archive_result.to_dict()
        if self.score_breakdown is not None:
            d["score_breakdown"] = self.score_breakdown.to_dict()
        if self.ioc_result is not None:
            d["ioc_result"] = self.ioc_result.to_dict()
        d["execution_results"] = [r.to_dict() for r in self.execution_results]
        if include_events:
            d["events"] = [e.to_dict() for e in self.events]
        else:
            d["event_count"] = len(self.events)
        if self.config_snapshot:
            d["config_snapshot"] = self.config_snapshot
        return d

    def summary(self) -> str:
        """Human-readable one-shot summary useful for logs and demos."""
        lines = [
            "═" * 64,
            "  SANDBOX REPORT",
            f"  Report   : {self.report_id}",
            f"  File     : {self.file_path}",
            f"  Hash     : {self.file_hash[:20]}..." if self.file_hash else "  Hash     : (unavailable)",
            f"  Drone    : {self.drone_id}",
            f"  Category : {self.file_category}",
            f"  Duration : {self.duration_sec:.2f}s   Events: {len(self.events)}",
            f"  Score    : {self.risk_score}",
            "  " + "─" * 60,
            f"  VERDICT  : {self.verdict.value}",
            f"  ACTION   : {self.action}",
        ]
        if self.ioc_result and self.ioc_result.any_match:
            if self.ioc_result.matched_ips:
                lines.append(f"  IOC IPs  : {self.ioc_result.matched_ips}")
            if self.ioc_result.matched_domains:
                lines.append(f"  IOC DOMs : {self.ioc_result.matched_domains}")
            if self.ioc_result.matched_hashes:
                lines.append(f"  IOC HASH : {self.ioc_result.matched_hashes}")
        if self.score_breakdown and self.score_breakdown.top_factors:
            lines.append("  Top risk factors:")
            for factor in self.score_breakdown.top_factors:
                lines.append(f"    • {factor}")
        lines.append("═" * 64)
        return "\n".join(lines)
