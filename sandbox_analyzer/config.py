"""
Configuration for the Sandbox Analyzer module.
All tuneable parameters are centralized here.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple


# ──────────────────────────────────────────────────────────────────────
# Default event → risk weight table.
# Higher weights = actions that are almost never legitimate in a sandboxed
# drone/RPA payload. Calibration is an engineering judgement, traced in
# the design doc (see §6 "Risk Scoring").
# ──────────────────────────────────────────────────────────────────────
DEFAULT_BEHAVIOR_WEIGHTS: Dict[str, int] = {
    "self_replication":       40,   # copies itself into persistence locations
    "privilege_escalation":   35,   # setuid / capability gain
    "memory_inject":          35,   # sudden VmRSS spike (packer/injector)
    "api_hooking":            30,
    "file_write_executable":  30,   # drops a new binary/script
    "network_connect":        25,   # any outbound connection attempt
    "shell_command":          25,   # shell spawned by a data file
    "registry_write":         20,
    "high_entropy_write":     15,   # packed/encrypted write
    "dns_lookup":             15,
    "process_spawn":          10,
    "file_delete":            10,
    "file_system_write":       5,
}

# Paths that are suspicious to write into when seen inside the sandbox.
DEFAULT_SUSPICIOUS_PATHS: Tuple[str, ...] = (
    "/tmp", "/var/tmp",
    "/etc/cron", "/var/spool/cron",
    "/etc/passwd", "/etc/shadow",
    "/root", "/.ssh",
    "/dev/mem", "/dev/kmem",
    "/etc/init.d", "/etc/rc",
)

# Process names that are suspicious when spawned by a sandboxed file.
DEFAULT_SUSPICIOUS_PROCESSES: Set[str] = {
    "bash", "sh", "zsh", "dash", "fish",   # reverse-shell indicators
    "wget", "curl", "nc", "ncat",           # network download/connect
    "crontab", "at",                        # persistence scheduling
    "chmod", "chown", "sudo", "su",         # privilege tools
    "gcc", "cc", "make",                    # in-sandbox compilation
}

DEFAULT_SHELL_PROCESSES: Set[str] = {"bash", "sh", "zsh", "dash", "fish"}

# File extensions considered executable when found written into suspicious
# paths (bumps classification from file_system_write to file_write_executable).
DEFAULT_EXECUTABLE_EXTENSIONS: Tuple[str, ...] = (
    ".sh", ".py", ".elf", ".bin", ".pl", ".rb",
)


@dataclass
class SandboxConfig:
    """
    Configuration for the Sandbox Analyzer.

    Groups: routing, archive handling, execution limits, monitor polling,
    risk scoring, IOC correlation, verdict thresholds, and feedback.
    """

    # ── Routing ────────────────────────────────────────────────────────
    # When True, files classified as SAFE (plain CSV / TXT etc.) return an
    # immediate CLEAN report without executing.
    skip_safe_files: bool = True
    # When True, Windows PE executables are flagged for manual review and
    # NOT executed (the sandbox runs on Linux). Enabling cross-VM execution
    # is handled by a future adapter; this flag keeps behaviour explicit.
    flag_windows_executables: bool = True

    # ── Archive handling ───────────────────────────────────────────────
    max_extract_depth: int = 3
    zip_bomb_ratio: float = 0.005               # compressed/uncompressed
    zip_bomb_min_size_bytes: int = 10 * 1024 * 1024   # only check ratio above this uncompressed size
    encrypted_no_key_score: int = 25            # risk points added to I_base
    double_extension_score: int = 30

    # ── Execution limits (kernel-enforced via setrlimit) ───────────────
    memory_bytes: int = 128 * 1024 * 1024       # 128 MB virtual memory cap
    cpu_seconds: int = 20                       # CPU-time cap (SIGXCPU)
    file_bytes: int = 32 * 1024 * 1024          # max file size the process may create
    max_processes: int = 50                     # fork-bomb guard
    wall_timeout_seconds: int = 30              # wall-clock kill
    empty_environment: bool = True              # run with env={} by default
    communicate_grace_seconds: int = 2          # additional time for proc.communicate

    # ── Monitors ───────────────────────────────────────────────────────
    poll_interval_seconds: float = 0.2
    enable_filesystem_monitor: bool = True
    enable_network_monitor: bool = True
    enable_process_monitor: bool = True
    enable_privilege_monitor: bool = True
    memory_spike_threshold_kb: int = 50 * 1024  # 50 MB jump in one poll
    stdout_capture_bytes: int = 2000
    stderr_capture_bytes: int = 2000

    # ── Suspicious-target lists ────────────────────────────────────────
    suspicious_paths: Tuple[str, ...] = field(
        default_factory=lambda: tuple(DEFAULT_SUSPICIOUS_PATHS)
    )
    suspicious_processes: Set[str] = field(
        default_factory=lambda: set(DEFAULT_SUSPICIOUS_PROCESSES)
    )
    shell_processes: Set[str] = field(
        default_factory=lambda: set(DEFAULT_SHELL_PROCESSES)
    )
    executable_extensions: Tuple[str, ...] = field(
        default_factory=lambda: tuple(DEFAULT_EXECUTABLE_EXTENSIONS)
    )

    # ── Risk scoring ───────────────────────────────────────────────────
    behavior_weights: Dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_BEHAVIOR_WEIGHTS)
    )

    # ── IOC correlation ────────────────────────────────────────────────
    ioc_match_bonus: int = 20
    enable_ioc_correlation: bool = True

    # ── Verdict thresholds ─────────────────────────────────────────────
    suspicious_threshold: int = 25
    malicious_threshold: int = 60

    # ── Feedback (post-verdict callbacks) ──────────────────────────────
    enable_feedback_hooks: bool = True

    # ── Logging ────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ──────────────────────────────────────────────────────────────────
    # Fail fast on mis-configurations.
    # ──────────────────────────────────────────────────────────────────
    def __post_init__(self) -> None:
        if self.max_extract_depth < 0:
            raise ValueError(f"max_extract_depth must be >= 0; got {self.max_extract_depth}")
        if not 0.0 < self.zip_bomb_ratio <= 1.0:
            raise ValueError(
                f"zip_bomb_ratio must be in (0, 1]; got {self.zip_bomb_ratio}"
            )
        if self.zip_bomb_min_size_bytes < 0:
            raise ValueError("zip_bomb_min_size_bytes must be >= 0")
        for name, value in (
            ("memory_bytes", self.memory_bytes),
            ("cpu_seconds", self.cpu_seconds),
            ("file_bytes", self.file_bytes),
            ("max_processes", self.max_processes),
            ("wall_timeout_seconds", self.wall_timeout_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be > 0; got {value}")
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be > 0")
        if self.suspicious_threshold < 0:
            raise ValueError("suspicious_threshold must be >= 0")
        if self.malicious_threshold <= self.suspicious_threshold:
            raise ValueError(
                "malicious_threshold must be strictly greater than suspicious_threshold; "
                f"got {self.malicious_threshold} <= {self.suspicious_threshold}"
            )
        if any(v < 0 for v in self.behavior_weights.values()):
            raise ValueError("behavior_weights must all be non-negative")
