"""
Stage 4 — The Four Monitors.

Reads /proc at a configurable poll interval while the sandboxed process
runs. Every suspicious observation becomes a `MonitorEvent`. Linux-only;
the monitors silently produce no events on non-Linux hosts.

Reference for /proc-based malware analysis:
  Cozzi et al., "Understanding Linux Malware", IEEE Oakland 2018
  https://ieeexplore.ieee.org/document/8418602
"""

import logging
import os
import threading
import time
from typing import List, Optional, Set, Tuple

from .config import SandboxConfig
from .models import MonitorEvent, MonitorName

logger = logging.getLogger(__name__)


# Flags from /proc/<PID>/fdinfo/<fd>. Values are the stdlib os.O_* masks.
_O_WRONLY = 0o000001
_O_RDWR   = 0o000002


# ── Thread-safe event log ──────────────────────────────────────────

class EventLog:
    """Thread-safe collector. All four monitors append to the same log."""

    def __init__(self) -> None:
        self._events: List[MonitorEvent] = []
        self._lock = threading.Lock()

    def add(self, monitor: str, category: str, detail: str,
            data: Optional[dict] = None) -> None:
        ev = MonitorEvent(
            timestamp=time.time(),
            monitor=monitor,
            category=category,
            detail=detail,
            data=dict(data or {}),
        )
        with self._lock:
            self._events.append(ev)

    def all_events(self) -> List[MonitorEvent]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:   # pragma: no cover — convenience
        with self._lock:
            return len(self._events)


# ── Monitor 1 — File System ───────────────────────────────────────

class FileSystemMonitor:
    """
    Inspects /proc/<PID>/fd/ (symlinks to open files) and
    /proc/<PID>/fdinfo/<fd> (open-flags) and raises events for writes
    into suspicious paths.
    """

    def __init__(self, pid: int, log: EventLog, config: SandboxConfig):
        self.pid = pid
        self.log = log
        self.config = config
        self._seen: Set[Tuple[str, str]] = set()

    def poll(self) -> None:
        fd_dir = f"/proc/{self.pid}/fd"
        if not os.path.isdir(fd_dir):
            return
        try:
            fds = os.listdir(fd_dir)
        except (FileNotFoundError, PermissionError):
            return

        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except (FileNotFoundError, PermissionError):
                continue

            flags = self._read_open_flags(fd)
            is_write = bool(flags & _O_WRONLY or flags & _O_RDWR)
            is_sus_path = any(target.startswith(p) for p in self.config.suspicious_paths)
            key = (fd, target)
            if key in self._seen or not (is_write and is_sus_path):
                continue
            self._seen.add(key)
            is_exec = any(target.endswith(ext) for ext in self.config.executable_extensions)
            category = "file_write_executable" if is_exec else "file_system_write"
            self.log.add(
                monitor=MonitorName.FILESYSTEM.value,
                category=category,
                detail=f"Write to suspicious path: {target}",
                data={"path": target, "flags": oct(flags)},
            )

    def _read_open_flags(self, fd: str) -> int:
        info_path = f"/proc/{self.pid}/fdinfo/{fd}"
        try:
            with open(info_path) as fh:
                for line in fh:
                    if line.startswith("flags:"):
                        return int(line.split()[1], 8)
        except (FileNotFoundError, PermissionError, ValueError):
            return 0
        return 0


# ── Monitor 2 — Network ───────────────────────────────────────────

def _parse_proc_net_tcp(path: str = "/proc/net/tcp") -> Set[Tuple[str, str, str]]:
    """Return a set of (local, remote, state) tuples from /proc/net/tcp."""
    conns: Set[Tuple[str, str, str]] = set()
    try:
        with open(path) as fh:
            next(fh, None)   # header
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    conns.add((parts[1], parts[2], parts[3]))
    except (FileNotFoundError, PermissionError):
        pass
    return conns


class NetworkMonitor:
    """
    Snapshots /proc/net/tcp before execution and diffs it during execution.
    Any new row with state 01 (ESTABLISHED) or 02 (SYN_SENT) is reported
    as an outbound connection attempt — even if the connect failed.
    """

    def __init__(self, log: EventLog, config: SandboxConfig):
        self.log = log
        self.config = config
        self.baseline: Set[Tuple[str, str, str]] = _parse_proc_net_tcp()

    def poll(self) -> None:
        current = _parse_proc_net_tcp()
        for conn in current - self.baseline:
            local, remote, state = conn
            # 01 ESTABLISHED, 02 SYN_SENT; 0.0.0.0:0 = listening socket noise
            if state in ("02", "01") and remote != "00000000:0000":
                self.baseline.add(conn)
                self.log.add(
                    monitor=MonitorName.NETWORK.value,
                    category="network_connect",
                    detail=f"Outbound connection: {local} → {remote} state={state}",
                    data={"local": local, "remote": remote, "state": state},
                )


# ── Monitor 3 — Processes ─────────────────────────────────────────

class ProcessMonitor:
    """
    Tracks the full descendent tree of the sandboxed process. Any shell
    (bash/sh/...) spawned as a child raises a shell_command event; any
    other child is logged as process_spawn.
    """

    def __init__(self, pid: int, log: EventLog, config: SandboxConfig):
        self.pid = pid
        self.log = log
        self.config = config
        self._seen: Set[int] = set()
        self._psutil = self._import_psutil()

    @staticmethod
    def _import_psutil():
        try:
            import psutil   # third-party but ubiquitous
            return psutil
        except ImportError:   # pragma: no cover
            logger.warning("psutil not installed — ProcessMonitor disabled")
            return None

    def poll(self) -> None:
        if self._psutil is None:
            return
        try:
            children = self._psutil.Process(self.pid).children(recursive=True)
        except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
            return

        for child in children:
            if child.pid in self._seen:
                continue
            self._seen.add(child.pid)
            try:
                name = (child.name() or "").lower()
                cmd = " ".join(child.cmdline())
            except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                continue

            # Shell spawns are the strongest signal; any name in
            # suspicious_processes (curl/wget/nc/sudo/...) still promotes
            # above the default process_spawn weight by being flagged as
            # a shell_command (these are also shell-ish lateral-movement
            # tools). Plain spawns fall back to process_spawn.
            if name in self.config.shell_processes:
                category = "shell_command"
            elif name in self.config.suspicious_processes:
                category = "shell_command"
            else:
                category = "process_spawn"
            self.log.add(
                monitor=MonitorName.PROCESS.value,
                category=category,
                detail=f"Child process: {name} (PID {child.pid})",
                data={"name": name, "pid": child.pid, "cmd": cmd[:200]},
            )


# ── Monitor 4 — Privileges ────────────────────────────────────────

class PrivilegeMonitor:
    """
    Reads /proc/<PID>/status for:
      - CapEff changes  → privilege escalation
      - VmRSS spikes    → payload decompression / shellcode injection
    """

    def __init__(self, pid: int, log: EventLog, config: SandboxConfig):
        self.pid = pid
        self.log = log
        self.config = config
        self._last_cap: Optional[str] = None
        self._last_mem_kb: int = 0

    def poll(self) -> None:
        status = self._read_status()
        if not status:
            return

        cap = status.get("CapEff", "0000000000000000")
        if self._last_cap is None:
            self._last_cap = cap
        elif cap != self._last_cap and cap != "0000000000000000":
            self.log.add(
                monitor=MonitorName.PRIVILEGE.value,
                category="privilege_escalation",
                detail=f"Capability change: {self._last_cap} → {cap}",
                data={"previous": self._last_cap, "current": cap},
            )
            self._last_cap = cap

        vmrss = status.get("VmRSS", "0 kB")
        try:
            mem_kb = int(vmrss.split()[0])
        except (ValueError, IndexError):
            mem_kb = 0
        if (mem_kb - self._last_mem_kb) > self.config.memory_spike_threshold_kb:
            self.log.add(
                monitor=MonitorName.PRIVILEGE.value,
                category="memory_inject",
                detail=f"Memory spike: +{mem_kb - self._last_mem_kb} KB",
                data={"delta_kb": mem_kb - self._last_mem_kb, "vmrss_kb": mem_kb},
            )
        self._last_mem_kb = mem_kb

    def _read_status(self) -> dict:
        try:
            with open(f"/proc/{self.pid}/status") as fh:
                return {
                    k.strip(): v.strip()
                    for line in fh
                    for k, _, v in [line.partition(":")]
                }
        except (FileNotFoundError, PermissionError):
            return {}


# ── Monitor runner helper ─────────────────────────────────────────

def build_monitors(
    pid: int,
    log: EventLog,
    config: SandboxConfig,
) -> list:
    """Instantiate every monitor whose flag is enabled in config."""
    monitors: list = []
    if config.enable_filesystem_monitor:
        monitors.append(FileSystemMonitor(pid, log, config))
    if config.enable_network_monitor:
        monitors.append(NetworkMonitor(log, config))
    if config.enable_process_monitor:
        monitors.append(ProcessMonitor(pid, log, config))
    if config.enable_privilege_monitor:
        monitors.append(PrivilegeMonitor(pid, log, config))
    return monitors
