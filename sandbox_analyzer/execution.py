"""
Stage 3 — Isolated Execution Environment.

Launches a child process with kernel-enforced resource caps, an empty
environment, and an isolated working directory. A watchdog thread sends
SIGKILL after `wall_timeout_seconds`.

Linux-only: `resource.setrlimit()` is a POSIX primitive and `/proc`
monitoring requires Linux. On other platforms the limits cannot be
enforced and the functions in this module will raise.
"""

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Callable, List, Optional

from .config import SandboxConfig
from .models import ExecutionResult

logger = logging.getLogger(__name__)


IS_LINUX = platform.system() == "Linux"
try:
    import resource as _resource   # POSIX only
    HAVE_POSIX_RESOURCE = True
except ImportError:   # pragma: no cover — Windows fallback
    _resource = None
    HAVE_POSIX_RESOURCE = False

#: Public flag indicating whether kernel-enforced sandbox execution
#: (Stages 3 and 4) can run on this host. Consumed by the orchestrator
#: so it can degrade gracefully on non-Linux development machines.
SANDBOX_EXECUTION_AVAILABLE = IS_LINUX and HAVE_POSIX_RESOURCE


def _make_preexec_fn(config: SandboxConfig):
    """
    Return a preexec function that applies kernel resource limits in the
    child process after fork() and before exec() — so limits are active
    before any code in the target file runs.
    """
    if not HAVE_POSIX_RESOURCE:
        return None

    mem = config.memory_bytes
    cpu = config.cpu_seconds
    fsz = config.file_bytes
    npr = config.max_processes

    def _apply_limits() -> None:
        _resource.setrlimit(_resource.RLIMIT_AS,    (mem, mem))
        _resource.setrlimit(_resource.RLIMIT_CPU,   (cpu, cpu))
        _resource.setrlimit(_resource.RLIMIT_FSIZE, (fsz, fsz))
        _resource.setrlimit(_resource.RLIMIT_NPROC, (npr, npr))
        _resource.setrlimit(_resource.RLIMIT_CORE,  (0, 0))

    return _apply_limits


def _truncate(data: bytes, cap: int) -> str:
    if cap <= 0:
        return ""
    return data[:cap].decode(errors="replace")


def execute_file(
    file_path: str,
    config: SandboxConfig,
    interpreter: Optional[str] = None,
    work_dir: Optional[str] = None,
    env: Optional[dict] = None,
    on_pid: Optional[Callable[[int], None]] = None,
) -> ExecutionResult:
    """
    Launch the target file inside the sandbox and block until it exits
    (or is killed by the watchdog).

    Args:
        file_path: The file to run.
        config: SandboxConfig carrying resource limits and capture caps.
        interpreter: Interpreter to invoke (e.g. "python3"); None = run as binary.
        work_dir: Optional working directory. A fresh temp dir is used otherwise.
        env: Optional environment dict. Empty by default when config.empty_environment is True.
        on_pid: Optional callback invoked with the child PID as soon as it is
                known. Monitors in Stage 4 use this to attach without racing.

    Returns:
        ExecutionResult with stdout/stderr/exit-code/duration plus flags.

    Raises:
        RuntimeError: on non-POSIX hosts where resource limits cannot be applied.
    """
    if not HAVE_POSIX_RESOURCE:
        raise RuntimeError(
            "sandbox execution requires POSIX resource.setrlimit; "
            "this module is Linux-only"
        )

    if not os.path.isfile(file_path):
        return ExecutionResult(error=f"file not found: {file_path}")

    owns_work_dir = work_dir is None
    if owns_work_dir:
        work_dir = tempfile.mkdtemp(prefix="sandbox_exec_")

    cmd: List[str] = [interpreter, file_path] if interpreter else [file_path]
    effective_env = {} if config.empty_environment and env is None else (env or os.environ.copy())

    result = ExecutionResult()
    proc: Optional[subprocess.Popen] = None
    start = time.time()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=work_dir,
            env=effective_env,
            preexec_fn=_make_preexec_fn(config),
        )
        result.pid = proc.pid
        if on_pid is not None:
            try:
                on_pid(proc.pid)
            except Exception:   # pragma: no cover — callback errors are non-fatal
                logger.exception("on_pid callback raised")

        # Watchdog: after wall_timeout, kill the process if still running.
        timed_out = threading.Event()

        def _watchdog() -> None:
            time.sleep(config.wall_timeout_seconds)
            if proc.poll() is None:
                timed_out.set()
                try:
                    proc.kill()
                except Exception:   # pragma: no cover
                    logger.exception("watchdog kill failed")

        threading.Thread(target=_watchdog, daemon=True).start()

        try:
            stdout, stderr = proc.communicate(
                timeout=config.wall_timeout_seconds + config.communicate_grace_seconds
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out.set()

        result.exit_code = proc.returncode
        result.stdout = _truncate(stdout, config.stdout_capture_bytes)
        result.stderr = _truncate(stderr, config.stderr_capture_bytes)
        result.timed_out = timed_out.is_set()

    except FileNotFoundError as exc:
        result.error = f"interpreter not found: {exc}"
    except PermissionError as exc:
        result.error = f"permission denied: {exc}"
    except Exception as exc:   # pragma: no cover — unexpected
        logger.exception("execute_file: unexpected failure")
        result.error = str(exc)
    finally:
        result.duration_sec = time.time() - start
        if owns_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)

    return result
