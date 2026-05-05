"""
Standalone demo for the Sandbox Analyzer.

Runs the eight-stage pipeline on four representative inputs:

    1. A benign CSV (routed SAFE, returns CLEAN without execution)
    2. A disguised shell script named .jpg (magic-byte detection)
    3. A ZIP with a double-extension member (recon.jpg.sh)
    4. A suspicious Python script that spawns a shell and makes a
       network callback to a known-bad IP (Linux only — skipped elsewhere)

Run:
    python -m sandbox_analyzer.run_demo
"""

import logging
import os
import platform
import tempfile
import zipfile

from sandbox_analyzer import (
    LocalThreatIntelClient,
    LoggingFeedbackSink,
    SandboxAnalyzer,
    SandboxConfig,
)


def _hr(title: str) -> None:
    print(f"\n{'─' * 78}\n{title}\n{'─' * 78}")


def _write(path: str, body: str, mode: str = "w") -> None:
    with open(path, mode) as f:
        f.write(body)


def stage_safe_csv(analyzer: SandboxAnalyzer, workdir: str) -> None:
    _hr("Stage A — SAFE routing (plain CSV, no execution)")
    path = os.path.join(workdir, "telemetry.csv")
    _write(path, "lat,lon,alt\n28.61,77.20,120\n")
    report = analyzer.analyze(path, drone_id="DRONE_A")
    print(report.summary())


def stage_disguised_script(analyzer: SandboxAnalyzer, workdir: str) -> None:
    _hr("Stage B — Magic-byte detection (.jpg that's really a shell script)")
    path = os.path.join(workdir, "photo.jpg")
    _write(path, "#!/bin/bash\necho disguised\n")
    report = analyzer.analyze(path, drone_id="DRONE_B")
    print(report.summary())


def stage_archive_double_extension(analyzer: SandboxAnalyzer, workdir: str) -> None:
    _hr("Stage C — Archive with double-extension member")
    path = os.path.join(workdir, "mission_data.zip")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("flight_log.csv", "ts,lat,lon\n1000,28.6,77.2\n")
        zf.writestr("recon.jpg.sh", "#!/bin/bash\nid\n")
    report = analyzer.analyze(path, drone_id="DRONE_C")
    print(report.summary())


def stage_malicious_script(analyzer: SandboxAnalyzer, workdir: str) -> None:
    if platform.system() != "Linux":
        _hr(f"Stage D — Skipped: live execution needs Linux (host is {platform.system()})")
        return
    _hr("Stage D — Live execution of a script that mimics C2 behaviour")
    path = os.path.join(workdir, "malware.py")
    _write(path, (
        "import socket, subprocess, time\n"
        "try:\n"
        "    s = socket.socket(); s.settimeout(1)\n"
        "    s.connect(('203.0.113.42', 4444)); s.close()\n"
        "except Exception:\n"
        "    pass\n"
        "try:\n"
        "    subprocess.run(['bash', '-c', 'id'], capture_output=True, timeout=2)\n"
        "except Exception:\n"
        "    pass\n"
        "time.sleep(0.4)\n"
    ))
    report = analyzer.analyze(path, drone_id="DRONE_D")
    print(report.summary())


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    config = SandboxConfig()
    # Seed the reference threat-intel client with one known-bad IP so
    # stage D triggers an IOC match when it runs on Linux.
    tic = LocalThreatIntelClient(ips={"203.0.113.42"})
    analyzer = SandboxAnalyzer(
        config=config,
        threat_intel_client=tic,
        feedback_sink=LoggingFeedbackSink(),
    )

    workdir = tempfile.mkdtemp(prefix="sandbox_demo_")
    try:
        stage_safe_csv(analyzer, workdir)
        stage_disguised_script(analyzer, workdir)
        stage_archive_double_extension(analyzer, workdir)
        stage_malicious_script(analyzer, workdir)

        _hr("Analyzer stats")
        for k, v in analyzer.stats.items():
            print(f"  {k:<24} {v}")
    finally:
        pass  # keep tmp files for post-mortem inspection


if __name__ == "__main__":
    main()
