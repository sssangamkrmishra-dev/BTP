"""
Stage 6 — IOC Correlation.

Integration seam for the **Threat Intelligence Correlator** module. The
class-based client in this file is the contract: the reference
implementation (`LocalThreatIntelClient`) is backed by an in-memory
database suitable for tests and demos; production deployments inject a
subclass that talks to VirusTotal / AlienVault OTX / MISP / an internal
Threat Intelligence Correlator service.

Input:  file hash + observed IPs + observed domains from monitor events.
Output: `IOCResult` with matched indicators and a risk bonus.
"""

import hashlib
import logging
import re
import threading
from typing import Iterable, List, Optional, Set

from .config import SandboxConfig
from .models import IOCResult, MonitorEvent, MonitorName

logger = logging.getLogger(__name__)


_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
#: FQDN heuristic — requires at least two dots so bare "photo.jpg" never
#: false-matches and a TLD of 2+ letters so file extensions cannot pass.
_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+\.[a-zA-Z]{2,})\b"
)


# ── Client contract ───────────────────────────────────────────────

class ThreatIntelClient:
    """
    Abstract client for the Threat Intelligence Correlator module.

    Subclasses override `query()` to talk to a real backend. The return
    value must carry exactly the four keys shown below so that
    `correlate_iocs()` can build an `IOCResult` without special-casing.
    """

    source = "unknown"

    def query(
        self,
        file_hash: str,
        observed_ips: Set[str],
        observed_domains: Set[str],
    ) -> dict:
        raise NotImplementedError


class LocalThreatIntelClient(ThreatIntelClient):
    """
    In-memory reference implementation. Thread-safe; seed the lists at
    construction time and mutate them via `add_*` if the host wants to
    simulate feedback-loop updates in tests.
    """

    source = "local_stub"

    def __init__(
        self,
        hashes: Optional[Iterable[str]] = None,
        ips: Optional[Iterable[str]] = None,
        domains: Optional[Iterable[str]] = None,
    ):
        self._lock = threading.RLock()
        self._hashes: Set[str] = set(hashes or ())
        self._ips: Set[str] = set(ips or ())
        self._domains: Set[str] = set(domains or ())

    def query(
        self,
        file_hash: str,
        observed_ips: Set[str],
        observed_domains: Set[str],
    ) -> dict:
        with self._lock:
            matched_hashes = [file_hash] if file_hash and file_hash in self._hashes else []
            matched_ips = list(observed_ips & self._ips)
            matched_domains = list(observed_domains & self._domains)
        return {
            "matched_hashes": matched_hashes,
            "matched_ips": matched_ips,
            "matched_domains": matched_domains,
            "any_match": bool(matched_hashes or matched_ips or matched_domains),
        }

    # ── Feedback-loop update hooks ────────────────────────────────
    def add_hash(self, sha256: str) -> None:
        with self._lock:
            self._hashes.add(sha256)

    def add_ip(self, ip: str) -> None:
        with self._lock:
            self._ips.add(ip)

    def add_domain(self, domain: str) -> None:
        with self._lock:
            self._domains.add(domain)

    def snapshot(self) -> dict:   # pragma: no cover — debug aid
        with self._lock:
            return {
                "hashes": sorted(self._hashes),
                "ips": sorted(self._ips),
                "domains": sorted(self._domains),
            }


# ── Helpers ───────────────────────────────────────────────────────

def compute_file_hash(file_path: str, chunk_size: int = 8192) -> str:
    """SHA-256 of the file on disk; empty string on I/O error."""
    sha = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def extract_network_iocs(events: List[MonitorEvent]) -> dict:
    """Pull IPs and domains out of Network-monitor events for IOC lookup."""
    ips: Set[str] = set()
    domains: Set[str] = set()
    net_monitor = MonitorName.NETWORK.value
    for ev in events:
        if ev.monitor != net_monitor:
            continue
        ips.update(_IP_PATTERN.findall(ev.detail))
        domains.update(_DOMAIN_PATTERN.findall(ev.detail))
        # Also look at structured `data` fields when present.
        remote = ev.data.get("remote") if isinstance(ev.data, dict) else None
        if remote:
            ips.update(_IP_PATTERN.findall(str(remote)))
    # Strip obvious false positives (loopback / zero address).
    ips.discard("0.0.0.0")
    ips.discard("127.0.0.1")
    return {"ips": ips, "domains": domains}


def correlate_iocs(
    file_path: str,
    events: List[MonitorEvent],
    config: SandboxConfig,
    client: Optional[ThreatIntelClient] = None,
) -> IOCResult:
    """
    Look up hash / IPs / domains against the injected threat-intel
    client and translate the response into an `IOCResult`.

    When `config.enable_ioc_correlation` is False, returns an empty
    result with `source="disabled"`.
    """
    if not config.enable_ioc_correlation:
        return IOCResult(source="disabled")

    client = client or LocalThreatIntelClient()
    file_hash = compute_file_hash(file_path)
    net = extract_network_iocs(events)

    try:
        response = client.query(file_hash, net["ips"], net["domains"])
    except Exception:
        logger.exception("threat intel client raised; continuing without IOC match")
        return IOCResult(source=client.source)

    any_match = bool(response.get("any_match"))
    return IOCResult(
        any_match=any_match,
        matched_hashes=list(response.get("matched_hashes") or ()),
        matched_ips=list(response.get("matched_ips") or ()),
        matched_domains=list(response.get("matched_domains") or ()),
        bonus_score=config.ioc_match_bonus if any_match else 0,
        source=client.source,
    )
