"""
Stage 7 — Verdict mapping.

Threshold-based mapping from integer risk score to the three-level
`Verdict` enum plus a human-readable action description used by the
Response & Quarantine Manager.
"""

from typing import Dict

from .config import SandboxConfig
from .models import Verdict


VERDICT_ACTIONS: Dict[Verdict, str] = {
    Verdict.CLEAN:      "Forward file to operational network",
    Verdict.SUSPICIOUS: "Quarantine. Queue for analyst review.",
    Verdict.MALICIOUS:  "Block. Alert SOC/SIEM. Flag drone feed as compromised.",
}


def determine_verdict(risk_score: int, config: SandboxConfig) -> Verdict:
    """Classify a score against `config.{suspicious,malicious}_threshold`."""
    if risk_score >= config.malicious_threshold:
        return Verdict.MALICIOUS
    if risk_score >= config.suspicious_threshold:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def action_for(verdict: Verdict) -> str:
    """Operator-facing action string for the Response & Quarantine Manager."""
    return VERDICT_ACTIONS[verdict]
