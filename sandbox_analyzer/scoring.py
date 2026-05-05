"""
Stage 5 — Risk Scoring Engine.

Translates a list of `MonitorEvent`s into a single additive risk score.
Weights are configurable (`SandboxConfig.behavior_weights`). The design
rationale (additive, not binary) is captured in the design doc.
"""

from typing import Dict, List

from .config import SandboxConfig
from .models import MonitorEvent, ScoreBreakdown


def compute_risk_score(
    events: List[MonitorEvent],
    config: SandboxConfig,
) -> ScoreBreakdown:
    """
    Aggregate per-event weights into a total score plus a ranked
    "top factors" list for forensic readability.

    Unknown categories contribute 0 points (safely ignored).
    """
    weights = config.behavior_weights
    by_cat: Dict[str, int] = {}
    ev_cnt: Dict[str, int] = {}
    for ev in events:
        w = weights.get(ev.category, 0)
        by_cat[ev.category] = by_cat.get(ev.category, 0) + w
        ev_cnt[ev.category] = ev_cnt.get(ev.category, 0) + 1

    total = sum(by_cat.values())
    top = [
        f"{cat} (x{ev_cnt[cat]} = +{pts})"
        for cat, pts in sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)[:5]
        if pts > 0
    ]
    return ScoreBreakdown(
        total_score=total,
        by_category=by_cat,
        event_count=ev_cnt,
        top_factors=top,
    )
