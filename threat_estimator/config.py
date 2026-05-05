"""
Configuration for the Game-Theoretic Threat Estimator module.
All tuneable parameters are centralized here.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple


@dataclass
class EstimatorConfig:
    """
    Configuration for the Game-Theoretic Threat Estimator.

    Controls the Stackelberg game model, Bayesian cold-start prior,
    adaptive threshold behaviour, and impact/DSR heuristics.
    """

    # ── Impact model weights (see v3 notebook §2.1) ────────────────────
    alpha: float = 0.5        # reputation → I_prime
    beta: float = 0.3         # zone risk → I_prime
    gamma: float = 0.2        # history → DSR degradation
    delta: float = 0.0        # threat-intel boost → DSR (0 until wired)
    eps: float = 1e-3         # clamp epsilon for probabilities

    # ── Threat-score mapping (see v3 notebook §4) ──────────────────────
    kappa: float = 0.8        # sigmoid scale on raw utility
    lambda_blend: float = 0.9 # model-vs-reputation blend

    # ── Defender / attacker model (see v3 notebook §3) ─────────────────
    defender_strategies: Tuple[str, ...] = ("signature", "ml", "sandbox")
    attacker_actions: Tuple[str, ...] = ("inject", "no_inject")
    DSR_base: Dict[str, float] = field(default_factory=lambda: {
        "signature": 0.70,
        "ml":        0.85,
        "sandbox":   0.95,
    })
    C_d: Dict[str, float] = field(default_factory=lambda: {
        "signature": 1.0,
        "ml":        3.0,
        "sandbox":   6.0,
    })
    C_a: Dict[str, float] = field(default_factory=lambda: {
        "inject":    2.0,
        "no_inject": 0.0,
    })

    # ── Inspection thresholds (see v3 notebook §8) ─────────────────────
    th_low: float = 0.40
    th_high: float = 0.70
    adaptive_thresholds: bool = True
    FPR_target: float = 0.05
    FNR_target: float = 0.03
    eta: float = 0.10
    threshold_low_min: float = 0.20
    threshold_low_max: float = 0.50
    threshold_high_min: float = 0.55
    threshold_high_max: float = 0.85
    threshold_min_gap: float = 0.10

    # ── Bayesian cold-start prior (see v3 notebook §7) ─────────────────
    prior_benign: float = 0.85

    # ── Reputation update (see v3 notebook §7.6) ───────────────────────
    reward_rate: float = 0.05
    penalty_rate: float = 0.50
    default_reputation: float = 0.80   # fallback when Bayesian cannot score

    # ── Base impact heuristics (see v3 notebook §2.1) ──────────────────
    type_risk: Dict[str, float] = field(default_factory=lambda: {
        "telemetry": 0.10,
        "text":      0.20,
        "image":     0.50,
        "video":     0.90,
        "archive":   0.80,
        "zip":       0.80,
        "pdf":       0.60,
        "audio":     0.40,
        "other":     0.40,
    })
    I_base_min: float = 0.0
    I_base_max: float = 10.0

    # ── Zone risk ──────────────────────────────────────────────────────
    default_zone_risk: float = 0.5
    zone_risk_lookup: Dict[str, float] = field(default_factory=dict)

    # ── Insecure-flag impact bumps (from ingestion interceptor) ────────
    # Each flag present on a submission adds the listed delta to I_base.
    flag_impact_bumps: Dict[str, float] = field(default_factory=lambda: {
        "encrypted_payload":  1.0,
        "nested_archive":     0.8,
        "unknown_signature":  0.5,
        "large_binary":       0.5,
        "auth_failed":        1.5,
        "checksum_failed":    1.0,
        "suspicious_mime":    0.7,
        "suspicious_ext":     0.7,
    })

    # Auth results from the ingestion interceptor that should reduce R.
    unsafe_auth_results: Set[str] = field(default_factory=lambda: {"fail", "failed"})

    # ── Logging ────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Bounded caches ─────────────────────────────────────────────────
    # Max number of drones kept in the "last estimate" LRU cache used by
    # record_outcome() to seed reputation updates for cold-start drones.
    estimate_cache_max_size: int = 1024

    # ──────────────────────────────────────────────────────────────────
    # Internal consistency checks. Fail fast on construction so
    # mis-configured deployments never produce silently wrong estimates.
    # ──────────────────────────────────────────────────────────────────
    def __post_init__(self) -> None:
        for s in self.defender_strategies:
            if s not in self.DSR_base:
                raise ValueError(f"DSR_base missing entry for defender strategy {s!r}")
            if s not in self.C_d:
                raise ValueError(f"C_d missing entry for defender strategy {s!r}")
        for a in self.attacker_actions:
            if a not in self.C_a:
                raise ValueError(f"C_a missing entry for attacker action {a!r}")
        if not 0.0 <= self.th_low < self.th_high <= 1.0:
            raise ValueError(
                f"need 0 <= th_low < th_high <= 1; got {self.th_low}, {self.th_high}"
            )
        if self.threshold_low_min > self.threshold_low_max:
            raise ValueError("threshold_low_min must be <= threshold_low_max")
        if self.threshold_high_min > self.threshold_high_max:
            raise ValueError("threshold_high_min must be <= threshold_high_max")
        if not 0.0 < self.prior_benign < 1.0:
            raise ValueError(f"prior_benign must be in (0, 1); got {self.prior_benign}")
        if not 0.0 <= self.reward_rate <= 1.0:
            raise ValueError(f"reward_rate must be in [0, 1]; got {self.reward_rate}")
        if not 0.0 <= self.penalty_rate <= 1.0:
            raise ValueError(f"penalty_rate must be in [0, 1]; got {self.penalty_rate}")
        if self.eta < 0.0:
            raise ValueError(f"eta must be >= 0; got {self.eta}")
        if self.estimate_cache_max_size < 1:
            raise ValueError(
                f"estimate_cache_max_size must be >= 1; got {self.estimate_cache_max_size}"
            )
