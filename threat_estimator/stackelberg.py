"""
Stackelberg game solver for the threat estimator.

Computes the adjusted impact (`I'`) and detection success rates
(`DSR'`), builds the defender/attacker payoff matrices, and resolves
the pure-strategy Stackelberg equilibrium with the defender as leader.

Formulas match Game_theoretic_threat_estimator_v3.ipynb §2 – §4.
"""

import math
from typing import Dict, List, Tuple

from .models import EquilibriumResult, PayoffMatrix


# ── Primitive helpers ───────────────────────────────────────────────

def clamp(x: float, lo: float = 1e-3, hi: float = 1.0 - 1e-3) -> float:
    return max(lo, min(hi, x))


def sigmoid(x: float) -> float:
    # Guard against overflow for large negative inputs.
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


# ── Adjusted impact / DSR ───────────────────────────────────────────

def compute_I_prime(
    I_base: float,
    reputation: float,
    zone_risk: float,
    alpha: float = 0.5,
    beta: float = 0.3,
) -> float:
    """
    Adjusted impact:

        I' = I_base · (1 + α(1 - R)) · (1 + β·Z)

    Higher I_base, lower R, or higher Z all push I' up multiplicatively.
    """
    return I_base * (1.0 + alpha * (1.0 - reputation)) * (1.0 + beta * zone_risk)


def compute_DSR_primes(
    DSR_base: Dict[str, float],
    history: float,
    threat_intel: float = 0.0,
    gamma: float = 0.2,
    delta: float = 0.0,
    eps: float = 1e-3,
) -> Dict[str, float]:
    """
    Adjusted detection success rate per defender strategy:

        DSR'(s) = clamp( DSR(s) · (1 - γ·H) · (1 + δ·TI), ε, 1-ε )

    History H degrades DSR (evasion rate). Threat-intel TI (if wired)
    boosts DSR when corroborating IOCs are present.
    """
    out: Dict[str, float] = {}
    for s, base in DSR_base.items():
        adjusted = base * (1.0 - gamma * history) * (1.0 + delta * threat_intel)
        out[s] = clamp(adjusted, eps, 1.0 - eps)
    return out


# ── Payoff matrices ─────────────────────────────────────────────────

def build_payoff_matrices(
    I_prime: float,
    DSR_prime: Dict[str, float],
    C_d: Dict[str, float],
    C_a: Dict[str, float],
    defender_strategies: Tuple[str, ...],
    attacker_actions: Tuple[str, ...],
) -> PayoffMatrix:
    """
    Build defender (U_d) and attacker (U_a) payoffs using the conservative
    no_inject rule from §3.1 of the v3 notebook:

        U_a(s, inject)    = (1 - DSR'(s)) · I'  - C_a(inject)
        U_a(s, no_inject) = 0
        U_d(s, inject)    = DSR'(s) · I'  - C_d(s)
        U_d(s, no_inject) = - C_d(s)          # only pays inspection cost
    """
    U_a: List[List[float]] = []
    U_d: List[List[float]] = []

    for s in defender_strategies:
        dsr = DSR_prime[s]
        asp = 1.0 - dsr
        row_a: List[float] = []
        row_d: List[float] = []
        for a in attacker_actions:
            if a == "no_inject":
                ua = 0.0
                ud = -C_d[s]
            else:
                ua = asp * I_prime - C_a.get(a, 0.0)
                ud = dsr * I_prime - C_d[s]
            row_a.append(round(ua, 6))
            row_d.append(round(ud, 6))
        U_a.append(row_a)
        U_d.append(row_d)

    return PayoffMatrix(
        defender_strategies=list(defender_strategies),
        attacker_actions=list(attacker_actions),
        U_d=U_d,
        U_a=U_a,
    )


# ── Stackelberg solver (pure strategies, defender-as-leader) ────────

def solve_stackelberg_pure(
    payoffs: PayoffMatrix,
    C_d: Dict[str, float],
    tie_epsilon: float = 1e-12,
) -> EquilibriumResult:
    """
    Defender-as-leader pure-strategy Stackelberg equilibrium.

    1. For each defender strategy s, compute the attacker's best response
       a*(s) = argmax_a U_a(s, a). On ties, the attacker picks the action
       that hurts the defender most (i.e. minimises U_d).
    2. Defender picks s* = argmax_s U_d(s, a*(s)). On ties among defender
       strategies, prefer the cheaper one (lowest C_d).

    Complexity: O(|S_d| · |S_a|).
    """
    if not payoffs.U_a or not payoffs.U_a[0]:
        raise ValueError("empty payoff matrices")

    best_def = None

    for i, row_a in enumerate(payoffs.U_a):
        # Attacker best response for this defender row.
        max_ua = max(row_a)
        candidates = [j for j, v in enumerate(row_a) if abs(v - max_ua) < tie_epsilon]
        if len(candidates) == 1:
            j_best = candidates[0]
        else:
            j_best = min(candidates, key=lambda j: payoffs.U_d[i][j])
        ua = row_a[j_best]
        ud = payoffs.U_d[i][j_best]

        s_name = payoffs.defender_strategies[i]

        if best_def is None or ud > best_def["ud"] + tie_epsilon:
            best_def = {"di": i, "aj": j_best, "ud": ud, "ua": ua}
        elif abs(ud - best_def["ud"]) < tie_epsilon:
            best_s = payoffs.defender_strategies[best_def["di"]]
            if C_d.get(s_name, float("inf")) < C_d.get(best_s, float("inf")):
                best_def = {"di": i, "aj": j_best, "ud": ud, "ua": ua}

    assert best_def is not None
    di = best_def["di"]
    aj = best_def["aj"]
    return EquilibriumResult(
        defender_strategy=payoffs.defender_strategies[di],
        attacker_action=payoffs.attacker_actions[aj],
        defender_index=di,
        attacker_index=aj,
        U_d_eq=round(best_def["ud"], 6),
        U_a_eq=round(best_def["ua"], 6),
    )


# ── Threat-score mapping ────────────────────────────────────────────

def compute_threat_score(
    U_a_eq: float,
    U_d_eq: float,
    reputation: float,
    kappa: float = 0.8,
    lambda_blend: float = 0.9,
) -> Tuple[float, float, float]:
    """
    Map equilibrium utilities + reputation to T_S ∈ [0, 1].

        raw   = U_a_eq - U_d_eq
        T_raw = σ(κ · raw)
        T_S   = λ · T_raw + (1-λ) · (1 - R)

    Returns (raw, T_raw, T_S) all in [0, 1] for T_raw and T_S.
    """
    raw = U_a_eq - U_d_eq
    T_raw = sigmoid(kappa * raw)
    T_S = lambda_blend * T_raw + (1.0 - lambda_blend) * (1.0 - reputation)
    T_S = max(0.0, min(1.0, T_S))
    return raw, T_raw, T_S
