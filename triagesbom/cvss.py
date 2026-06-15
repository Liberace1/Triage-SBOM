"""CVSS v3.x base-score computation from a vector string.

OSV reports severity as a CVSS *vector* (e.g. "CVSS:3.1/AV:N/AC:L/...") rather
than a numeric base score, so the base score is derived from the vector here
using the official CVSS v3.0/v3.1 base-score formula. Non-v3 vectors and
qualitative ratings fall back to a coarse numeric map.
"""

from __future__ import annotations

import math

# Metric value tables (CVSS v3.1 specification, section 7.4).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

# Coarse fallback for qualitative ratings (no vector available).
_QUALITATIVE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "MODERATE": 5.5, "LOW": 3.0, "NONE": 0.0}


def _roundup(value: float) -> float:
    """Official CVSS v3.1 Roundup: round up to the nearest 0.1."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _parse_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, _, val = part.partition(":")
            metrics[key.strip().upper()] = val.strip().upper()
    return metrics


def base_score_from_vector(vector: str) -> float:
    """Compute a CVSS v3.x base score from its vector string (0.0 if unparseable)."""
    if not vector:
        return 0.0
    m = _parse_metrics(vector)
    if m.get("CVSS") not in ("3.0", "3.1"):
        return 0.0
    try:
        scope_changed = m["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
    except KeyError:
        return 0.0

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) if not scope_changed else 1.08 * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def qualitative_to_score(rating: str) -> float:
    """Map a qualitative severity word (HIGH, CRITICAL, ...) to a coarse score."""
    return _QUALITATIVE.get(rating.strip().upper(), 0.0)
