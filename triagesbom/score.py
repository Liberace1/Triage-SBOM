"""Transparent, config-driven weighted scoring + per-finding reason strings.

    risk = (kev_boost if KEV else 0)
         + epss_weight * epss              # epss is 0..1
         + cvss_weight * (cvss / 10)       # cvss normalized to 0..1

KEV membership is a hard escalator: kev_boost is set larger than the maximum
possible non-KEV contribution (epss_weight + cvss_weight), so any KEV-listed
CVE always ranks above any non-KEV CVE.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from triagesbom.models import Finding

DEFAULT_WEIGHTS_PATH = Path(__file__).resolve().parent.parent / "config" / "weights.json"


@dataclass(frozen=True)
class Weights:
    kev_boost: float = 100.0
    epss_weight: float = 30.0
    cvss_weight: float = 20.0

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Weights":
        weights_path = Path(path) if path else DEFAULT_WEIGHTS_PATH
        data = json.loads(weights_path.read_text(encoding="utf-8"))
        return cls(
            kev_boost=float(data.get("kev_boost", cls.kev_boost)),
            epss_weight=float(data.get("epss_weight", cls.epss_weight)),
            cvss_weight=float(data.get("cvss_weight", cls.cvss_weight)),
        )


def _format_epss(epss: float) -> str:
    """Percent string; keep a decimal for small values so it isn't '0%'."""
    return f"EPSS {epss:.1%}" if epss < 0.1 else f"EPSS {epss:.0%}"


def _reason(finding: Finding) -> str:
    """One-line, human-readable justification for the score."""
    epss_pct = _format_epss(finding.epss)
    cvss = f"CVSS {finding.cvss:.1f}"
    if finding.kev_flag:
        return f"KEV-listed (actively exploited), {epss_pct}, {cvss} - fix immediately"
    if finding.epss >= 0.5:
        return f"Not in KEV but {epss_pct} exploit probability, {cvss} - high exploit likelihood"
    if finding.cvss >= 9.0:
        return f"Critical severity {cvss} but low exploit probability ({epss_pct}) - patch on schedule"
    return f"{cvss}, {epss_pct} - lower priority"


def score_finding(finding: Finding, weights: Weights) -> Finding:
    """Compute the risk score and reason for a finding (mutates and returns it)."""
    risk = (
        (weights.kev_boost if finding.kev_flag else 0.0)
        + weights.epss_weight * finding.epss
        + weights.cvss_weight * (finding.cvss / 10.0)
    )
    finding.score = round(risk, 2)
    finding.reason = _reason(finding)
    return finding


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted highest-risk first (stable tiebreak on CVE id)."""
    return sorted(findings, key=lambda f: (f.score, f.cve_id), reverse=True)
