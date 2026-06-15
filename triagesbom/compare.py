"""Compare the risk ranking against a naive CVSS-only sort.

This is the demo's whole point: show that ranking by CVSS alone buries CVEs that
are actually being exploited (high EPSS / KEV-listed) under theoretical criticals
nobody is attacking.
"""

from __future__ import annotations

from dataclasses import dataclass

from triagesbom.models import Finding


def _key(f: Finding) -> tuple[str, str, str]:
    return (f.component.name, f.component.version, f.cve_id)


@dataclass(frozen=True)
class RankDelta:
    """One finding's position in the risk ranking vs. the CVSS-only ranking."""

    finding: Finding
    risk_rank: int
    cvss_rank: int

    @property
    def move(self) -> int:
        """Places the risk ranking moved it up (+) or down (-) vs CVSS-only."""
        return self.cvss_rank - self.risk_rank


def cvss_only_order(findings: list[Finding]) -> list[Finding]:
    """A naive CVSS-only sort: highest CVSS first (deterministic tiebreak)."""
    return sorted(findings, key=lambda f: (-f.cvss, f.cve_id))


def build_comparison(ranked_findings: list[Finding]) -> list[RankDelta]:
    """Pair each finding's risk rank with its CVSS-only rank (risk order kept)."""
    risk_rank = {_key(f): i for i, f in enumerate(ranked_findings, start=1)}
    cvss_rank = {_key(f): i for i, f in enumerate(cvss_only_order(ranked_findings), start=1)}
    return [
        RankDelta(finding=f, risk_rank=risk_rank[_key(f)], cvss_rank=cvss_rank[_key(f)])
        for f in ranked_findings
    ]


def headline_burial(deltas: list[RankDelta]) -> RankDelta | None:
    """The most striking case: an actively-exploited CVE that CVSS-only demotes.

    Returns the KEV-listed or high-EPSS finding the risk ranking promoted the
    most over the CVSS-only sort, or None if nothing was reordered that way.
    """
    candidates = [
        d for d in deltas
        if d.move > 0 and (d.finding.kev_flag or d.finding.epss >= 0.5)
    ]
    return max(candidates, key=lambda d: d.move) if candidates else None
