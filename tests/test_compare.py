"""Slice 5 tests: risk ranking vs. naive CVSS-only sort."""

from __future__ import annotations

from triagesbom.compare import build_comparison, cvss_only_order, headline_burial
from triagesbom.pipeline import run_offline


def _by_cve(deltas):
    return {d.finding.cve_id: d for d in deltas}


def test_cvss_only_order_is_by_cvss_desc():
    result = run_offline()
    ordered = cvss_only_order(result.findings)
    cvss_values = [f.cvss for f in ordered]
    assert cvss_values == sorted(cvss_values, reverse=True)


def test_actively_exploited_low_cvss_is_promoted():
    """The crafted demo's headline: webadmin-ui (CVSS 4.3, EPSS 88%) is near the
    bottom by CVSS but near the top by risk."""
    result = run_offline()
    deltas = _by_cve(build_comparison(result.findings))
    webadmin = deltas["CVE-2023-31001"]
    assert webadmin.cvss_rank > webadmin.risk_rank  # risk ranking promoted it
    assert webadmin.move > 0
    # CVSS-only would bury it: 4.3 is the lowest CVSS, so it sorts last.
    assert webadmin.cvss_rank == len(result.findings)


def test_theoretical_critical_is_demoted():
    """commons-text (CVSS 9.8, EPSS 1.8%) loses ground to exploited issues."""
    result = run_offline()
    deltas = _by_cve(build_comparison(result.findings))
    openssl = deltas["CVE-2022-3602"]  # CVSS 9.8 but EPSS ~0.4%
    assert openssl.risk_rank > openssl.cvss_rank  # risk ranking demoted it
    assert openssl.move < 0


def test_ranks_are_complete_and_unique():
    result = run_offline()
    deltas = build_comparison(result.findings)
    n = len(result.findings)
    assert sorted(d.risk_rank for d in deltas) == list(range(1, n + 1))
    assert sorted(d.cvss_rank for d in deltas) == list(range(1, n + 1))


def test_risk_rank_matches_input_order():
    result = run_offline()
    deltas = build_comparison(result.findings)
    for i, d in enumerate(deltas, start=1):
        assert d.risk_rank == i
        assert d.finding is result.findings[i - 1]


def test_headline_burial_picks_most_promoted_exploited_cve():
    result = run_offline()
    deltas = build_comparison(result.findings)
    burial = headline_burial(deltas)
    assert burial is not None
    # In the crafted demo, the most-promoted exploited CVE is webadmin-ui.
    assert burial.finding.cve_id == "CVE-2023-31001"


def test_headline_burial_none_when_no_reordering():
    result = run_offline()
    # Strip EPSS/KEV signal so nothing is "actively exploited".
    flat = []
    for f in result.findings:
        f.epss = 0.0
        f.kev_flag = False
        flat.append(f)
    assert headline_burial(build_comparison(flat)) is None
