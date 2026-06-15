"""Ranking-invariant tests: prove the scoring is smarter than a CVSS-only sort."""

from __future__ import annotations

from pathlib import Path

import pytest

from triagesbom.models import Component, Finding
from triagesbom.pipeline import run_offline
from triagesbom.score import Weights, rank_findings, score_finding

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def result():
    return run_offline()


def _by_cve(findings: list[Finding]) -> dict[str, Finding]:
    return {f.cve_id: f for f in findings}


def test_clean_components_produce_no_findings(result):
    """flask, left-pad, zlib have no CVEs -> they appear in no finding."""
    components_with_findings = {f.component.name for f in result.findings}
    assert "flask" not in components_with_findings
    assert "left-pad" not in components_with_findings
    assert "zlib" not in components_with_findings


def test_every_finding_has_a_reason(result):
    assert result.findings
    assert all(f.reason for f in result.findings)


def test_kev_ranks_above_non_kev(result):
    """Every KEV-listed finding must outrank every non-KEV finding."""
    findings = result.findings
    last_kev = max(i for i, f in enumerate(findings) if f.kev_flag)
    first_non_kev = min(i for i, f in enumerate(findings) if not f.kev_flag)
    assert last_kev < first_non_kev


def test_equal_cvss_higher_epss_ranks_higher(result):
    """jackson-databind and axios both have CVSS 7.5; higher EPSS wins."""
    by_cve = _by_cve(result.findings)
    jackson = by_cve["CVE-2019-12384"]  # CVSS 7.5, EPSS higher
    axios = by_cve["CVE-2021-3749"]     # CVSS 7.5, EPSS lower
    assert jackson.cvss == axios.cvss == 7.5
    assert jackson.epss > axios.epss
    assert jackson.score > axios.score


def test_high_epss_low_cvss_beats_high_cvss_low_epss(result):
    """The whole point: an actively-exploited low-CVSS CVE outranks a
    theoretical critical that nobody is exploiting."""
    by_cve = _by_cve(result.findings)
    actively_exploited = by_cve["CVE-2023-31001"]  # CVSS 4.3, EPSS 0.88
    theoretical_crit = by_cve["CVE-2022-42889"]    # CVSS 9.8, EPSS 0.018
    assert actively_exploited.cvss < theoretical_crit.cvss
    assert actively_exploited.score > theoretical_crit.score
    # A naive CVSS-only sort would have inverted these two.


def test_kev_boost_is_a_hard_escalator():
    """A KEV CVE with the worst possible EPSS/CVSS still beats the best non-KEV."""
    w = Weights()
    comp = Component(name="x", version="1", ecosystem="")
    worst_kev = score_finding(
        Finding(component=comp, cve_id="CVE-0000-0001", cvss=0.0, epss=0.0, kev_flag=True), w
    )
    best_non_kev = score_finding(
        Finding(component=comp, cve_id="CVE-0000-0002", cvss=10.0, epss=1.0, kev_flag=False), w
    )
    assert worst_kev.score > best_non_kev.score


def test_findings_are_sorted_descending(result):
    scores = [f.score for f in result.findings]
    assert scores == sorted(scores, reverse=True)


def test_rank_findings_orders_by_score():
    comp = Component(name="x", version="1", ecosystem="")
    a = Finding(component=comp, cve_id="CVE-A", cvss=0, epss=0, kev_flag=False, score=5.0)
    b = Finding(component=comp, cve_id="CVE-B", cvss=0, epss=0, kev_flag=False, score=50.0)
    assert [f.cve_id for f in rank_findings([a, b])] == ["CVE-B", "CVE-A"]
