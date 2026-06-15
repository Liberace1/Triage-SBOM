"""End-to-end pipeline: SBOM -> CVEs -> enrich -> score -> ranked findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from triagesbom.enrich import EPSSData, KEVData, download_kev, fetch_epss
from triagesbom.models import Component, Finding
from triagesbom.osv_client import LiveOSVClient, OfflineOSVClient, OSVClient
from triagesbom.sbom import parse_cyclonedx
from triagesbom.score import Weights, rank_findings, score_finding

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
DEFAULT_SBOM = FIXTURES_DIR / "sample.cdx.json"
DEFAULT_OSV_FIXTURE = FIXTURES_DIR / "osv_offline.json"
DEFAULT_OSV_CACHE = FIXTURES_DIR / "osv_cache.json"
DEFAULT_EPSS_FIXTURE = FIXTURES_DIR / "epss_snapshot.csv"
DEFAULT_KEV_FIXTURE = FIXTURES_DIR / "kev_snapshot.json"
DEFAULT_EPSS_CACHE = FIXTURES_DIR / "epss_cache.csv"
DEFAULT_KEV_CACHE = FIXTURES_DIR / "kev_cache.json"


@dataclass
class PipelineResult:
    components: list[Component]
    findings: list[Finding]


def build_findings(
    components: list[Component],
    osv: OSVClient,
    epss: EPSSData,
    kev: KEVData,
    weights: Weights,
) -> list[Finding]:
    """Look up, enrich, and score every CVE across all components."""
    findings: list[Finding] = []
    for component in components:
        for match in osv.query(component):
            finding = Finding(
                component=component,
                cve_id=match.cve_id,
                cvss=match.cvss,
                epss=epss.probability(match.cve_id),
                kev_flag=kev.is_listed(match.cve_id),
            )
            findings.append(score_finding(finding, weights))
    return rank_findings(findings)


def _run(
    sbom_path: str | Path,
    osv: OSVClient,
    epss_fixture: str | Path,
    kev_fixture: str | Path,
    weights_path: str | Path | None,
) -> PipelineResult:
    components = parse_cyclonedx(sbom_path)
    epss = EPSSData(epss_fixture)
    kev = KEVData(kev_fixture)
    weights = Weights.load(weights_path)
    findings = build_findings(components, osv, epss, kev, weights)
    return PipelineResult(components=components, findings=findings)


def run_offline(
    sbom_path: str | Path = DEFAULT_SBOM,
    osv_fixture: str | Path = DEFAULT_OSV_FIXTURE,
    epss_fixture: str | Path = DEFAULT_EPSS_FIXTURE,
    kev_fixture: str | Path = DEFAULT_KEV_FIXTURE,
    weights_path: str | Path | None = None,
) -> PipelineResult:
    """Run the full pipeline using only bundled offline fixtures (no network)."""
    return _run(sbom_path, OfflineOSVClient(osv_fixture), epss_fixture, kev_fixture, weights_path)


def run_live(
    sbom_path: str | Path = DEFAULT_SBOM,
    osv_cache: str | Path = DEFAULT_OSV_CACHE,
    epss_cache: str | Path = DEFAULT_EPSS_CACHE,
    kev_cache: str | Path = DEFAULT_KEV_CACHE,
    weights_path: str | Path | None = None,
    refresh: bool = False,
) -> PipelineResult:
    """Run with live OSV + EPSS + KEV, caching all three to dated local files.

    OSV is queried per component; the resulting CVE set is then enriched with
    live EPSS (FIRST API) and live KEV (CISA feed). Every response is cached so a
    later `--offline` run reproduces the result with no network. `refresh=True`
    re-downloads EPSS/KEV even if a cache exists.
    """
    components = parse_cyclonedx(sbom_path)
    osv = LiveOSVClient(osv_cache)
    # First pass: gather all CVEs (also warms the OSV in-memory cache).
    cve_ids = sorted({m.cve_id for c in components for m in osv.query(c)})
    kev = download_kev(kev_cache, refresh=refresh)
    epss = fetch_epss(cve_ids, epss_cache, refresh=refresh)
    weights = Weights.load(weights_path)
    findings = build_findings(components, osv, epss, kev, weights)
    return PipelineResult(components=components, findings=findings)
