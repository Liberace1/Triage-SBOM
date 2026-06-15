"""OSV lookup behind an interface.

The pipeline depends only on the abstract `OSVClient`. Two implementations:

  - `OfflineOSVClient`  - reads CVEs from a bundled JSON fixture (no network).
  - `LiveOSVClient`     - queries the real OSV API and writes a write-through
                          cache in the same fixture format, so a later
                          `--offline` run reads straight from that cache.

Both produce the same `OSVMatch` records, so swapping them never changes the
rest of the pipeline.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from triagesbom.cvss import base_score_from_vector, qualitative_to_score
from triagesbom.models import Component

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class OSVMatch:
    """One CVE OSV reports for a component, with its CVSS base score."""

    cve_id: str
    cvss: float


def _component_key(component: Component) -> str:
    """Cache/fixture key: lower-case 'name@version'."""
    return f"{component.name}@{component.version}".lower()


class OSVClient(ABC):
    """Look up known vulnerabilities for a component."""

    @abstractmethod
    def query(self, component: Component) -> list[OSVMatch]:
        """Return the CVEs affecting this component (empty list if clean)."""


# --- OSV response normalization ---

def _preferred_cve_id(vuln: dict[str, Any]) -> str:
    """Pick a CVE id for a vuln: its own id if a CVE, else a CVE alias, else id."""
    vuln_id = str(vuln.get("id", ""))
    if vuln_id.upper().startswith("CVE-"):
        return vuln_id
    for alias in vuln.get("aliases", []) or []:
        if str(alias).upper().startswith("CVE-"):
            return str(alias)
    return vuln_id  # fall back to the OSV id (e.g. a GHSA-...)


def _best_cvss(vuln: dict[str, Any]) -> float:
    """Best CVSS base score for a vuln from its CVSS_V3 vector(s), with fallback."""
    best = 0.0
    for sev in vuln.get("severity", []) or []:
        if str(sev.get("type", "")).upper().startswith("CVSS_V3"):
            best = max(best, base_score_from_vector(str(sev.get("score", ""))))
    if best == 0.0:
        # Fall back to a qualitative rating if OSV provides one.
        rating = (vuln.get("database_specific") or {}).get("severity", "")
        best = qualitative_to_score(str(rating))
    return best


def parse_osv_response(payload: dict[str, Any]) -> list[OSVMatch]:
    """Turn an OSV /v1/query response into OSVMatch records (deduped by CVE)."""
    matches: dict[str, float] = {}
    for vuln in payload.get("vulns", []) or []:
        cve_id = _preferred_cve_id(vuln)
        if not cve_id:
            continue
        cvss = _best_cvss(vuln)
        # Keep the highest CVSS if the same CVE appears more than once.
        matches[cve_id] = max(matches.get(cve_id, 0.0), cvss)
    return [OSVMatch(cve_id=c, cvss=v) for c, v in matches.items()]


# --- offline client ---

class OfflineOSVClient(OSVClient):
    """Fixture-backed OSV client. No network, no API key.

    The fixture is a JSON object keyed by "name@version" (case-insensitive
    name), each mapping to a list of {"cve_id", "cvss"} records.
    """

    def __init__(self, fixture_path: str | Path) -> None:
        path = Path(fixture_path)
        if not path.is_file():
            raise FileNotFoundError(f"Offline OSV fixture not found: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        self._db: dict[str, list[OSVMatch]] = {}
        for key, entries in raw.items():
            if key.startswith("_"):
                continue  # skip metadata keys like "_comment"
            self._db[key.lower()] = [
                OSVMatch(cve_id=e["cve_id"], cvss=float(e.get("cvss", 0.0)))
                for e in entries
            ]

    def query(self, component: Component) -> list[OSVMatch]:
        return list(self._db.get(_component_key(component), []))


# --- live client with write-through cache ---

# A transport takes a component and returns the raw OSV JSON payload.
Transport = Callable[[Component], dict[str, Any]]


class LiveOSVClient(OSVClient):
    """Query the real OSV API, caching every response to a fixture file.

    The cache file uses the same format as the offline fixture, so a subsequent
    `--offline --osv-fixture <cache>` run needs no network. A custom `transport`
    can be injected for testing without hitting the network.
    """

    def __init__(
        self,
        cache_path: str | Path,
        transport: Transport | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._cache_path = Path(cache_path)
        self._timeout = timeout
        self._transport = transport or self._http_query
        self._cache: dict[str, list[OSVMatch]] = {}
        if self._cache_path.is_file():
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            for key, entries in raw.items():
                if key.startswith("_"):
                    continue
                self._cache[key.lower()] = [
                    OSVMatch(cve_id=e["cve_id"], cvss=float(e.get("cvss", 0.0)))
                    for e in entries
                ]

    def _http_query(self, component: Component) -> dict[str, Any]:
        import requests  # lazy import: offline runs never need it

        if component.purl:
            body: dict[str, Any] = {"package": {"purl": component.purl}}
        elif component.ecosystem:
            body = {
                "package": {"name": component.name, "ecosystem": component.ecosystem},
                "version": component.version,
            }
        else:
            # No ecosystem/purl: best-effort name+version query.
            body = {"package": {"name": component.name}, "version": component.version}
        resp = requests.post(OSV_QUERY_URL, json=body, timeout=self._timeout)
        resp.raise_for_status()
        return resp.json()

    def _write_cache(self) -> None:
        serializable = {
            key: [{"cve_id": m.cve_id, "cvss": m.cvss} for m in matches]
            for key, matches in sorted(self._cache.items())
        }
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache_path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")

    def query(self, component: Component) -> list[OSVMatch]:
        key = _component_key(component)
        if key in self._cache:
            return list(self._cache[key])
        matches = parse_osv_response(self._transport(component))
        self._cache[key] = matches
        self._write_cache()
        return list(matches)
