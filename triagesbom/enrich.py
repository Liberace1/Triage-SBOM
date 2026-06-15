"""Enrichment: attach EPSS probability and CISA KEV flag to a CVE.

Two ways in, same on-disk formats either way:
  - Offline: `EPSSData`/`KEVData` read bundled snapshot files (no network).
  - Live:    `fetch_epss()` / `download_kev()` pull from the public sources and
             write a dated local cache that the offline loaders then read.

Public sources (free, no API key):
  - EPSS: FIRST.org API   https://api.first.org/data/v1/epss?cve=...   (JSON)
          cached as CSV    (cve,epss,percentile  with a #fetch_date header)
  - KEV:  CISA feed JSON   .../known_exploited_vulnerabilities.json
          cached slimmed   ({"dateReleased":..., "vulnerabilities":[{"cveID"}]})
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_BATCH = 100  # FIRST API accepts a comma-separated batch of CVEs per call


class EPSSData:
    """CVE -> EPSS probability, loaded from a FIRST.org-style CSV snapshot."""

    def __init__(self, csv_path: str | Path) -> None:
        path = Path(csv_path)
        if not path.is_file():
            raise FileNotFoundError(f"EPSS snapshot not found: {path}")
        self._scores: dict[str, float] = {}
        with path.open(encoding="utf-8", newline="") as fh:
            for row in csv.reader(fh):
                if not row or row[0].startswith("#") or row[0].lower() == "cve":
                    continue  # skip model-version header, column header, blanks
                try:
                    self._scores[row[0].upper()] = float(row[1])
                except (IndexError, ValueError):
                    continue

    def probability(self, cve_id: str) -> float:
        """EPSS probability 0.0-1.0 for a CVE (0.0 if not in the snapshot)."""
        return self._scores.get(cve_id.upper(), 0.0)


class KEVData:
    """Set of CVE IDs in the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, json_path: str | Path) -> None:
        path = Path(json_path)
        if not path.is_file():
            raise FileNotFoundError(f"KEV snapshot not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        self._cves: set[str] = {
            str(v["cveID"]).upper() for v in data.get("vulnerabilities", [])
        }

    def is_listed(self, cve_id: str) -> bool:
        """True if the CVE is actively exploited per the CISA KEV catalog."""
        return cve_id.upper() in self._cves


# --- live download + cache ---

# Transports are injectable so the cache logic can be tested without network.
EpssTransport = Callable[[list[str]], list[dict]]  # cve_ids -> [{"cve","epss","percentile"}, ...]
KevTransport = Callable[[], dict]                   # -> raw CISA KEV JSON


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _http_epss(cve_ids: list[str]) -> list[dict]:
    """Query the FIRST EPSS API for the given CVEs (batched)."""
    import requests  # lazy import: offline runs never need it

    out: list[dict] = []
    for i in range(0, len(cve_ids), _EPSS_BATCH):
        batch = cve_ids[i : i + _EPSS_BATCH]
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": ",".join(batch), "limit": len(batch)},
            timeout=30,
        )
        resp.raise_for_status()
        out.extend(resp.json().get("data", []))
    return out


def _http_kev() -> dict:
    import requests  # lazy import

    resp = requests.get(KEV_FEED_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _read_epss_cache(path: Path) -> dict[str, tuple[str, str]]:
    """Load an existing EPSS cache CSV -> {CVE: (epss, percentile)}."""
    scores: dict[str, tuple[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0].lower() == "cve":
                continue
            if len(row) >= 2:
                scores[row[0].upper()] = (row[1], row[2] if len(row) > 2 else "")
    return scores


def _write_epss_cache(path: Path, scores: dict[str, tuple[str, str]]) -> None:
    lines = [
        f"#fetch_date:{_today()},source:api.first.org/data/v1/epss",
        "cve,epss,percentile",
    ]
    for cve in sorted(scores):
        epss, pct = scores[cve]
        lines.append(f"{cve},{epss},{pct}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def fetch_epss(
    cve_ids: list[str],
    cache_path: str | Path,
    transport: EpssTransport | None = None,
    refresh: bool = False,
) -> EPSSData:
    """Ensure EPSS scores for `cve_ids` are in the cache, fetching any missing.

    Reuses already-cached CVEs (unless `refresh`), fetches only the gaps, and
    rewrites the dated cache CSV. Returns an `EPSSData` reading that cache.
    """
    path = Path(cache_path)
    existing: dict[str, tuple[str, str]] = {}
    if path.is_file() and not refresh:
        existing = _read_epss_cache(path)

    wanted = list(dict.fromkeys(c.upper() for c in cve_ids))  # dedupe, keep order
    missing = wanted if refresh else [c for c in wanted if c not in existing]
    if missing:
        transport = transport or _http_epss
        for rec in transport(missing):
            cve = str(rec.get("cve", "")).upper()
            if cve:
                existing[cve] = (str(rec.get("epss", "0")), str(rec.get("percentile", "")))

    _write_epss_cache(path, existing)
    return EPSSData(path)


def download_kev(
    cache_path: str | Path,
    transport: KevTransport | None = None,
    refresh: bool = False,
) -> KEVData:
    """Download the CISA KEV catalog into a slimmed, dated local cache.

    Uses the existing cache if present (unless `refresh`). The cache keeps only
    the metadata + cveIDs the tool needs, so it stays small.
    """
    path = Path(cache_path)
    if path.is_file() and not refresh:
        return KEVData(path)

    transport = transport or _http_kev
    data = transport()
    slim = {
        "title": data.get("title", "CISA Known Exploited Vulnerabilities (cached)"),
        "catalogVersion": data.get("catalogVersion", ""),
        "dateReleased": data.get("dateReleased", ""),
        "fetch_date": _today(),
        "count": len(data.get("vulnerabilities", [])),
        "vulnerabilities": [
            {"cveID": v["cveID"]} for v in data.get("vulnerabilities", []) if v.get("cveID")
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(slim, indent=2), encoding="utf-8")
    return KEVData(path)
