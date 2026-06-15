"""Slice 3 tests: live EPSS + KEV download with local cache + dated snapshot.

No network: download functions are driven by injected fake transports.
"""

from __future__ import annotations

import json

from triagesbom.enrich import download_kev, fetch_epss


# --- EPSS ---


class _EpssTransport:
    """Fake FIRST EPSS API: returns canned records, records what was asked."""

    def __init__(self, table: dict[str, float]):
        self.table = table
        self.requested: list[list[str]] = []

    def __call__(self, cve_ids):
        self.requested.append(list(cve_ids))
        return [
            {"cve": c, "epss": str(self.table[c]), "percentile": "0.5"}
            for c in cve_ids
            if c in self.table
        ]


def test_fetch_epss_writes_dated_cache(tmp_path):
    cache = tmp_path / "epss_cache.csv"
    t = _EpssTransport({"CVE-2021-44228": 0.94, "CVE-2022-22965": 0.96})
    epss = fetch_epss(["CVE-2021-44228", "CVE-2022-22965"], cache, transport=t)

    assert epss.probability("CVE-2021-44228") == 0.94
    assert epss.probability("CVE-2022-22965") == 0.96
    text = cache.read_text(encoding="utf-8")
    assert text.startswith("#fetch_date:")  # dated snapshot header
    assert "cve,epss,percentile" in text


def test_fetch_epss_only_fetches_missing_cves(tmp_path):
    cache = tmp_path / "epss_cache.csv"
    t1 = _EpssTransport({"CVE-1": 0.1, "CVE-2": 0.2})
    fetch_epss(["CVE-1", "CVE-2"], cache, transport=t1)
    assert t1.requested == [["CVE-1", "CVE-2"]]

    # Second call: one cached, one new -> only the new one is requested.
    t2 = _EpssTransport({"CVE-3": 0.3})
    epss = fetch_epss(["CVE-1", "CVE-3"], cache, transport=t2)
    assert t2.requested == [["CVE-3"]]          # CVE-1 served from cache
    assert epss.probability("CVE-1") == 0.1     # preserved across runs
    assert epss.probability("CVE-3") == 0.3


def test_fetch_epss_refresh_refetches_all(tmp_path):
    cache = tmp_path / "epss_cache.csv"
    t1 = _EpssTransport({"CVE-1": 0.1})
    fetch_epss(["CVE-1"], cache, transport=t1)
    t2 = _EpssTransport({"CVE-1": 0.9})
    epss = fetch_epss(["CVE-1"], cache, transport=t2, refresh=True)
    assert t2.requested == [["CVE-1"]]
    assert epss.probability("CVE-1") == 0.9     # refreshed value


def test_unknown_cve_scores_zero(tmp_path):
    cache = tmp_path / "epss_cache.csv"
    t = _EpssTransport({"CVE-1": 0.1})
    epss = fetch_epss(["CVE-1"], cache, transport=t)
    assert epss.probability("CVE-9999-0000") == 0.0


# --- KEV ---


def _kev_payload():
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.06.05",
        "dateReleased": "2026-06-05T17:00:14.652Z",
        "count": 2,
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "shortDescription": "..."},
            {"cveID": "CVE-2017-5638", "vendorProject": "Apache", "shortDescription": "..."},
        ],
    }


def test_download_kev_slims_and_caches(tmp_path):
    cache = tmp_path / "kev_cache.json"
    calls = {"n": 0}

    def transport():
        calls["n"] += 1
        return _kev_payload()

    kev = download_kev(cache, transport=transport)
    assert calls["n"] == 1
    assert kev.is_listed("CVE-2021-44228")
    assert kev.is_listed("CVE-2017-5638")
    assert not kev.is_listed("CVE-2000-0000")

    on_disk = json.loads(cache.read_text(encoding="utf-8"))
    assert on_disk["dateReleased"] == "2026-06-05T17:00:14.652Z"
    assert "fetch_date" in on_disk                       # dated snapshot
    # Slimmed: only cveID kept per entry.
    assert on_disk["vulnerabilities"][0] == {"cveID": "CVE-2021-44228"}


def test_download_kev_uses_cache_without_refetch(tmp_path):
    cache = tmp_path / "kev_cache.json"
    calls = {"n": 0}

    def transport():
        calls["n"] += 1
        return _kev_payload()

    download_kev(cache, transport=transport)
    download_kev(cache, transport=transport)   # cache hit
    assert calls["n"] == 1

    download_kev(cache, transport=transport, refresh=True)  # forced
    assert calls["n"] == 2
