"""Slice 2 tests: CVSS scoring, OSV response parsing, live client caching.

No network: the live client is driven by an injected fake transport.
"""

from __future__ import annotations

import json

import pytest

from triagesbom.cvss import base_score_from_vector, qualitative_to_score
from triagesbom.models import Component
from triagesbom.osv_client import (
    LiveOSVClient,
    OfflineOSVClient,
    parse_osv_response,
)

# --- CVSS base-score computation ---


def test_cvss_log4shell_scope_changed_is_10():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert base_score_from_vector(vector) == 10.0


def test_cvss_spring4shell_scope_unchanged_is_9_8():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert base_score_from_vector(vector) == 9.8


def test_cvss_unparseable_returns_zero():
    assert base_score_from_vector("") == 0.0
    assert base_score_from_vector("not-a-vector") == 0.0
    assert base_score_from_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") == 0.0


def test_qualitative_fallback():
    assert qualitative_to_score("CRITICAL") == 9.5
    assert qualitative_to_score("HIGH") == 8.0
    assert qualitative_to_score("unknown") == 0.0


# --- OSV response normalization ---


def test_parse_extracts_cve_from_aliases_and_cvss_from_vector():
    payload = {
        "vulns": [
            {
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": ["CVE-2021-44228"],
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
                ],
            }
        ]
    }
    matches = parse_osv_response(payload)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2021-44228"
    assert matches[0].cvss == 10.0


def test_parse_falls_back_to_qualitative_severity():
    payload = {
        "vulns": [
            {"id": "CVE-2020-0001", "database_specific": {"severity": "HIGH"}}
        ]
    }
    matches = parse_osv_response(payload)
    assert matches[0].cve_id == "CVE-2020-0001"
    assert matches[0].cvss == 8.0


def test_parse_empty_response_is_no_findings():
    assert parse_osv_response({}) == []
    assert parse_osv_response({"vulns": []}) == []


# --- live client write-through cache ---


class _CountingTransport:
    """Fake OSV transport: returns a canned payload and counts calls."""

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = 0

    def __call__(self, component: Component) -> dict:
        self.calls += 1
        return self.payload


@pytest.fixture
def osv_payload():
    return {
        "vulns": [
            {
                "id": "CVE-2022-22965",
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
            }
        ]
    }


def test_live_client_caches_and_writes_file(tmp_path, osv_payload):
    cache = tmp_path / "osv_cache.json"
    transport = _CountingTransport(osv_payload)
    client = LiveOSVClient(cache_path=cache, transport=transport)
    comp = Component(name="spring-web", version="5.3.16", ecosystem="Maven")

    first = client.query(comp)
    assert transport.calls == 1
    assert first[0].cve_id == "CVE-2022-22965"
    assert first[0].cvss == 9.8

    # Second query for the same component is served from the in-memory cache.
    client.query(comp)
    assert transport.calls == 1

    # The cache file was written in the offline-fixture format.
    on_disk = json.loads(cache.read_text(encoding="utf-8"))
    assert "spring-web@5.3.16" in on_disk
    assert on_disk["spring-web@5.3.16"][0]["cve_id"] == "CVE-2022-22965"


def test_offline_reads_what_live_cached(tmp_path, osv_payload):
    """The whole point: --offline works from the cache a live run wrote."""
    cache = tmp_path / "osv_cache.json"
    transport = _CountingTransport(osv_payload)
    comp = Component(name="spring-web", version="5.3.16", ecosystem="Maven")
    LiveOSVClient(cache_path=cache, transport=transport).query(comp)

    offline = OfflineOSVClient(cache)
    matches = offline.query(comp)
    assert matches[0].cve_id == "CVE-2022-22965"
    assert matches[0].cvss == 9.8


def test_live_client_reuses_cache_across_instances(tmp_path, osv_payload):
    cache = tmp_path / "osv_cache.json"
    comp = Component(name="spring-web", version="5.3.16", ecosystem="Maven")
    t1 = _CountingTransport(osv_payload)
    LiveOSVClient(cache_path=cache, transport=t1).query(comp)
    assert t1.calls == 1

    # A fresh client loads the existing cache file and does not call out again.
    t2 = _CountingTransport(osv_payload)
    LiveOSVClient(cache_path=cache, transport=t2).query(comp)
    assert t2.calls == 0
