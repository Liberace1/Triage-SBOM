# AI Usage Report — TriageSBOM

Required AI-usage report for CSC-842 Tool 2. It records where AI assistance was
used, what I directed and decided, what I changed or rejected and why, and how I
verified the result.

## Overview

I designed the tool and drove the build incrementally — one working vertical
slice at a time — reviewing and testing each slice before moving on. I used an AI
coding assistant to scaffold the core Python pipeline modules and their unit
tests from my specification. Every architectural decision, the scoring model, the
sample-data design, the web UI, and the containerized deployment were mine, and I
verified all behavior by running the tests and the tool.

- **AI-assisted:** initial scaffolding of the `triagesbom/` pipeline modules
  (parsing, OSV client, CVSS calculation, enrichment, scoring, output) and the
  pytest suite, generated from my prompts and spec.
- **My own work:** the project design and spec, all scoring/architecture
  decisions, the crafted sample dataset, the Streamlit web UI (`app.py`), the
  Docker/Compose deployment, the run scripts, dependency configuration, and all
  testing/verification.

---

## Core pipeline (offline)

**What I directed:** one CycloneDX SBOM in, a ranked CVE list out, fully offline
(no network, no keys). A normalized data model, a CycloneDX parser, an OSV-client
*interface* backed by an offline fixture, EPSS + KEV enrichment, a transparent
config-driven weighted score with per-finding reasons, and ranked console + JSON
output.

**AI-scaffolded modules:** `models.py`, `sbom.py`, `osv_client.py` (interface +
offline client), `enrich.py`, `score.py`, `pipeline.py`, `output.py`,
`__main__.py`, plus `tests/test_ranking.py`.

**Decisions I made:**
- Required the OSV lookup to sit behind an interface so the offline client could
  later be swapped for a live one without touching the pipeline.
- Chose the weights `kev_boost=100, epss_weight=30, cvss_weight=20` so KEV is a
  provable hard escalator (100 > 30 + 20 = max non-KEV score).
- Designed the sample dataset to prove the ranking beats a CVSS-only sort: a
  low-CVSS (4.3) but high-EPSS (88%) finding must outrank two CVSS-9.8 criticals
  with near-zero EPSS.

**Issues I caught and fixed:**
- The offline OSV loader crashed on the `_comment` metadata key
  (`TypeError: string indices must be integers`); fixed by skipping `_`-prefixed
  keys. Caught by running the tests.
- Tidied reason strings ("EPSS 0%" → "EPSS 0.4%" for tiny values) and fixed the
  console table width for non-interactive shells.

**Verification:** `pytest` (8 tests) green; ran the CLI on the sample and
confirmed 12 components → 9 findings, 3 KEV at the top, and `webadmin-ui`
(CVSS 4.3, EPSS 88%) ranked #4 above the CVSS-9.8 components.

---

## Live OSV lookup with caching

**What I directed:** wire the real OSV API behind the existing interface, cache
every response, and keep offline mode working from that cache.

**AI-scaffolded:** `cvss.py` (CVSS v3.x base score from the vector string),
`parse_osv_response()` and `LiveOSVClient` in `osv_client.py`, `run_live()`,
and `tests/test_osv_live.py`.

**Decisions I made:**
- Cache live responses to a *separate* file (`osv_cache.json`) instead of
  overwriting the crafted teaching fixture, so the deterministic demo survives.
- Compute the CVSS base score from the OSV vector rather than trusting a numeric
  field, since the standardized field is the vector string.

**Verification:** `pytest` (18 tests) green; CVSS calculator checked against known
values (Log4Shell = 10.0, Spring4Shell = 9.8); a real OSV call for
`log4j-core 2.14.1` returned 7 CVEs with correct public scores; a full live run
cached 115 findings, and re-running offline from that cache produced identical
output.

---

## Live EPSS + KEV download with caching

**What I directed:** add live EPSS and KEV downloads with a local dated cache,
keeping offline mode reproducible. No API keys.

**AI-scaffolded:** `fetch_epss()` and `download_kev()` in `enrich.py`, the live
enrichment path in `run_live()`, and `tests/test_feeds_live.py`.

**Decisions I made:**
- Verified the real endpoints (`api.first.org/data/v1/epss`, the CISA KEV feed)
  and their JSON shapes before coding, rather than assuming URLs/fields.
- Used the EPSS *API* (query only the CVEs found) instead of the ~250k-row bulk
  CSV, which also makes "fetch only the missing CVEs" caching natural.
- Slimmed the KEV cache to metadata + cveIDs (76 KB vs ~MB) with a `fetch_date`
  so it stays a small, genuine dated snapshot.

**A result I double-checked:** several KEV CVEs displayed "EPSS 94%" — I inspected
the cache and confirmed the underlying values are distinct (0.9436, 0.9427, …)
and simply round to 94%. Not a bug.

**Verification:** `pytest` (24 tests) green; a real `--refresh` run pulled live
OSV + EPSS + KEV (CISA catalog, 1612 entries) for 115 findings; re-running offline
from the three caches was byte-identical (`diff` clean).

---

## "vs CVSS-only" comparison view

**What I directed:** show how the EPSS+KEV+CVSS ranking reorders findings versus a
naive CVSS-only sort — the core proof of the tool's value.

**AI-scaffolded:** `compare.py` (`build_comparison()`, `headline_burial()`),
`print_comparison()` and the `vs_cvss_only` JSON block in `output.py`, the
`--compare` flag, and `tests/test_compare.py`.

**Decisions I made:**
- Keyed the rank comparison by `(component, version, cve_id)` so it is robust to
  copied/reconstructed findings.
- Defined the rank-move sign so positive means the risk ranking treats a CVE as
  more urgent than CVSS alone, and replaced an em-dash with `--` to avoid console
  mojibake during the demo.

**Verification:** `pytest` (31 tests) green; `--compare` shows `webadmin-ui`
(CVSS 4.3, EPSS 88%) at CVSS-rank #9 but risk-rank #4 (+5), and `openssl`
(CVSS 9.8, EPSS 0%) demoted −2 — exactly the intended point.

---

## Built and integrated by me (no AI scaffolding of the code)

- **Streamlit web UI (`app.py`):** SBOM upload, "Load Sample", an offline/live
  toggle, live-tunable scoring weights, summary metrics, a sortable results
  table, and JSON/CSV export — wired onto the same pipeline.
- **Containerized deployment:** `Dockerfile` and `docker-compose.yml` to build and
  serve the UI on port 8501, with fixtures/config mounted for the offline demo.
- **Run scripts:** `run.sh` / `run.bat` to create the environment and launch the
  UI in one step; Streamlit config set to a minimal toolbar for a clean demo.
- **Packaging:** dependency and entry-point configuration in `pyproject.toml` /
  `requirements.txt`.
- **Final pass:** reviewed and cleaned the generated code into a consistent,
  neutral style.

## How I verified everything

- The full pytest suite (31 tests) passes.
- I ran the CLI in offline and live modes and inspected the ranked output and the
  JSON file.
- I ran live lookups against OSV, FIRST.org (EPSS), and CISA (KEV) and confirmed
  the cached results reproduce byte-for-byte offline.
- I exercised the web UI end to end (upload/sample → rank → export).
