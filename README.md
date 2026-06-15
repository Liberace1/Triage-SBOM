# TriageSBOM — find the vulnerabilities that actually matter

**CSC-842 Tool 2 — Systems, Software & Infrastructure Security**

You give TriageSBOM a list of the software your app is built from (an **SBOM**),
and it returns a short *"fix these first"* list — ranked by which security holes
are **actually being exploited**, not just which ones *sound* scary.

A scanner gives you hundreds of CVEs sorted by severity (**CVSS**). But severity
isn't urgency: a "9.8 Critical" nobody is exploiting matters less than a "medium"
attackers are using today. TriageSBOM re-ranks using two signals CVSS ignores:

| Signal | Question it answers | Source |
|--------|--------------------|--------|
| **EPSS** | How *likely* is exploitation soon? (0–100%) | FIRST.org |
| **CISA KEV** | Is it being exploited *right now*? (yes/no) | CISA |
| **CVSS** | How *bad* if exploited? | OSV / NVD |

No accounts, no API keys, works offline.

---

## Run it

**Quickest start — the setup script.** It asks whether you want to run with
**Docker** or **Python**, then handles that path end to end:

```bash
# macOS / Linux / Git Bash:   ./setup.sh
# Windows PowerShell:         .\setup.ps1
```

- *Docker:* checks Docker is installed (offers to install it, or links you to the
  download), waits until the daemon is running, builds and starts the app, then
  **opens your browser** at http://localhost:8501.
- *Python:* checks for Python 3.11+, builds the venv, installs everything, runs a
  smoke test, then launches the web UI and **opens your browser** automatically.

Tip: set `SETUP_DRY_RUN=1` to print what the script *would* launch (including the
browser step) without actually starting anything.

Prefer to do it yourself? Three manual options — **pick one**, from inside the
`TriageSBOM/` folder:

**1. Docker** (only Docker needed):
```bash
docker compose up --build      # then open http://localhost:8501
```
Stop with `Ctrl+C`, then `docker compose down`.

**2. Web app, locally** (needs Python 3.11+):
```bash
# Windows:  .\run.bat       macOS/Linux:  ./run.sh
```
Opens at **http://localhost:8501** → click **Load Sample** → **Rank Vulnerabilities**.

**3. Command line** (needs Python 3.11+):
```bash
python -m venv venv
# activate:  Windows  .\venv\Scripts\Activate.ps1   |   macOS/Linux  source venv/bin/activate
pip install -e ".[dev]"
triagesbom tests/fixtures/sample.cdx.json --offline --compare
```
Add `--out ranked.json` to save results to a file.

---

## How to read the results

Each row is one vulnerability, highest risk first:

| Column | Meaning |
|--------|---------|
| **Score** | Final risk score — higher = patch sooner. |
| **KEV** | `YES` = on CISA's "exploited right now" list. Always ranks at the top. |
| **CVE** | The vulnerability ID. |
| **Component** | Which library it's in. |
| **CVSS / EPSS** | Severity (0–10) / chance of exploitation in 30 days. |
| **Why** | Plain-English reason for the ranking. |

---

## Why it beats sorting by severity

The included sample proves the point:

| Rank | CVE | Component | CVSS | EPSS | KEV |
|------|-----|-----------|-----:|-----:|:---:|
| 1–3 | Struts / Spring / Log4Shell | struts2-core, spring-web, log4j-core | 9.8–10.0 | 94–97% | ✅ |
| **4** | **CVE-2023-31001** | **webadmin-ui** | **4.3** | **88%** | ❌ |
| 5 | CVE-2022-42889 | commons-text | 9.8 | 2% | ❌ |
| 6 | CVE-2022-3602 | openssl | 9.8 | 0.4% | ❌ |

`webadmin-ui` is only **4.3** by severity (bottom of a CVSS sort) but is
**actively exploited (EPSS 88%)**, so it lands at **#4** — above two "9.8
criticals" nobody is attacking. Run with `--compare` to see this side by side.

---

## Offline vs. live

- **Offline** (`--offline`): uses bundled sample data — no internet, reproducible.
- **Live** (default): looks up real data from OSV, FIRST.org, and CISA, and
  **caches it** so you can re-run offline. No API keys.

```bash
triagesbom my-app.cdx.json --out ranked.json     # live + cache (--refresh to re-fetch)
```

Generate an SBOM from a container image with Syft, then triage it:
```bash
syft <image> -o cyclonedx-json > image.cdx.json && triagesbom image.cdx.json --offline
```

---

## How it works

```
SBOM → parse CycloneDX → OSV lookup (CVEs+CVSS) → enrich (EPSS+KEV)
     → score & rank → ranked table + ranked.json
```

**Scoring** (in [`config/weights.json`](config/weights.json), tunable):
```
risk = (100 if KEV else 0) + 30*EPSS + 20*(CVSS/10)
```
KEV is a hard escalator — 100 > 30+20, so anything actively exploited always
ranks on top. Every finding carries a one-line reason.

---

## Notes

- **No reachability yet:** the score is risk *potential* — it flags that a
  vulnerable component is present and exploited *in the world*, not whether *your*
  code reaches it. (Planned next step.)
- CycloneDX JSON input only for now.
- `python -m pytest -q` runs the 31 tests. Code lives in `triagesbom/`; the web
  UI is `app.py`.
