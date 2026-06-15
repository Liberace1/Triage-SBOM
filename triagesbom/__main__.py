"""TriageSBOM CLI entry point.

Example:
    triagesbom tests/fixtures/sample.cdx.json --out ranked.json --offline
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triagesbom.pipeline import (
    DEFAULT_EPSS_CACHE,
    DEFAULT_EPSS_FIXTURE,
    DEFAULT_KEV_CACHE,
    DEFAULT_KEV_FIXTURE,
    DEFAULT_OSV_CACHE,
    DEFAULT_OSV_FIXTURE,
    DEFAULT_SBOM,
    run_live,
    run_offline,
)
from triagesbom.compare import build_comparison
from triagesbom.output import print_comparison, print_ranked_table, write_ranked_json


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="triagesbom",
        description="Rank the known vulnerabilities in an SBOM by exploit risk "
        "(EPSS + CISA KEV + CVSS).",
    )
    parser.add_argument(
        "sbom",
        type=Path,
        nargs="?",
        default=DEFAULT_SBOM,
        help=f"CycloneDX JSON SBOM (default: {DEFAULT_SBOM})",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("ranked.json"),
        help="Write ranked findings to this JSON file (default: ranked.json)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use bundled offline fixtures only (no network, no keys). "
        "Without this flag, OSV is queried live and responses are cached.",
    )
    parser.add_argument(
        "--osv-fixture",
        type=Path,
        default=DEFAULT_OSV_FIXTURE,
        help=f"Offline OSV fixture for --offline (default: {DEFAULT_OSV_FIXTURE.name})",
    )
    parser.add_argument(
        "--osv-cache",
        type=Path,
        default=DEFAULT_OSV_CACHE,
        help=f"Write-through OSV cache for live mode (default: {DEFAULT_OSV_CACHE.name})",
    )
    parser.add_argument(
        "--epss-fixture",
        type=Path,
        default=DEFAULT_EPSS_FIXTURE,
        help=f"Offline EPSS snapshot for --offline (default: {DEFAULT_EPSS_FIXTURE.name})",
    )
    parser.add_argument(
        "--kev-fixture",
        type=Path,
        default=DEFAULT_KEV_FIXTURE,
        help=f"Offline KEV snapshot for --offline (default: {DEFAULT_KEV_FIXTURE.name})",
    )
    parser.add_argument(
        "--epss-cache",
        type=Path,
        default=DEFAULT_EPSS_CACHE,
        help=f"Live EPSS cache (default: {DEFAULT_EPSS_CACHE.name})",
    )
    parser.add_argument(
        "--kev-cache",
        type=Path,
        default=DEFAULT_KEV_CACHE,
        help=f"Live KEV cache (default: {DEFAULT_KEV_CACHE.name})",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="In live mode, re-download EPSS/KEV even if a cache exists.",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Also show how the risk ranking reorders vs. a naive CVSS-only sort.",
    )
    parser.add_argument(
        "--weights",
        type=Path,
        default=None,
        help="Scoring weights JSON (default: config/weights.json)",
    )
    args = parser.parse_args()

    try:
        if args.offline:
            result = run_offline(
                sbom_path=args.sbom,
                osv_fixture=args.osv_fixture,
                epss_fixture=args.epss_fixture,
                kev_fixture=args.kev_fixture,
                weights_path=args.weights,
            )
        else:
            print(
                "Live mode: querying OSV, EPSS (FIRST.org) and KEV (CISA); "
                "caching all responses to tests/fixtures/.",
                file=sys.stderr,
            )
            result = run_live(
                sbom_path=args.sbom,
                osv_cache=args.osv_cache,
                epss_cache=args.epss_cache,
                kev_cache=args.kev_cache,
                weights_path=args.weights,
                refresh=args.refresh,
            )
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # network/HTTP errors in live mode
        print(f"error: live fetch failed: {exc}", file=sys.stderr)
        print("Tip: run with --offline to use the bundled fixtures.", file=sys.stderr)
        return 1

    components_in = len(result.components)
    comparison = build_comparison(result.findings) if args.compare else None
    write_ranked_json(
        result.findings, args.out, components_in=components_in, comparison=comparison
    )
    print_ranked_table(result.findings, components_in=components_in)
    if comparison is not None:
        print()
        print_comparison(comparison)
    print(f"\nWrote ranked worklist to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
