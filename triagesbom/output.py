"""Ranked worklist output: console table (rich) + ranked.json."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from triagesbom.compare import RankDelta, headline_burial
from triagesbom.models import Finding


def _finding_to_dict(rank: int, f: Finding) -> dict:
    return {
        "rank": rank,
        "component": f.component.name,
        "version": f.component.version,
        "ecosystem": f.component.ecosystem,
        "cve_id": f.cve_id,
        "cvss": f.cvss,
        "epss": round(f.epss, 4),
        "kev": f.kev_flag,
        "score": f.score,
        "reason": f.reason,
    }


def write_ranked_json(
    findings: list[Finding],
    path: str | Path,
    components_in: int,
    comparison: list[RankDelta] | None = None,
) -> None:
    """Write the ranked worklist to JSON, highest risk first.

    If `comparison` is given, also record each finding's risk rank vs. its
    CVSS-only rank so the reordering is inspectable.
    """
    payload: dict = {
        "summary": {
            "components_in": components_in,
            "components_with_findings": len({f.component for f in findings}),
            "findings_out": len(findings),
            "kev_findings": sum(1 for f in findings if f.kev_flag),
        },
        "findings": [_finding_to_dict(i, f) for i, f in enumerate(findings, start=1)],
    }
    if comparison is not None:
        payload["vs_cvss_only"] = [
            {
                "cve_id": d.finding.cve_id,
                "component": d.finding.component.name,
                "risk_rank": d.risk_rank,
                "cvss_rank": d.cvss_rank,
                "move": d.move,
            }
            for d in comparison
        ]
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_ranked_table(
    findings: list[Finding],
    components_in: int,
    console: Console | None = None,
) -> None:
    """Print the ranked 'patch first' table to the console."""
    # Fixed width so the table renders cleanly even in a piped / non-TTY shell.
    console = console or Console(width=120)

    table = Table(title="TriageSBOM - Patch First (ranked by exploit risk)")
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Score", justify="right", width=7)
    table.add_column("KEV", justify="center", width=4)
    table.add_column("CVE", width=18)
    table.add_column("Component", width=22)
    table.add_column("Version", width=12)
    table.add_column("CVSS", justify="right", width=5)
    table.add_column("EPSS", justify="right", width=6)
    table.add_column("Why", width=46)

    for rank, f in enumerate(findings, start=1):
        kev_cell = "[bold red]YES[/bold red]" if f.kev_flag else "-"
        score_style = "bold red" if f.kev_flag else "yellow" if f.epss >= 0.5 else ""
        table.add_row(
            str(rank),
            f"[{score_style}]{f.score:.1f}[/{score_style}]" if score_style else f"{f.score:.1f}",
            kev_cell,
            f.cve_id,
            f.component.name[:22],
            f.component.version[:12],
            f"{f.cvss:.1f}",
            f"{f.epss:.0%}",
            f.reason[:46],
        )

    console.print(table)
    kev_count = sum(1 for f in findings if f.kev_flag)
    components_with = len({f.component for f in findings})
    console.print(
        f"\n[dim]{components_in} component(s) scanned -> "
        f"{len(findings)} finding(s) across {components_with} component(s); "
        f"{kev_count} KEV-listed (actively exploited).[/dim]"
    )


def _move_cell(move: int) -> str:
    """Render a rank change: green if risk promoted it, red if demoted."""
    if move > 0:
        return f"[green]+{move}[/green]"   # more urgent than CVSS-only thought
    if move < 0:
        return f"[red]{move}[/red]"        # CVSS-only over-prioritized it
    return "[dim]0[/dim]"


def print_comparison(
    comparison: list[RankDelta],
    console: Console | None = None,
    limit: int = 15,
) -> None:
    """Print risk ranking vs. a naive CVSS-only sort, highlighting reordering."""
    console = console or Console(width=120)

    table = Table(title="Risk ranking vs. a naive CVSS-only sort")
    table.add_column("Risk #", justify="right", width=6)
    table.add_column("CVSS #", justify="right", width=6)
    table.add_column("Move", justify="right", width=6)
    table.add_column("CVE", width=18)
    table.add_column("Component", width=20)
    table.add_column("CVSS", justify="right", width=5)
    table.add_column("EPSS", justify="right", width=6)
    table.add_column("KEV", justify="center", width=4)

    for d in comparison[:limit]:
        f = d.finding
        table.add_row(
            str(d.risk_rank),
            str(d.cvss_rank),
            _move_cell(d.move),
            f.cve_id,
            f.component.name[:20],
            f"{f.cvss:.1f}",
            f"{f.epss:.0%}",
            "[bold red]YES[/bold red]" if f.kev_flag else "-",
        )

    console.print(table)
    console.print(
        "[dim]Move = places the risk ranking shifted a CVE vs. CVSS-only "
        "([green]+[/green] = more urgent than CVSS alone shows, "
        "[red]-[/red] = CVSS-only over-prioritized it).[/dim]"
    )

    burial = headline_burial(comparison)
    if burial is not None:
        f = burial.finding
        why = "KEV-listed (actively exploited)" if f.kev_flag else f"EPSS {f.epss:.0%}"
        console.print(
            f"\n[bold]Headline:[/bold] a CVSS-only sort would rank "
            f"[cyan]{f.cve_id}[/cyan] ({f.component.name}, CVSS {f.cvss:.1f}) at "
            f"[red]#{burial.cvss_rank}[/red] -- but it is {why}, so TriageSBOM "
            f"surfaces it at [green]#{burial.risk_rank}[/green] "
            f"({burial.move} places higher)."
        )
