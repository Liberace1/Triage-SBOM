"""Normalized data models for the SBOM triage pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    """One software component extracted from an SBOM."""

    name: str
    version: str
    ecosystem: str
    purl: str = ""


@dataclass
class Finding:
    """A vulnerability in a component, enriched and scored.

    A Finding is the unit that gets ranked. One component can yield several
    Findings (one per CVE); a clean component yields none.
    """

    component: Component
    cve_id: str
    cvss: float
    epss: float
    kev_flag: bool
    score: float = 0.0
    reason: str = ""
