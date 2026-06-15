"""Parse a CycloneDX JSON SBOM into a list of Components (CycloneDX only for now)."""

from __future__ import annotations

import json
from pathlib import Path

from triagesbom.models import Component

# Map a purl "type" to the OSV ecosystem name OSV expects.
# https://ossf.github.io/osv-schema/#affectedpackage-field
_PURL_TYPE_TO_OSV = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}


def _ecosystem_from_purl(purl: str) -> str:
    """Derive an OSV ecosystem from a purl string like 'pkg:maven/org.x/y@1.0'."""
    if not purl.startswith("pkg:"):
        return ""
    purl_type = purl[len("pkg:"):].split("/", 1)[0].split("@", 1)[0].lower()
    return _PURL_TYPE_TO_OSV.get(purl_type, "")


def parse_cyclonedx(path: str | Path) -> list[Component]:
    """Read a CycloneDX JSON file and return its components.

    Raises FileNotFoundError if the path is missing and ValueError if the file
    is not a CycloneDX document.
    """
    sbom_path = Path(path)
    if not sbom_path.is_file():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    data = json.loads(sbom_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ValueError(
            f"Not a CycloneDX JSON SBOM (missing bomFormat=CycloneDX): {sbom_path}"
        )

    components: list[Component] = []
    seen: set[tuple[str, str]] = set()
    for raw in data.get("components", []):
        name = str(raw.get("name") or "").strip()
        version = str(raw.get("version") or "").strip()
        if not name or not version:
            # A component with no name/version can't be looked up; skip it.
            continue
        purl = str(raw.get("purl") or "").strip()
        ecosystem = _ecosystem_from_purl(purl)
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        components.append(
            Component(name=name, version=version, ecosystem=ecosystem, purl=purl)
        )
    return components
