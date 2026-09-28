"""Deterministic CycloneDX 1.5 JSON serialization (subset, locally produced).

The output contains no timestamp, random serial number or other unstable
field, and maps are emitted with sorted keys, so regenerating the SBOM for
the same inputs yields byte-identical JSON.
"""

from __future__ import annotations

import json

from .models import SBOM

_CDX_SPEC = "1.5"
_CDX_TYPE = {"python": "library", "npm": "library"}
_PURL_ECOSYSTEM = {}


def component_ref(comp) -> str:
    return f"{comp.ecosystem.value}:{comp.name}@{comp.version}"


def to_cyclonedx(sbom: SBOM) -> dict:
    components = []
    dependencies = []
    for key in sorted(sbom.components):
        comp = sbom.components[key]
        entry = {
            "bom-ref": component_ref(comp),
            "type": _CDX_TYPE.get(comp.ecosystem.value, "library"),
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl or "",
            "scope": "required" if comp.scope == "required" else "optional",
            "properties": [
                {"name": "localsbom:ecosystem", "value": comp.ecosystem.value},
                {"name": "localsbom:source", "value": comp.source_type},
                {"name": "localsbom:declared-constraint",
                 "value": comp.declared_constraint or ""},
            ],
        }
        if comp.hashes:
            entry["hashes"] = [
                {"alg": h.alg.upper(), "content": h.value}
                for h in sorted(comp.hashes, key=lambda x: (x.alg, x.value))
            ]
        if comp.licenses:
            entry["licenses"] = [
                {"license": {"id": lic}} if _is_spdx_id(lic)
                else {"license": {"name": lic}}
                for lic in sorted(set(comp.licenses))
            ]
        evidence_paths = sorted(set(comp.origins))
        if evidence_paths:
            entry["properties"].append(
                {"name": "localsbom:evidence", "value": "|".join(evidence_paths)}
            )
        components.append(entry)

        deps = sorted(comp.dependencies)
        if deps:
            resolved = []
            for dep_key in deps:
                dep_comp = sbom.components.get(dep_key)
                if dep_comp is not None:
                    resolved.append(component_ref(dep_comp))
            if resolved:
                dependencies.append({"ref": component_ref(comp), "dependsOn": sorted(set(resolved))})

    metadata_component = {
        "bom-ref": f"project:{sbom.project_name}@{sbom.project_version}",
        "type": "application",
        "name": sbom.project_name,
        "version": sbom.project_version,
    }
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": _CDX_SPEC,
        "version": 1,
        "serialNumber": "",  # intentionally empty: stable offline output
        "metadata": {
            "component": metadata_component,
            "properties": [
                {"name": "localsbom:root", "value": sbom.root_dir},
                {"name": "localsbom:lockfiles",
                 "value": "|".join(sorted(sbom.lock_files))},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    return doc


def dumps(sbom: SBOM) -> str:
    return json.dumps(to_cyclonedx(sbom), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


_SPDX_IDS = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0-only",
    "GPL-3.0-only", "LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0", "ISC",
    "PSF-2.0", "Python-2.0", "Unlicense", "0BSD", "Zlib", "CC0-1.0",
    "AGPL-3.0-only", "Artistic-2.0", "EPL-2.0", "WTFPL", "BSL-1.1",
    "BlueOak-1.0.0", "CC-BY-4.0", "EUPL-1.2", "NCSA", "PostgreSQL",
}


def _is_spdx_id(lic: str) -> bool:
    return lic in _SPDX_IDS
