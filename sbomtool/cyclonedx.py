"""Stable CycloneDX 1.5 JSON generation (local data only).

The output is deterministic: components, licenses, hashes, properties and
dependency edges are all emitted in sorted order, and no timestamps or
random serial numbers are added, so identical inputs always produce
byte-identical documents.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import quote

from .model import Component, ProjectScan, RootProject

SPEC_VERSION = "1.5"
SBOM_TOOL_VERSION = "1.0.0"

_SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")


def make_purl(ecosystem: str, name: str, version: Optional[str],
              source_type: str = "registry") -> Optional[str]:
    if ecosystem == "python":
        ptype = "pypi"
        pname = name
    elif ecosystem == "npm":
        ptype = "npm"
        pname = name
        if name.startswith("@") and "/" in name:
            scope, pname = name[1:].split("/", 1)
            pname = "@" + quote(scope, safe="") + "/" + quote(pname, safe="")
        else:
            pname = quote(pname, safe="")
    else:
        return None
    purl = f"pkg:{ptype}/{pname.lower()}"
    if version:
        purl += "@" + quote(str(version), safe=".-+_")
    if source_type not in ("registry", "declared"):
        purl += f"?repository_id={source_type}"
    return purl


def build_cyclonedx(scans: Iterable[ProjectScan],
                    project_name: Optional[str] = None) -> dict:
    scans = list(scans)
    components: list[dict] = []
    dependencies_section: list[dict] = []

    aggregate_ref = "root:project"
    ecosystem_root_refs: list[str] = []

    for scan in scans:
        root_comp = _root_component(scan.root)
        components.append(root_comp)
        ecosystem_root_refs.append(root_comp["bom-ref"])
        root_refs = sorted({
            r for r in (_pick_bom_ref(scan, norm)
                        for norm in scan.root_direct) if r is not None
        })
        dependencies_section.append({
            "ref": root_comp["bom-ref"],
            "dependsOn": root_refs,
        })

        for comp in sorted(scan.components,
                           key=lambda c: (c.normalized_name,
                                          c.version or "", c.source_type)):
            components.append(_component_dict(comp))
            refs = sorted({
                r for r in (_dep_ref(scan, comp, dep)
                            for dep in comp.dependencies) if r is not None
            })
            dependencies_section.append({
                "ref": comp.bom_ref(),
                "dependsOn": refs,
            })

    aggregate = {
        "type": "application",
        "bom-ref": aggregate_ref,
        "name": project_name or "local-project",
    }
    dependencies_section.append({
        "ref": aggregate_ref,
        "dependsOn": sorted(ecosystem_root_refs),
    })

    dependencies_section.sort(key=lambda d: d["ref"])
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": aggregate,
            "tools": [
                {
                    "vendor": "local",
                    "name": "offline-sbom-tool",
                    "version": SBOM_TOOL_VERSION,
                }
            ],
            "properties": _metadata_properties(scans),
        },
        "components": sorted(components, key=lambda c: c["bom-ref"]),
        "dependencies": dependencies_section,
    }
    return document


def _metadata_properties(scans: list[ProjectScan]) -> list[dict]:
    props: list[dict] = []
    for scan in scans:
        files = sorted(set(scan.manifest_files) |
                       ({scan.lock_file} if scan.lock_file else set()))
        props.append({
            "name": f"sbom:{scan.ecosystem}:source-files",
            "value": ",".join(files),
        })
    props.sort(key=lambda p: p["name"])
    return props


def _root_component(root: RootProject) -> dict:
    bom_ref = f"root:{root.ecosystem}:{root.name}"
    comp = {
        "type": "application",
        "bom-ref": bom_ref,
        "name": root.name,
        "purl": None,
    }
    if root.version:
        comp["version"] = root.version
    if root.description:
        comp["description"] = root.description
    licenses = _license_choices(root.licenses)
    if licenses:
        comp["licenses"] = licenses
    if root.properties:
        comp["properties"] = [
            {"name": k, "value": v}
            for k, v in sorted(root.properties.items())
        ]
    return comp


def _component_dict(comp: Component) -> dict:
    purl = comp.purl or make_purl(comp.ecosystem, comp.normalized_name,
                                  comp.version, comp.source_type)
    result = {
        "type": "library",
        "bom-ref": comp.bom_ref(),
        "name": comp.name,
        "purl": purl,
    }
    if comp.version:
        result["version"] = comp.version
    if comp.description:
        result["description"] = comp.description
    if comp.licenses:
        result["licenses"] = _license_choices(comp.licenses)
    if comp.hashes:
        result["hashes"] = sorted(
            ({"alg": algo.upper(), "content": digest}
             for algo, digest in comp.hashes.items()),
            key=lambda h: h["alg"])
    properties = dict(comp.properties)
    properties.setdefault("sbom:ecosystem", comp.ecosystem)
    properties.setdefault("sbom:sourceType", comp.source_type)
    properties.setdefault("sbom:scope", comp.scope)
    if comp.source_file:
        properties.setdefault("sbom:sourceFile", comp.source_file)
    if comp.dependency_specs:
        for dep_norm in sorted(comp.dependency_specs):
            properties[f"sbom:depSpec:{dep_norm}"] = \
                comp.dependency_specs[dep_norm]
    result["properties"] = [
        {"name": k, "value": v}
        for k, v in sorted(properties.items())
    ]
    return result


def _license_choices(licenses: list[str]) -> list[dict]:
    choices: list[dict] = []
    seen: set[str] = set()
    for lic in licenses:
        lic = (lic or "").strip()
        if not lic or lic in seen:
            continue
        seen.add(lic)
        if _is_spdx_expression(lic):
            choices.append({"expression": lic})
        else:
            choices.append({"license": {"name": lic}})
    return sorted(choices, key=lambda c: c.get("expression")
                  or c["license"]["name"])


def _is_spdx_expression(value: str) -> bool:
    if " " in value and not re.search(r"\s(AND|OR|WITH)\s", value):
        return False
    tokens = re.split(r"\s+(?:AND|OR|WITH)\s+|\s+|[\(\)]", value)
    return all(not t or _SPDX_ID.match(t) for t in tokens)


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _pick_bom_ref(scan: ProjectScan, norm: str) -> Optional[str]:
    matches = sorted(
        (c for c in scan.components if c.normalized_name == norm),
        key=lambda c: (c.version or "", c.source_type))
    return matches[0].bom_ref() if matches else None


def _dep_ref(scan: ProjectScan, owner: Component,
             dep_norm: str) -> Optional[str]:
    # Resolve edge target with npm/node-style preference for a version the
    # owner's spec points at; otherwise the first component of that name.
    spec = owner.dependency_specs.get(dep_norm, "")
    candidates = [c for c in scan.components
                  if c.normalized_name == dep_norm]
    if not candidates:
        return None
    if scan.ecosystem == "npm" and spec:
        from .versions import npm_spec_matches

        for cand in candidates:
            if cand.version and _safe_match(npm_spec_matches, spec,
                                            cand.version):
                return cand.bom_ref()
    if scan.ecosystem == "python" and spec:
        from .versions import python_spec_matches

        for cand in candidates:
            if cand.version and _safe_match(python_spec_matches, spec,
                                            cand.version):
                return cand.bom_ref()
    return sorted(candidates, key=lambda c: (c.version or "",
                                            c.source_type))[0].bom_ref()


def _safe_match(matcher, spec, version) -> bool:
    try:
        return matcher(spec, version)
    except Exception:  # noqa: BLE001
        return False
