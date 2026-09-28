"""Order-independent SBOM comparison.

Two CycloneDX documents (produced by this tool, or compatible documents with
``name``/``version`` and ecosystem properties) are compared at the package
identity level.  Input ordering never creates noise: every comparison works
on sorted indexes.
"""

from __future__ import annotations

from typing import Optional

from .errors import SBOMError
from .versions import compare_versions


def _index_components(document: dict) -> dict:
    if not isinstance(document, dict):
        raise SBOMError("SBOM document must be a JSON object")
    if document.get("bomFormat") != "CycloneDX":
        raise SBOMError("only CycloneDX documents are supported")
    index: dict[tuple[str, str], dict] = {}
    for comp in document.get("components", []):
        if comp.get("type") not in ("library", "framework"):
            continue
        eco, norm = _component_identity(comp)
        index[(eco, norm)] = comp
    return index


def _component_identity(comp: dict) -> tuple[str, str]:
    eco = "unknown"
    for prop in comp.get("properties", []):
        if prop.get("name") == "sbom:ecosystem":
            eco = prop["value"]
            break
    purl = comp.get("purl") or ""
    name = _name_from_purl(purl) or comp.get("name", "")
    if eco == "npm" and name.startswith("@"):
        name = name.lower()
    elif eco == "python":
        name = name.lower().replace("_", "-")
    return eco, name


def _name_from_purl(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    rest = purl[4:].split("?", 1)[0]
    if "/" not in rest:
        return ""
    _type, path = rest.split("/", 1)
    # strip version with rsplit so npm scoped names ("@scope/pkg@1") work
    at = path.rfind("@")
    if at > 0:
        return path[:at]
    return path


def diff_sboms(old_doc: dict, new_doc: dict) -> dict:
    """Return a structured diff report between two SBOM documents."""

    old = _index_components(old_doc)
    new = _index_components(new_doc)

    old_keys = set(old)
    new_keys = set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    upgraded: list[dict] = []
    downgraded: list[dict] = []
    changed: list[dict] = []
    unchanged: list[dict] = []

    for key in sorted(old_keys & new_keys):
        a, b = old[key], new[key]
        va, vb = a.get("version"), b.get("version")
        entry = {
            "ecosystem": key[0],
            "name": key[1],
            "old_version": va,
            "new_version": vb,
        }
        if va == vb:
            hash_change = _hash_change(a, b)
            if hash_change:
                changed.append({**entry, "change": "hash",
                                "hashes": hash_change})
            else:
                unchanged.append(entry)
        else:
            eco = key[0]
            if va and vb:
                rel = compare_versions(va, vb,
                                       "python" if eco == "python"
                                       else "npm")
                direction = "upgraded" if rel < 0 else "downgraded"
            else:
                direction = "changed"
            (upgraded if direction == "upgraded"
             else downgraded if direction == "downgraded"
             else changed).append(entry)

    return {
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "upgraded": len(upgraded),
            "downgraded": len(downgraded),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "added": [_entry(new[k]) for k in added],
        "removed": [_entry(old[k]) for k in removed],
        "upgraded": upgraded,
        "downgraded": downgraded,
        "changed": changed,
        "unchanged": unchanged,
    }


def _entry(comp: dict) -> dict:
    eco, name = _component_identity(comp)
    return {"ecosystem": eco, "name": name,
            "version": comp.get("version")}


def _hash_change(a: dict, b: dict) -> Optional[dict]:
    ha = {h["alg"]: h["content"] for h in a.get("hashes", [])}
    hb = {h["alg"]: h["content"] for h in b.get("hashes", [])}
    shared = set(ha) & set(hb)
    for alg in sorted(shared):
        if ha[alg] != hb[alg]:
            return {"algorithm": alg, "old": ha[alg], "new": hb[alg]}
    gained = sorted(set(hb) - set(ha))
    lost = sorted(set(ha) - set(hb))
    if gained or lost:
        return {"algorithm": (gained or lost)[0],
                "old": ha.get((gained or lost)[0]),
                "new": hb.get((gained or lost)[0])}
    return None
