"""Deterministic SBOM-to-SBOM comparison.

Components are identified by their ecosystem-scoped *name*; version and
hash changes are reported separately.  Because every collection is sorted
before comparison, reordering components or dependencies between the two
documents never produces a spurious difference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .errors import InputError
from .versions import compare


@dataclass
class SBOMDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    upgraded: list[dict] = field(default_factory=list)
    downgraded: list[dict] = field(default_factory=list)
    version_same_hash_changed: list[dict] = field(default_factory=list)
    license_changed: list[dict] = field(default_factory=list)
    dependency_edges_added: list[str] = field(default_factory=list)
    dependency_edges_removed: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (
            self.added or self.removed or self.upgraded or self.downgraded
            or self.version_same_hash_changed or self.license_changed
            or self.dependency_edges_added or self.dependency_edges_removed
        )

    def to_dict(self) -> dict:
        return {
            "added": self.added,
            "removed": self.removed,
            "upgraded": self.upgraded,
            "downgraded": self.downgraded,
            "version_same_hash_changed": self.version_same_hash_changed,
            "license_changed": self.license_changed,
            "dependency_edges_added": self.dependency_edges_added,
            "dependency_edges_removed": self.dependency_edges_removed,
        }


def _load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise InputError(f"cannot read SBOM {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"malformed SBOM JSON {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise InputError(f"{path} is not a CycloneDX SBOM document")
    return data


def _index(doc: dict) -> dict[str, dict]:
    """Map stable component keys (ecosystem:name) -> component data."""

    out = {}
    for comp in doc.get("components", []):
        props = {p["name"]: p.get("value", "") for p in comp.get("properties", [])}
        eco = props.get("localsbom:ecosystem", "unknown")
        out[f"{eco}:{comp.get('name')}"] = comp
    return out


def _hash_set(comp: dict) -> set[tuple[str, str]]:
    return {(h.get("alg", ""), h.get("content", "")) for h in comp.get("hashes", [])}


def _license_set(comp: dict) -> set[str]:
    out = set()
    for lic in comp.get("licenses", []):
        l = lic.get("license", {})
        out.add(l.get("id") or l.get("name") or "")
    return {x for x in out if x}


def _edge_set(doc: dict, idx: dict[str, dict]) -> set[tuple[str, str]]:
    ref_to_key = {c["bom-ref"]: k for k, c in idx.items()}
    edges = set()
    for dep in doc.get("dependencies", []):
        src = ref_to_key.get(dep.get("ref", ""))
        if src is None:
            continue
        for dst_ref in dep.get("dependsOn", []):
            dst = ref_to_key.get(dst_ref)
            if dst is not None:
                edges.add((src, dst))
    return edges


def diff_sboms(old_path: str, new_path: str) -> SBOMDiff:
    old, new = _load(old_path), _load(new_path)
    oi, ni = _index(old), _index(new)
    result = SBOMDiff()

    result.added = sorted(set(ni) - set(oi))
    result.removed = sorted(set(oi) - set(ni))

    for key in sorted(set(oi) & set(ni)):
        a, b = oi[key], ni[key]
        va, vb = a.get("version", ""), b.get("version", "")
        if va != vb:
            c = compare(vb, va)
            entry = {"component": key, "from": va, "to": vb}
            (result.upgraded if c >= 0 else result.downgraded).append(entry)
        else:
            ha, hb = _hash_set(a), _hash_set(b)
            if ha and hb and ha != hb:
                result.version_same_hash_changed.append(
                    {
                        "component": key,
                        "version": va,
                        "from_hashes": sorted(ha),
                        "to_hashes": sorted(hb),
                    }
                )
        la, lb = _license_set(a), _license_set(b)
        if la != lb:
            result.license_changed.append(
                {
                    "component": key,
                    "from": sorted(la),
                    "to": sorted(lb),
                }
            )

    result.dependency_edges_added = sorted(
        f"{a}->{b}" for a, b in (_edge_set(new, ni) - _edge_set(old, oi))
    )
    result.dependency_edges_removed = sorted(
        f"{a}->{b}" for a, b in (_edge_set(old, oi) - _edge_set(new, ni))
    )
    return result
