"""Turn parsed declarations, locks and local evidence into one unified SBOM."""

from __future__ import annotations

import os
from collections import defaultdict

from .localmeta import (
    find_node_modules,
    find_python_site_packages,
    scan_node_packages,
    scan_python_packages,
)
from .models import (
    Ecosystem,
    Finding,
    LockData,
    LockedPkg,
    SBOM,
    Severity,
    SOURCE_DECLARATION,
    SOURCE_LOCAL,
    SOURCE_LOCK,
    SOURCE_LOCK_LOCAL,
    component_key,
)
from .naming import make_purl, normalize_name
from .parsers import discover, parse_declaration, parse_lock
from .versions import satisfies


def analyze(
    root: str,
    *,
    use_local: bool = True,
    declarations: dict[Ecosystem, str] | None = None,
    locks: dict[str, tuple[Ecosystem, str]] | None = None,
) -> SBOM:
    """Analyze a local project directory and build the SBOM.

    Integrity findings are produced separately by
    :func:`integrity_findings`; this function assembles evidence only.
    """

    root = os.path.abspath(root)
    if declarations is None or locks is None:
        declarations, locks = discover(root)

    project_name = os.path.basename(root)
    project_version = None
    decl_map: dict[Ecosystem, object] = {}
    for eco, path in declarations.items():
        decl = parse_declaration(path, eco)
        decl_map[eco] = decl
        if decl.project_name:
            project_name = decl.project_name
        project_version = project_version or decl.project_version

    lock_data: list[LockData] = []
    for path, (eco, fmt) in sorted(locks.items()):
        lock_data.append(parse_lock(path, eco, fmt))

    local_pkgs: list[LockedPkg] = []
    if use_local:
        local_pkgs.extend(scan_python_packages(find_python_site_packages(root)))
        local_pkgs.extend(scan_node_packages(find_node_modules(root)))

    sbom = SBOM(
        project_name=project_name,
        project_version=project_version or "0.0.0",
        root_dir=root,
        declarations=decl_map,  # type: ignore[arg-type]
        lock_files=[ld.source_file for ld in lock_data],
    )

    # index lock instances: component key -> all locked/local records
    instances: dict[str, list[LockedPkg]] = defaultdict(list)
    raw_versions: dict[str, set[str]] = defaultdict(set)
    for ld in lock_data:
        for pkg in ld.packages:
            k = pkg_key(pkg)
            instances[k].append(pkg)
            raw_versions[k].add(pkg.version)
    for pkg in local_pkgs:
        instances[pkg_key(pkg)].append(pkg)
    sbom.raw_lock_versions = dict(raw_versions)

    # declarations first (so a declared-only dep survives even with no lock)
    for eco, decl in decl_map.items():  # type: ignore[union-attr]
        for name, info in decl.declared.items():
            key = component_key(eco, name)
            if key not in sbom.components:
                comp = _component_from_decl(eco, name, info)
                sbom.components[key] = comp

    for key, pkgs in instances.items():
        locked_versions = [p for p in pkgs if _is_lock_origin(p.origin)]
        local_versions = [p for p in pkgs if not _is_lock_origin(p.origin)]
        chosen: LockedPkg
        if locked_versions:
            chosen = _select_primary(locked_versions)
            source = SOURCE_LOCK_LOCAL if local_versions else SOURCE_LOCK
        else:
            chosen = _select_primary(local_versions)
            source = SOURCE_LOCAL
        eco = chosen.ecosystem
        comp = sbom.components.get(key)
        if comp is None:
            comp = _component_from_locked(chosen, source)
            sbom.components[key] = comp
        else:
            comp.version = chosen.version
            comp.source_type = source
            _absorb_locked(comp, chosen)
        for p in pkgs:
            _absorb_locked(comp, p)
        comp.purl = make_purl(eco, comp.name, comp.version)

    # deterministic ordering of stored side-data
    for comp in sbom.components.values():
        comp.hashes = _dedup_hashes(comp.hashes)
        comp.licenses = sorted(set(comp.licenses))
        comp.origins = sorted(set(comp.origins))
        comp.dependencies = set(comp.dependencies)
    return sbom


def pkg_key(pkg: LockedPkg) -> str:
    return component_key(pkg.ecosystem, pkg.name)


def _is_lock_origin(origin: str) -> bool:
    base = os.path.basename(origin)
    return base in ("uv.lock", "Pipfile.lock", "package-lock.json", "yarn.lock") or base.endswith(
        "requirements.txt"
    )


def _select_primary(pkgs: list[LockedPkg]) -> LockedPkg:
    def rank(p: LockedPkg):
        try:
            return (0, [int(x) for x in p.version.split(".") if x.isdigit()][:3], p.version)
        except Exception:
            return (1, [], p.version)

    return sorted(pkgs, key=lambda p: (p.scope != "required", rank(p), p.version))[0]


def _component_from_decl(eco: Ecosystem, name: str, info: dict):
    from .models import Component

    return Component(
        ecosystem=eco,
        name=normalize_name(name, eco),
        version="0.0.0",
        source_type=SOURCE_DECLARATION,
        declared_constraint=info["constraint"],
        scope=info.get("scope", "required"),
    )


def _component_from_locked(pkg: LockedPkg, source: str):
    from .models import Component

    return Component(
        ecosystem=pkg.ecosystem,
        name=pkg.name,
        version=pkg.version,
        source_type=source,
        hashes=list(pkg.hashes),
        licenses=list(pkg.licenses),
        dependencies=set(pkg.dependencies),
        origins=[pkg.origin],
        scope=pkg.scope,
        purl=make_purl(pkg.ecosystem, pkg.name, pkg.version),
    )


def _absorb_locked(comp, pkg: LockedPkg) -> None:
    for h in pkg.hashes:
        if (h.alg, h.value) not in {(x.alg, x.value) for x in comp.hashes}:
            comp.hashes.append(h)
    for lic in pkg.licenses:
        if lic not in comp.licenses:
            comp.licenses.append(lic)
    comp.dependencies |= pkg.dependencies
    if pkg.origin and pkg.origin not in comp.origins:
        comp.origins.append(pkg.origin)
    if pkg.scope == "required":
        comp.scope = "required"


def _dedup_hashes(hashes):
    out, seen = [], set()
    for h in sorted(hashes, key=lambda x: (x.alg, x.origin, x.value)):
        sig = (h.alg, h.value)
        if sig not in seen:
            seen.add(sig)
            out.append(h)
    return out


# --------------------------------------------------------- integrity checks

def integrity_findings(sbom: SBOM) -> list[Finding]:
    """Detect supply-chain integrity problems within a single SBOM."""

    findings: list[Finding] = []
    comps = sbom.components

    # 1. Duplicate components: one name resolving to several distinct
    #    versions across lock files.
    raw_versions = getattr(sbom, "raw_lock_versions", {})
    for key, versions in raw_versions.items():
        if len(versions) > 1:
            findings.append(
                Finding(
                    "DUP_VERSION",
                    Severity.ERROR,
                    f"component resolved to multiple versions: {sorted(versions)}",
                    component=key,
                )
            )

    # 2. Declared package missing from any lock (or entirely absent).
    for eco, decl in sbom.declarations.items():
        for name, info in decl.declared.items():
            key = component_key(eco, name)
            comp = comps.get(key)
            if comp is None or comp.source_type == SOURCE_DECLARATION:
                findings.append(
                    Finding(
                        "MISSING_PACKAGE",
                        Severity.ERROR,
                        f"declared dependency is absent from every lock file and local tree "
                        f"(constraint {info['constraint'] or 'any'!r})",
                        component=key,
                    )
                )
                continue
            # 3. Version inconsistency: locked version violates declaration.
            ok = satisfies(comp.version, info["constraint"], eco)
            if ok is False:
                findings.append(
                    Finding(
                        "VERSION_MISMATCH",
                        Severity.ERROR,
                        f"locked version {comp.version} does not satisfy declared "
                        f"constraint {info['constraint']!r}",
                        component=key,
                    )
                )
            elif ok is None:
                findings.append(
                    Finding(
                        "VERSION_UNCHECKED",
                        Severity.INFO,
                        f"could not mechanically verify locked {comp.version} against "
                        f"constraint {info['constraint']!r}",
                        component=key,
                    )
                )
            # 4. marker for the declaration-specific LOCK_MISS case is handled below

    # 5. Dangling dependency edges (missing transitive package).
    known = set(comps.keys())
    for comp in comps.values():
        for dep in sorted(comp.dependencies):
            if dep not in known:
                findings.append(
                    Finding(
                        "BROKEN_DEPENDENCY",
                        Severity.ERROR,
                        f"dependency {dep} is referenced but no component provides it",
                        component=comp.coord,
                    )
                )

    # 5b. Packages installed locally but absent from every lock file.
    for key, comp in comps.items():
        if comp.source_type == SOURCE_LOCAL:
            findings.append(
                Finding(
                    "LOCK_MISS",
                    Severity.WARNING,
                    "package exists in the local install tree but is not recorded in any lock file",
                    component=key,
                )
            )

    # 6. Locked components lacking any locally obtainable content hash.
    for comp in sorted(comps.values(), key=lambda c: c.coord):
        if comp.source_type in (SOURCE_LOCK,) and not comp.hashes:
            findings.append(
                Finding(
                    "NO_CONTENT_HASH",
                    Severity.WARNING,
                    "locked component has no locally obtainable content hash",
                    component=comp.coord,
                )
            )

    return sorted(findings, key=lambda f: (f.severity.value, f.code, f.component or "", f.message))
