"""Dependency integrity / completeness analysis.

Detects:
  * MISSING_PACKAGE        -- declared direct dependency absent from the lock
  * UNRESOLVED_VERSION     -- component with no concrete version and no lock
  * DUPLICATE_COMPONENT    -- same package appears more than once in a lock
  * VERSION_MISMATCH       -- locked version does not satisfy the manifest
  * LOCK_MISSING           -- declarations exist but no lock file at all
  * MISSING_HASH           -- registry component without a content hash
  * BROKEN_DEPENDENCY_EDGE -- dependency references a component not in SBOM
  * DUPLICATE_DECLARATION  -- same package declared twice in manifests
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from .errors import ParseError  # noqa: F401  (re-exported for callers)
from .model import ProjectScan, normalize_name
from .pep508 import evaluate_marker
from .versions import npm_spec_matches, python_spec_matches

ERROR = "error"
WARNING = "warning"
INFO = "info"

#: severity ranks for summary / exit-code decisions
RANK = {INFO: 0, WARNING: 1, ERROR: 2}


def analyze_integrity(scans: Iterable[ProjectScan]) -> list[dict]:
    issues: list[dict] = []
    for scan in scans:
        issues.extend(_analyze_scan(scan))
    return issues


def _analyze_scan(scan: ProjectScan) -> list[dict]:
    issues: list[dict] = []
    eco = scan.ecosystem
    components = scan.components
    by_name: dict[str, list] = {}
    for comp in components:
        by_name.setdefault(comp.normalized_name, []).append(comp)

    # --- duplicate declarations in manifest files -------------------------
    decl_seen: dict[str, str] = {}
    for dep in scan.declarations:
        if not _marker_active(dep):
            continue
        if dep.normalized_name in decl_seen:
            issues.append(_issue(
                "DUPLICATE_DECLARATION", WARNING, eco, dep.name,
                f"{dep.name!r} declared multiple times "
                f"({decl_seen[dep.normalized_name]}, {dep.source_file})"))
        else:
            decl_seen[dep.normalized_name] = dep.source_file

    # --- duplicate / multi-version components -----------------------------
    for norm, comps in sorted(by_name.items()):
        versions = {c.version for c in comps}
        if len(comps) > 1:
            if len(versions) > 1:
                severity = ERROR if eco == "python" else WARNING
                issues.append(_issue(
                    "DUPLICATE_COMPONENT", severity, eco, comps[0].name,
                    f"{comps[0].name!r} resolved to multiple versions: "
                    + ", ".join(sorted(v or "unresolved" for v in versions)),
                    versions=sorted(v or "" for v in versions)))
            else:
                issues.append(_issue(
                    "DUPLICATE_COMPONENT", WARNING, eco, comps[0].name,
                    f"{comps[0].name!r} appears "
                    f"{len(comps)}x at version {next(iter(versions))}",
                    duplicate=True))

    # --- declarations vs lock ---------------------------------------------
    if scan.declarations and not scan.lock_file:
        issues.append(_issue(
            "LOCK_MISSING", ERROR, eco, None,
            f"{eco}: manifest present but no lock file was found; "
            "dependency set is not fully resolved"))

    for dep in scan.declarations:
        if not _marker_active(dep):
            continue
        comps = by_name.get(dep.normalized_name, [])
        if not comps:
            issues.append(_issue(
                "MISSING_PACKAGE", ERROR, eco, dep.name,
                f"declared dependency {dep.name!r} ({dep.spec or 'any'}) "
                f"is not present in {scan.lock_file or 'any lock file'}"))
            continue
        _check_constraint(dep, comps, scan, issues)

    # --- unresolved versions / missing hashes -----------------------------
    for comp in components:
        if comp.version is None and comp.source_type == "declared":
            issues.append(_issue(
                "UNRESOLVED_VERSION", WARNING, eco, comp.name,
                f"{comp.name!r} has no resolved version (no lock file)"))
        if comp.source_type == "registry" and not comp.hashes \
                and scan.lock_file:
            issues.append(_issue(
                "MISSING_HASH", WARNING, eco, comp.name,
                f"registry component {comp.name!r}@{comp.version} has no "
                "content hash in the lock file"))

    # --- dependency graph integrity ---------------------------------------
    known = set(by_name)
    for comp in components:
        for dep_name in comp.dependencies:
            if dep_name not in known:
                issues.append(_issue(
                    "BROKEN_DEPENDENCY_EDGE", WARNING, eco, comp.name,
                    f"{comp.name!r}@{comp.version} depends on "
                    f"{dep_name!r} which is not present in the SBOM"))

    # --- parser warnings ---------------------------------------------------
    for message in scan.warnings:
        issues.append(_issue("PARSER_WARNING", INFO, eco, None, message))

    return issues


def _check_constraint(dep, comps, scan: ProjectScan, issues: list[dict]) -> None:
    spec = (dep.spec or "").strip()
    if dep.source_type in ("file", "vcs", "url", "workspace"):
        return
    if not spec or not _spec_is_version_range(spec, scan.ecosystem):
        return
    versions = [c.version for c in comps if c.version]
    if not versions:
        return
    match_spec = spec
    if scan.ecosystem == "python":
        match_spec = _poetry_to_pep508(spec)
        matcher = python_spec_matches
    else:
        matcher = npm_spec_matches
    satisfied = []
    for ver in versions:
        try:
            ok = matcher(match_spec, ver)
        except ParseError:
            ok = False
        satisfied.append(ok)
    if not any(satisfied):
        issues.append(_issue(
            "VERSION_MISMATCH", ERROR, scan.ecosystem, dep.name,
            f"declared spec for {dep.name!r} is {spec!r} but locked "
            f"version(s) are "
            f"{', '.join(sorted(versions))} in {scan.lock_file}",
            declared=spec, locked=sorted(versions)))


def _poetry_to_pep508(spec: str) -> str:
    """Translate Poetry's caret/tilde constraints into PEP 440 clauses.

    Poetry specs may also appear comma/pipe separated; each clause is
    translated independently and unions are dropped into >=-only clauses
    (a best-effort offline check — mismatch detection stays conservative).
    """

    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    out: list[str] = []
    for clause in clauses:
        if clause.startswith("^"):
            ver = clause[1:].strip()
            parts = ver.split(".")
            try:
                nums = [int(p) for p in parts]
            except ValueError:
                out.append(f">={ver}")
                continue
            if nums[0] > 0:
                out.append(f">={ver},<{nums[0] + 1}.0.0")
            elif len(nums) >= 2 and nums[1] > 0:
                out.append(f">={ver},<0.{nums[1] + 1}.0")
            elif len(nums) >= 3:
                out.append(f">={ver},<0.0.{nums[2] + 1}")
            else:
                out.append(f">={ver}")
        elif clause.startswith("~"):
            ver = clause[1:].strip()
            parts = ver.split(".")
            try:
                nums = [int(p) for p in parts]
            except ValueError:
                out.append(f">={ver}")
                continue
            if len(nums) >= 2:
                out.append(f">={ver},~={nums[0]}.{nums[1]}.0")
            else:
                out.append(f">={ver}")
        elif clause == "*":
            continue
        elif re.match(r"^\d+(?:\.\d+)*$", clause):
            # poetry/pipfile bare pin: "2.31.0" means ==2.31.0
            out.append(f"=={clause}")
        else:
            out.append(clause)
    return ",".join(out)


def _spec_is_version_range(spec: str, ecosystem: str) -> bool:
    spec = spec.strip()
    if not spec or spec in ("*", "latest"):
        return False
    if ecosystem == "python":
        # PEP 508 operators, poetry caret/tilde, or a bare pinned version
        return bool(re.match(
            r"^\s*(?:~=|===|==|!=|>=|<=|>|<|\^|~)\s*\d", spec)) or \
            bool(re.match(r"^\d+(?:\.\d+)*$", spec))
    # npm: ranges that start with an operator or a digit; tags/URLs excluded
    return bool(re.match(r"^(\^|~|>=|<=|>|<|=)?v?\d", spec)) or \
        spec.startswith(("^", "~", ">", "<", "="))


def _marker_active(dep) -> bool:
    try:
        return evaluate_marker(dep.markers)
    except ParseError:
        return True


def _issue(code: str, severity: str, ecosystem: str, component,
           message: str, **details) -> dict:
    issue = {
        "code": code,
        "severity": severity,
        "ecosystem": ecosystem,
        "component": component,
        "message": message,
    }
    if details:
        issue["details"] = details
    return issue


def sort_issues(issues: list[dict]) -> list[dict]:
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(issues, key=lambda i: (order.get(i["severity"], 3),
                                         i["ecosystem"],
                                         i["component"] or "", i["code"]))
