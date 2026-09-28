"""Command line interface.

    python -m sbomtool generate PROJECT --sbom out.json [--report r.json]
                                         [--policy p.json] [--licenses c.json]
    python -m sbomtool validate PROJECT --policy p.json [--licenses c.json]
                                         [--sbom existing.json]
    python -m sbomtool diff OLD.json NEW.json [--report diff.json]

Every command exits non-zero on malformed input or failed checks. Nothing
ever accesses the network.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import __version__
from .cyclonedx import build_cyclonedx
from .diff import diff_sboms
from .errors import SBOMError
from .integrity import analyze_integrity
from .parsers.project import scan_project
from .policy import evaluate_policy, load_license_catalogue, load_policy
from .report import build_report, stable_json


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sbomtool",
        description="Local, offline SBOM generation and validation tool.")
    parser.add_argument("--version", action="version",
                        version=f"sbomtool {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate",
                         help="generate a CycloneDX SBOM from a local project")
    gen.add_argument("project", help="project directory")
    gen.add_argument("--sbom", required=True, help="output SBOM JSON path")
    gen.add_argument("--report", help="optional validation report path")
    gen.add_argument("--policy", help="offline license policy JSON")
    gen.add_argument("--licenses",
                     help="offline package->license catalogue JSON")
    gen.add_argument("--name", help="override aggregate project name")

    val = sub.add_parser("validate",
                         help="validate a local project (and optional SBOM)")
    val.add_argument("project", help="project directory")
    val.add_argument("--sbom",
                     help="existing SBOM to re-verify against the project")
    val.add_argument("--policy", help="offline license policy JSON")
    val.add_argument("--licenses",
                     help="offline package->license catalogue JSON")
    val.add_argument("--report", help="write report JSON to this path")

    dif = sub.add_parser("diff", help="diff two SBOM JSON documents")
    dif.add_argument("old", help="older SBOM JSON")
    dif.add_argument("new", help="newer SBOM JSON")
    dif.add_argument("--report", help="write diff JSON to this path")

    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            return _cmd_generate(args)
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "diff":
            return _cmd_diff(args)
    except SBOMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

def _cmd_generate(args) -> int:
    scans = scan_project(args.project)
    issues = analyze_integrity(scans)

    catalogue = load_license_catalogue(args.licenses) if args.licenses else None
    policy = load_policy(args.policy) if args.policy else None
    violations = []
    if policy is not None:
        all_components = [c for scan in scans for c in scan.components]
        violations = evaluate_policy(policy, all_components, catalogue)

    bom = build_cyclonedx(scans, project_name=args.name or
                          os.path.basename(os.path.abspath(args.project)))
    _write_file(args.sbom, stable_json(bom))
    print(f"SBOM written to {args.sbom}")

    if args.report:
        report = build_report(
            scans, issues, violations,
            policy_path=os.path.abspath(args.policy) if args.policy else None,
            catalogue_path=os.path.abspath(args.licenses)
            if args.licenses else None,
            project_dir=os.path.abspath(args.project))
        _write_file(args.report, stable_json(report))
        print(f"report written to {args.report}")

    _print_summary(issues, violations)
    has_error = any(i["severity"] == "error" for i in issues) or \
        any(v["severity"] == "error" for v in violations)
    return 1 if has_error else 0


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def _cmd_validate(args) -> int:
    scans = scan_project(args.project)
    issues = list(analyze_integrity(scans))

    if args.sbom:
        issues.extend(_drift_check(args.sbom, scans))

    catalogue = load_license_catalogue(args.licenses) if args.licenses else None
    policy = load_policy(args.policy) if args.policy else None
    if policy is None:
        print("error: --policy is required for license validation",
              file=sys.stderr)
        return 2
    all_components = [c for scan in scans for c in scan.components]
    violations = evaluate_policy(policy, all_components, catalogue)

    if args.report:
        report = build_report(
            scans, issues, violations,
            policy_path=os.path.abspath(args.policy),
            catalogue_path=os.path.abspath(args.licenses)
            if args.licenses else None,
            project_dir=os.path.abspath(args.project))
        _write_file(args.report, stable_json(report))
        print(f"report written to {args.report}")

    _print_summary(issues, violations)
    has_error = any(i["severity"] == "error" for i in issues) or \
        any(v["severity"] == "error" for v in violations)
    return 1 if has_error else 0


def _drift_check(sbom_path: str, scans) -> list[dict]:
    """Re-generate the SBOM from local files and compare bytes/structure."""

    try:
        with open(sbom_path, encoding="utf-8") as fh:
            stored = json.load(fh)
    except json.JSONDecodeError as exc:
        return [{"code": "SBOM_CORRUPT", "severity": "error",
                 "ecosystem": "-", "component": None,
                 "message": f"stored SBOM is not valid JSON: {exc}"}]
    except OSError as exc:
        return [{"code": "SBOM_MISSING", "severity": "error",
                 "ecosystem": "-", "component": None,
                 "message": f"cannot read SBOM {sbom_path}: {exc}"}]
    if not isinstance(stored, dict) or \
            stored.get("bomFormat") != "CycloneDX":
        return [{"code": "SBOM_CORRUPT", "severity": "error",
                 "ecosystem": "-", "component": None,
                 "message": "stored file is not a CycloneDX document"}]

    rebuilt = build_cyclonedx(scans,
                              project_name=stored.get("metadata", {})
                              .get("component", {}).get("name"))
    drift: list[dict] = []
    stored_set = _component_signatures(stored)
    rebuilt_set = _component_signatures(rebuilt)
    for sig in sorted(stored_set - rebuilt_set):
        drift.append({"code": "SBOM_DRIFT", "severity": "error",
                      "ecosystem": sig[0], "component": sig[1],
                      "message": f"stored SBOM component not reproducible "
                                 f"from local project: {sig[1]}@{sig[2]}"})
    for sig in sorted(rebuilt_set - stored_set):
        drift.append({"code": "SBOM_DRIFT", "severity": "error",
                      "ecosystem": sig[0], "component": sig[1],
                      "message": f"local project component missing from "
                                 f"stored SBOM: {sig[1]}@{sig[2]}"})
    return drift


def _component_signatures(doc: dict) -> set[tuple[str, str, str, str]]:
    sigs: set[tuple[str, str, str, str]] = set()
    for comp in doc.get("components", []):
        if comp.get("type") not in ("library", "framework"):
            continue
        eco = "unknown"
        for prop in comp.get("properties", []):
            if prop.get("name") == "sbom:ecosystem":
                eco = prop.get("value", "unknown")
        sigs.add((eco, comp.get("name", ""), comp.get("version") or "",
                  comp.get("purl") or ""))
    return sigs


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def _cmd_diff(args) -> int:
    old = _read_sbom(args.old)
    new = _read_sbom(args.new)
    result = diff_sboms(old, new)
    text = stable_json(result)
    if args.report:
        _write_file(args.report, text)
        print(f"diff report written to {args.report}")
    else:
        sys.stdout.write(text)
    s = result["summary"]
    changed = (s["added"] + s["removed"] + s["upgraded"]
               + s["downgraded"] + s["changed"])
    return 1 if changed else 0


def _read_sbom(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise SBOMError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SBOMError(f"{path}: SBOM must be a JSON object")
    return data


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_file(path: str, content: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _print_summary(issues, violations) -> None:
    errors = [i for i in issues if i["severity"] == "error"]
    warns = [i for i in issues if i["severity"] == "warning"]
    verrors = [v for v in violations if v["severity"] == "error"]
    vwarns = [v for v in violations if v["severity"] == "warning"]
    print(f"integrity: {len(errors)} error(s), {len(warns)} warning(s); "
          f"license policy: {len(verrors)} violation(s), "
          f"{len(vwarns)} unknown-license warning(s)")
    for item in errors[:20] + verrors[:20]:
        print(f"  ERROR [{item['code']}] {item['message']}")
    for item in (warns[:10] + vwarns[:10]):
        print(f"  WARN  [{item['code']}] {item['message']}")


if __name__ == "__main__":
    raise SystemExit(main())
