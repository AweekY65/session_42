"""Command-line interface (offline; standard library only).

Exit codes:

* 0 success
* 1 report produced but findings/differences fail the requested gate
* 2 input or policy error (malformed/missing files) -- no success report emitted
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .analyzer import analyze, integrity_findings
from .cyclonedx import dumps as cdx_dumps
from .diff import diff_sboms
from .errors import InputError, PolicyError, SbomError
from .models import Severity
from .policy import evaluate, load_policy
from .report import render_json, render_text


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbomtool",
        description="Offline local SBOM generator, integrity checker and license policy gate.",
    )
    p.add_argument("--version", action="version", version=f"localsbom {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate a stable CycloneDX SBOM from a local project")
    g.add_argument("project_dir", help="project directory containing manifests/lock files")
    g.add_argument("-o", "--output", help="write SBOM JSON here (default: stdout)")
    g.add_argument("--no-local", action="store_true",
                   help="do not scan local install trees (site-packages / node_modules)")

    c = sub.add_parser("check", help="integrity checks + offline license policy evaluation")
    c.add_argument("project_dir")
    c.add_argument("--policy", help="offline license policy JSON file")
    c.add_argument("-o", "--output", help="write JSON report here (default: human text to stdout)")
    c.add_argument("--json", action="store_true", help="emit a machine-readable JSON report")
    c.add_argument("--no-local", action="store_true")
    c.add_argument("--allow-warnings", action="store_true",
                   help="exit 0 even when warnings are present (errors still fail)")

    d = sub.add_parser("diff", help="compare two SBOM documents, order-insensitive")
    d.add_argument("old_sbom")
    d.add_argument("new_sbom")
    d.add_argument("--json", action="store_true")
    return p


def _write(path: str | None, text: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def _cmd_generate(args) -> int:
    sbom = analyze(args.project_dir, use_local=not args.no_local)
    _write(args.output, cdx_dumps(sbom))
    return 0


def _cmd_check(args) -> int:
    sbom = analyze(args.project_dir, use_local=not args.no_local)
    findings = integrity_findings(sbom)
    policy = None
    if args.policy:
        policy = load_policy(args.policy)  # raises PolicyError on bad policy
        findings.extend(evaluate(policy, sbom.components))

    n_err = sum(1 for f in findings if f.severity == Severity.ERROR)
    n_warn = sum(1 for f in findings if f.severity == Severity.WARNING)
    summary = [
        f"project : {sbom.project_name}@{sbom.project_version}",
        f"root    : {os.path.abspath(sbom.root_dir)}",
        f"components: {len(sbom.components)}  errors: {n_err}  warnings: {n_warn}",
    ]
    if args.json or args.output:
        payload = {
            "project": {"name": sbom.project_name, "version": sbom.project_version,
                        "root": os.path.abspath(sbom.root_dir)},
            "component_count": len(sbom.components),
            "error_count": n_err,
            "warning_count": n_warn,
            "findings": [f.to_dict() for f in findings],
        }
        _write(args.output, render_json(payload))
        if not args.json:
            sys.stdout.write(render_text(title="SBOM check", findings=findings,
                                         summary_lines=summary))
    else:
        sys.stdout.write(render_text(title="SBOM check", findings=findings,
                                     summary_lines=summary))

    if n_err:
        return 1
    if n_warn and not args.allow_warnings:
        return 1
    return 0


def _cmd_diff(args) -> int:
    result = diff_sboms(args.old_sbom, args.new_sbom)
    if args.json:
        sys.stdout.write(render_json(result.to_dict()))
    else:
        lines = ["=== SBOM diff ===",
                 f"{args.old_sbom} -> {args.new_sbom}", ""]
        lines.append(f"added     ({len(result.added)}): "
                     + (", ".join(result.added) or "-"))
        lines.append(f"removed   ({len(result.removed)}): "
                     + (", ".join(result.removed) or "-"))
        for e in result.upgraded:
            lines.append(f"upgraded  {e['component']}: {e['from']} -> {e['to']}")
        for e in result.downgraded:
            lines.append(f"downgraded {e['component']}: {e['from']} -> {e['to']}")
        for e in result.version_same_hash_changed:
            lines.append(f"hash changed {e['component']} @ {e['version']}")
        for e in result.license_changed:
            lines.append(
                f"license changed {e['component']}: {e['from']} -> {e['to']}"
            )
        for edge in result.dependency_edges_added:
            lines.append(f"dep + {edge}")
        for edge in result.dependency_edges_removed:
            lines.append(f"dep - {edge}")
        if result.is_empty:
            lines.append("no differences")
        sys.stdout.write("\n".join(lines) + "\n")
    return 0 if result.is_empty else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            return _cmd_generate(args)
        if args.command == "check":
            return _cmd_check(args)
        if args.command == "diff":
            return _cmd_diff(args)
    except PolicyError as exc:
        sys.stderr.write(f"policy error: {exc}\n")
        return 2
    except InputError as exc:
        sys.stderr.write(f"input error: {exc}\n")
        return 2
    except SbomError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
