"""Report assembly and deterministic JSON serialization."""

from __future__ import annotations

import json

from .integrity import RANK, sort_issues

REPORT_SCHEMA_VERSION = 1


def build_report(scans, integrity_issues, policy_violations=None,
                 policy_path=None, catalogue_path=None,
                 project_dir=None) -> dict:
    issues = sort_issues(list(integrity_issues))
    violations = sorted(policy_violations or [],
                        key=lambda v: (v["ecosystem"], v["normalized_name"],
                                       v.get("version") or ""))
    severities = [i["severity"] for i in issues] + \
                 [v["severity"] for v in violations]
    status = "pass"
    if any(s == "error" for s in severities):
        status = "fail"
    elif any(s == "warning" for s in severities):
        status = "warn"

    ecosystems = sorted({scan.ecosystem for scan in scans})
    component_count = sum(len(scan.components) for scan in scans)
    return {
        "reportSchemaVersion": REPORT_SCHEMA_VERSION,
        "status": status,
        "project": project_dir,
        "ecosystems": ecosystems,
        "componentCount": component_count,
        "summary": {
            "errors": severities.count("error"),
            "warnings": severities.count("warning"),
            "infos": severities.count("info"),
            "integrity": _tally(issues),
            "policy": _tally(violations),
        },
        "policy": {
            "file": policy_path,
            "licenseCatalogue": catalogue_path,
            "evaluated": policy_path is not None,
        },
        "integrityIssues": issues,
        "licenseViolations": violations,
    }


def _tally(items) -> dict:
    result: dict[str, int] = {}
    key = "code"
    for item in items:
        result[item[key]] = result.get(item[key], 0) + 1
    return dict(sorted(result.items()))


def stable_json(data: dict | list, indent: int = 2) -> str:
    """Serialize with sorted keys and trailing newline — byte stable."""

    return json.dumps(data, indent=indent, sort_keys=True,
                      ensure_ascii=False) + "\n"


def max_severity(issues: list[dict]) -> str:
    worst = "info"
    for item in issues:
        sev = item.get("severity", "info")
        if RANK.get(sev, 0) > RANK.get(worst, 0):
            worst = sev
    return worst
