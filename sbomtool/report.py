"""Human-readable and machine-readable report rendering."""

from __future__ import annotations

import json

from .models import Severity

_SEV_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


def render_text(
    *,
    title: str,
    findings: list,
    summary_lines: list[str] | None = None,
) -> str:
    lines = [f"=== {title} ==="]
    if summary_lines:
        lines.extend(summary_lines)
        lines.append("")
    if not findings:
        lines.append("no issues found")
    else:
        for f in sorted(findings, key=lambda x: (_SEV_ORDER[x.severity], x.code, x.component or "")):
            target = f" [{f.component}]" if f.component else ""
            lines.append(f"{f.severity.value.upper():7} {f.code}{target}: {f.message}")
    return "\n".join(lines) + "\n"


def render_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
