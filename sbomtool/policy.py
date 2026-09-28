"""Offline license policy enforcement.

Policy file format (JSON)::

    {
      "version": 1,
      "policy": "allowlist" | "denylist",
      "allow": ["MIT", "Apache-2.0", ...],
      "deny":  ["GPL-3.0-only", ...],
      "onUnknown": "error" | "warn" | "allow",
      "ignore":  ["some-pkg"]          // normalized package names, any eco
    }

* ``allowlist`` (default): only licenses listed in ``allow`` are accepted;
  ``deny`` always wins.  Components without a license follow ``onUnknown``.
* ``denylist``: everything is accepted except licenses in ``deny``;
  components without a license follow ``onUnknown``.

Patterns are case-insensitive; the SPDX operators ``AND`` / ``OR`` / ``WITH``
are understood (an OR expression is allowed when any branch is allowed and
none is denied; an AND expression requires every branch to be allowed).

Any structural problem raises :class:`PolicyError` — a corrupt policy can
never produce a successful report.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from .errors import PolicyError
from .model import normalize_name

VALID_ON_UNKNOWN = {"error", "warn", "allow"}
VALID_POLICY_MODES = {"allowlist", "denylist"}


def load_policy(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path}: invalid JSON policy: {exc}") from exc
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    return validate_policy(data, path)


def validate_policy(data: dict, path: str = "<policy>") -> dict:
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: policy must be a JSON object")
    unknown_keys = set(data) - {"version", "policy", "allow", "deny",
                                "onUnknown", "ignore"}
    if unknown_keys:
        raise PolicyError(
            f"{path}: unknown policy keys: {sorted(unknown_keys)}")
    if "version" in data and data["version"] != 1:
        raise PolicyError(f"{path}: unsupported policy version "
                          f"{data['version']!r} (expected 1)")
    mode = data.get("policy", "allowlist")
    if mode not in VALID_POLICY_MODES:
        raise PolicyError(
            f"{path}: policy.mode must be one of "
            f"{sorted(VALID_POLICY_MODES)}, got {mode!r}")
    on_unknown = data.get("onUnknown", "error")
    if on_unknown not in VALID_ON_UNKNOWN:
        raise PolicyError(
            f"{path}: onUnknown must be one of {sorted(VALID_ON_UNKNOWN)}")
    allow, deny = data.get("allow", []), data.get("deny", [])
    ignore = data.get("ignore", [])
    for key, value in (("allow", allow), ("deny", deny),
                       ("ignore", ignore)):
        if not isinstance(value, list) or not all(
                isinstance(x, str) and x.strip() for x in value):
            raise PolicyError(
                f"{path}: {key!r} must be a list of non-empty strings")
    if mode == "allowlist" and not allow:
        raise PolicyError(
            f"{path}: allowlist policy must declare at least one allowed "
            "license in 'allow'")
    dupes = _duplicates([x.upper() for x in allow]) \
        or _duplicates([x.upper() for x in deny])
    if dupes:
        raise PolicyError(
            f"{path}: duplicate license entries: {sorted(dupes)}")
    return {
        "version": 1,
        "policy": mode,
        "allow": sorted({x.strip() for x in allow}),
        "deny": sorted({x.strip() for x in deny}),
        "onUnknown": on_unknown,
        "ignore": sorted({x.strip() for x in ignore}),
        "source": path,
    }


def _duplicates(items: list[str]) -> set[str]:
    seen: set[str] = set()
    dups: set[str] = set()
    for item in items:
        if item in seen:
            dups.add(item)
        seen.add(item)
    return dups


# ---------------------------------------------------------------------------
# Local license catalogue
# ---------------------------------------------------------------------------

def load_license_catalogue(path: str) -> dict:
    """Load ``{"python": {"name": "MIT"}, "npm": {...}}`` from local JSON."""

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"{path}: invalid JSON license catalogue: {exc}") from exc
    except OSError as exc:
        raise PolicyError(
            f"cannot read license catalogue {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: catalogue must be a JSON object")
    normalized: dict[str, dict[str, str]] = {}
    for ecosystem, table in data.items():
        if ecosystem not in ("python", "npm"):
            raise PolicyError(
                f"{path}: unknown ecosystem {ecosystem!r} "
                "(expected 'python' or 'npm')")
        if not isinstance(table, dict) or not all(
                isinstance(k, str) and isinstance(v, str)
                for k, v in table.items()):
            raise PolicyError(
                f"{path}: {ecosystem!r} must map package names to license "
                "strings")
        normalized[ecosystem] = {
            normalize_name(ecosystem, k): v.strip()
            for k, v in table.items() if v.strip()
        }
    return normalized


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class LicenseResolution:
    def __init__(self, catalogue: Optional[dict] = None):
        self.catalogue = catalogue or {}

    def resolve(self, component) -> list[str]:
        if component.licenses:
            return [lic for lic in component.licenses if lic and lic.strip()]
        entry = self.catalogue.get(component.ecosystem, {}).get(
            component.normalized_name)
        return [entry] if entry else []


def evaluate_policy(policy: dict, components,
                    catalogue: Optional[dict] = None) -> list[dict]:
    """Return a list of violation dicts (empty == policy satisfied)."""

    resolver = LicenseResolution(catalogue)
    ignored = set(policy["ignore"])
    violations: list[dict] = []
    for comp in sorted(components,
                       key=lambda c: (c.ecosystem, c.normalized_name,
                                      c.version or "")):
        if comp.is_root:
            continue
        if comp.normalized_name in ignored or \
                f"{comp.ecosystem}:{comp.normalized_name}" in ignored:
            continue
        licenses = resolver.resolve(comp)
        if not licenses:
            if policy["onUnknown"] != "allow":
                violations.append(_violation(
                    comp, [], "UNKNOWN_LICENSE",
                    policy["onUnknown"] if policy["onUnknown"] != "warn"
                    else "warning",
                    f"no license known for "
                    f"{comp.ecosystem}:{comp.name}@{comp.version or '?'}"))
            continue
        status, offending = _check_licenses(licenses, policy)
        if status == "denied":
            violations.append(_violation(
                comp, licenses, "DENIED_LICENSE", "error",
                f"{comp.ecosystem}:{comp.name}@{comp.version or '?'} uses "
                f"denied license {offending}"))
        elif status == "not-allowed":
            violations.append(_violation(
                comp, licenses, "LICENSE_NOT_ALLOWED", "error",
                f"{comp.ecosystem}:{comp.name}@{comp.version or '?'} "
                f"license {offending} is not on the allow list"))
    return violations


def _check_licenses(licenses: list[str], policy: dict):
    allow = {x.upper() for x in policy["allow"]}
    deny = {x.upper() for x in policy["deny"]}
    for raw in licenses:
        verdict, token = _eval_expression(raw, allow, deny)
        if verdict == "deny":
            return "denied", token
        if policy["policy"] == "allowlist" and verdict != "allow":
            return "not-allowed", token
    return "ok", None


def _eval_expression(raw: str, allow: set[str], deny: set[str]):
    """Evaluate an SPDX-ish expression; returns (verdict, token).

    OR is satisfied (allow) when any branch is allowed and is denied only
    when every branch is denied; otherwise unknown.
    """

    expr = raw.strip()
    or_branches = [b.strip() for b in re.split(r"\s+OR\s+", expr) if b.strip()]
    results = [_eval_and(b, allow, deny) for b in or_branches]
    if len(results) > 1:
        if any(v == "allow" for v, _ in results):
            return "allow", None
        if all(v == "deny" for v, _ in results):
            return "deny", next(t for v, t in results if t)
        return "unknown", next((t for v, t in results if t), None)
    return results[0]


def _eval_and(expr: str, allow: set[str], deny: set[str]):
    tokens = [t for t in re.split(r"\s+AND\s+", expr) if t.strip()]
    if not tokens:
        return "unknown", None
    outcomes = [_eval_with(t.strip(), allow, deny) for t in tokens]
    for verdict, token in outcomes:
        if verdict == "deny":
            return "deny", token
    if all(v == "allow" for v, _ in outcomes):
        return "allow", None
    return "unknown", next((t for v, t in outcomes if t), None)


def _eval_with(token: str, allow: set[str], deny: set[str]):
    # "GPL-2.0-only WITH Classpath-exception-2.0" — drop WITH clause
    head = re.split(r"\s+WITH\s+", token)[0].strip("() ")
    up = head.upper()
    if up in deny:
        return "deny", head
    if up in allow:
        return "allow", None
    return "unknown", head


def _violation(component, licenses, code: str, severity: str,
               message: str) -> dict:
    return {
        "code": code,
        "severity": severity,
        "ecosystem": component.ecosystem,
        "component": component.name,
        "normalized_name": component.normalized_name,
        "version": component.version,
        "licenses": list(licenses),
        "message": message,
    }
