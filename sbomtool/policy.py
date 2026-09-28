"""Offline license policy loading and evaluation.

Policy files are JSON with the shape::

    {
      "policy_version": 1,
      "action_on_unknown": "warn" | "deny" | "allow",
      "allow": ["MIT", "Apache-2.0"],
      "deny":  ["GPL-3.0-only"],
      "allow_unknown_components": ["some-internal-pkg"]
    }

Loading is deliberately strict: unknown keys, wrong types, overlapping
allow/deny entries or invalid action values raise :class:`PolicyError`.  A
caller that cannot load a policy must never emit a successful report.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .errors import PolicyError
from .models import Finding, Severity

_VALID_ACTIONS = {"allow", "warn", "deny"}
_TOP_KEYS = {
    "policy_version",
    "action_on_unknown",
    "allow",
    "deny",
    "allow_unknown_components",
}
_LIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")


@dataclass
class Policy:
    action_on_unknown: str = "warn"
    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    allow_unknown_components: set[str] = field(default_factory=set)

    def normalize_license(self, lic: str) -> str:
        """Map a handful of common spellings onto canonical SPDX ids."""

        canon = lic.strip()
        aliases = {
            "apache2": "Apache-2.0",
            "apache": "Apache-2.0",
            "mit license": "MIT",
            "bsd": "BSD-3-Clause",
        }
        return aliases.get(canon.lower(), canon)

    def evaluate_component(self, comp) -> Finding | None:
        """Return a Finding for a policy violation, else None (allowed)."""

        licenses = [self.normalize_license(l) for l in comp.licenses if l.strip()]
        name_override = comp.name in self.allow_unknown_components

        if not licenses:
            if name_override:
                return None
            if self.action_on_unknown == "allow":
                return None
            if self.action_on_unknown == "warn":
                return Finding(
                    "LICENSE_UNKNOWN", Severity.WARNING,
                    "component declares no recognizable license", comp.coord,
                )
            return Finding(
                "LICENSE_UNKNOWN_DENIED", Severity.ERROR,
                "component declares no recognizable license and policy denies unknown licenses",
                comp.coord,
            )

        denied = sorted(l for l in licenses if l in self.deny)
        if denied:
            return Finding(
                "LICENSE_DENIED", Severity.ERROR,
                f"license(s) {denied} are denied by policy", comp.coord,
            )

        # A component is allowed if at least one of its licenses is allowed;
        # but if NONE of its declared licenses are on the allow list and an
        # explicit allow list exists, it is unknown-to-policy.
        if self.allow:
            allowed_here = [l for l in licenses if l in self.allow]
            if not allowed_here:
                if name_override or self.action_on_unknown == "allow":
                    return None
                if self.action_on_unknown == "warn":
                    return Finding(
                        "LICENSE_NOT_LISTED", Severity.WARNING,
                        f"license(s) {sorted(set(licenses))} are not on the allow list",
                        comp.coord,
                    )
                return Finding(
                    "LICENSE_NOT_LISTED_DENIED", Severity.ERROR,
                    f"license(s) {sorted(set(licenses))} are not on the allow list",
                    comp.coord,
                )
        return None


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"malformed JSON policy file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError(f"policy {path}: top-level value must be a JSON object")
    extra = set(data) - _TOP_KEYS
    if extra:
        raise PolicyError(f"policy {path}: unknown keys {sorted(extra)}")

    version = data.get("policy_version")
    if version is not None and version != 1:
        raise PolicyError(f"policy {path}: unsupported policy_version {version!r}")

    action = data.get("action_on_unknown", "warn")
    if action not in _VALID_ACTIONS:
        raise PolicyError(
            f"policy {path}: action_on_unknown must be one of {sorted(_VALID_ACTIONS)}"
        )

    def as_licenses(value, key: str) -> set[str]:
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise PolicyError(f"policy {path}: {key!r} must be a list of strings")
        out = set()
        for item in value:
            lic = item.strip()
            if not lic or not _LIC_RE.match(lic):
                raise PolicyError(f"policy {path}: invalid license id {item!r} in {key}")
            out.add(lic)
        return out

    allow = as_licenses(data.get("allow", []), "allow")
    deny = as_licenses(data.get("deny", []), "deny")
    overlap = allow & deny
    if overlap:
        raise PolicyError(
            f"policy {path}: licenses {sorted(overlap)} appear in both allow and deny"
        )

    components = data.get("allow_unknown_components", [])
    if not isinstance(components, list) or not all(isinstance(x, str) for x in components):
        raise PolicyError(
            f"policy {path}: allow_unknown_components must be a list of strings"
        )

    return Policy(
        action_on_unknown=action,
        allow=allow,
        deny=deny,
        allow_unknown_components=set(components),
    )


def evaluate(policy: Policy, components) -> list[Finding]:
    findings = []
    for comp in sorted(components.values(), key=lambda c: c.coord):
        f = policy.evaluate_component(comp)
        if f is not None:
            findings.append(f)
    return findings
