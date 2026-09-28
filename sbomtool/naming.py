"""Package-name normalization and purl construction (local, deterministic)."""

from __future__ import annotations

import re

from .models import Ecosystem

_PEP503_RE = re.compile(r"[-_.]+")


def normalize_name(name: str, ecosystem: Ecosystem) -> str:
    """Return the canonical component name for an ecosystem.

    * PyPI: PEP 503 -- lowercase, runs of ``-_.`` collapse to ``-``.
    * npm: lowercase; scoped names (``@scope/pkg``) are preserved.
    """

    name = name.strip()
    if ecosystem == Ecosystem.PYTHON:
        return _PEP503_RE.sub("-", name).lower()
    if name.startswith("@") and "/" in name:
        scope, pkg = name[1:].split("/", 1)
        return "@" + scope.lower() + "/" + pkg.lower()
    return name.lower()


def make_purl(ecosystem: Ecosystem, name: str, version: str) -> str:
    if ecosystem == Ecosystem.PYTHON:
        return f"pkg:pypi/{name}@{version}"
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"
