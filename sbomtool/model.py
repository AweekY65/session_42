"""Core data model shared by every parser and analysis stage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Name normalisation
# ---------------------------------------------------------------------------

_PYTHON_SAFE = re.compile(r"[-_.]+")
# npm scoped names: "@Scope/Pkg" -> "@scope/pkg"
_NPM_SCOPE = re.compile(r"^@([^/]+)/(.+)$")


def normalize_name(ecosystem: str, name: str) -> str:
    """Return the canonical name used for identity / comparison.

    * Python: PEP 503 — lower case, runs of ``-_.`` collapse to ``-``.
    * npm:    lower case; the scope is preserved (``@scope/pkg``).
    """

    name = name.strip()
    if ecosystem == "python":
        return _PYTHON_SAFE.sub("-", name).lower()
    if ecosystem == "npm":
        m = _NPM_SCOPE.match(name)
        if m:
            return "@" + m.group(1).lower() + "/" + m.group(2).lower()
        return name.lower()
    return name.lower()


def ecosystem_label(ecosystem: str) -> str:
    return {"python": "Python", "npm": "npm"}.get(ecosystem, ecosystem)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

#: Source type values:
#:   registry  -- resolved from a package registry in a lock file
#:   declared  -- only present in a manifest, no lock resolution
#:   url       -- direct http(s)/file URL requirement
#:   file      -- local filesystem path dependency
#:   vcs       -- local/offline VCS reference (git+..., etc.)
#:   workspace -- npm workspace / link dependency
VALID_SOURCE_TYPES = {"registry", "declared", "url", "file", "vcs", "workspace"}


@dataclass
class DeclaredDependency:
    """One dependency statement found in a manifest file."""

    ecosystem: str
    name: str                       # name as written
    normalized_name: str
    spec: str                       # version constraint / raw spec
    source_type: str = "declared"
    source_file: str = ""
    markers: Optional[str] = None  # python environment markers
    extras: tuple[str, ...] = ()
    hashes: dict[str, str] = field(default_factory=dict)
    optional: bool = False

    def key(self) -> tuple[str, str]:
        return self.ecosystem, self.normalized_name


@dataclass
class Component:
    """A resolved package component (the SBOM unit)."""

    ecosystem: str
    name: str
    normalized_name: str
    version: Optional[str] = None
    source_type: str = "registry"
    source_file: str = ""
    description: Optional[str] = None
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    #: normalized names of direct dependencies of THIS component
    dependencies: list[str] = field(default_factory=list)
    #: raw dependency specs of this component: normalized name -> spec
    dependency_specs: dict[str, str] = field(default_factory=dict)
    scope: str = "required"        # required | optional | excluded
    purl: Optional[str] = None
    properties: dict[str, str] = field(default_factory=dict)
    is_root: bool = False

    def key(self) -> tuple[str, str, Optional[str]]:
        return self.ecosystem, self.normalized_name, self.version

    def bom_ref(self) -> str:
        """Stable CycloneDX bom-ref. Unique for duplicated components."""

        if self.is_root:
            return f"root:{self.ecosystem}:{self.normalized_name}"
        ver = self.version or "unversioned"
        if self.ecosystem == "python":
            base = f"pkg:pypi/{self.normalized_name}@{ver}"
        elif self.ecosystem == "npm":
            base = f"pkg:npm/{self.normalized_name}@{ver}"
        else:
            base = f"pkg:{self.ecosystem}/{self.normalized_name}@{ver}"
        if self.source_type != "registry":
            base += f"#source={self.source_type}"
        return base


@dataclass
class RootProject:
    """The project under analysis (emitted as the CycloneDX metadata component)."""

    ecosystem: str
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    licenses: list[str] = field(default_factory=list)
    source_file: str = ""
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class ProjectScan:
    """Everything one ecosystem parser discovered in a project directory."""

    ecosystem: str
    root: RootProject
    declarations: list[DeclaredDependency] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    manifest_files: list[str] = field(default_factory=list)
    lock_file: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    #: normalized name -> declared spec for the root project's direct deps
    root_direct: dict[str, str] = field(default_factory=dict)
