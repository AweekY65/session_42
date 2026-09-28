"""Core data model shared by parsers, analyzer and serializers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    PYTHON = "python"
    NPM = "npm"


# Source types describe *where* a component was discovered.
SOURCE_DECLARATION = "declaration"      # declared dependency file (pyproject / package.json)
SOURCE_LOCK = "lock"                    # materialized in a lock file
SOURCE_LOCAL = "local"                  # present only in an on-disk package dir
SOURCE_LOCK_LOCAL = "lock+local"        # locked AND found on disk


@dataclass(frozen=True)
class Hash:
    """A content hash obtained locally (lock metadata or on-disk content)."""

    alg: str            # e.g. "sha256"
    value: str          # lowercase hex digest
    origin: str         # "lock" | "local-record" | "local-content"

    def to_cdx(self) -> dict:
        return {"alg": self.alg.upper(), "content": self.value}


@dataclass
class Component:
    """A single software package component.

    Identity is ``(ecosystem, name, version)`` with names normalized to the
    ecosystem's canonical form (PEP 503 for PyPI, lowercase for npm).
    """

    ecosystem: Ecosystem
    name: str
    version: str
    source_type: str = SOURCE_LOCK
    declared_constraint: str | None = None
    hashes: list[Hash] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)   # SPDX-ish identifiers
    dependencies: set[str] = field(default_factory=set)  # component keys of deps
    origins: list[str] = field(default_factory=list)     # files proving the component
    scope: str = "required"             # "required" | "optional"
    purl: str | None = None

    @property
    def key(self) -> str:
        return component_key(self.ecosystem, self.name)

    @property
    def coord(self) -> str:
        """Name@version coordinate used in dependency arrays."""
        return f"{self.ecosystem.value}:{self.name}@{self.version}"

    def merge(self, other: "Component") -> None:
        """Merge another description of the same component into this one."""
        seen = {(h.alg, h.value) for h in self.hashes}
        for h in other.hashes:
            if (h.alg, h.value) not in seen:
                seen.add((h.alg, h.value))
                self.hashes.append(h)
        for lic in other.licenses:
            if lic not in self.licenses:
                self.licenses.append(lic)
        self.dependencies |= other.dependencies
        for o in other.origins:
            if o not in self.origins:
                self.origins.append(o)
        if other.declared_constraint and not self.declared_constraint:
            self.declared_constraint = other.declared_constraint
        if self.source_type == SOURCE_LOCK and other.source_type == SOURCE_LOCAL:
            self.source_type = SOURCE_LOCK_LOCAL
        elif self.source_type == SOURCE_LOCAL and other.source_type == SOURCE_LOCK:
            self.source_type = SOURCE_LOCK_LOCAL
        if other.scope == "required":
            self.scope = "required"


def component_key(ecosystem: Ecosystem, name: str) -> str:
    return f"{ecosystem.value}:{name}"


@dataclass
class ProjectDecl:
    """Result of parsing a human-authored dependency declaration file."""

    ecosystem: Ecosystem
    project_name: str | None
    project_version: str | None
    # name -> {"constraint": str, "scope": "required"|"optional"}
    declared: dict[str, dict] = field(default_factory=dict)
    source_file: str = ""


@dataclass
class LockedPkg:
    """One package instance as recorded in a lock file."""

    ecosystem: Ecosystem
    name: str
    version: str
    dependencies: set[str] = field(default_factory=set)   # component keys
    hashes: list[Hash] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)
    scope: str = "required"
    origin: str = ""
    path: str = ""          # npm v2/v3 node_modules path (identity)


@dataclass
class LockData:
    """Result of parsing a lock file."""

    ecosystem: Ecosystem
    packages: list[LockedPkg] = field(default_factory=list)
    source_file: str = ""
    lock_format: str = ""


@dataclass
class SBOM:
    """A unified bill of materials, possibly spanning ecosystems."""

    project_name: str
    project_version: str
    root_dir: str
    components: dict[str, Component] = field(default_factory=dict)
    # raw declarations keyed by ecosystem, for integrity checks
    declarations: dict[Ecosystem, ProjectDecl] = field(default_factory=dict)
    lock_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # component key -> set of versions recorded across parsed lock files
    raw_lock_versions: dict[str, set[str]] = field(default_factory=dict)


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    code: str
    severity: Severity
    message: str
    component: str | None = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "component": self.component,
            "message": self.message,
        }
