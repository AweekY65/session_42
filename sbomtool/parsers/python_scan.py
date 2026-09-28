"""Python ecosystem parser.

Recognised files:
  * requirements*.txt         (declarations, incl. -r includes, --hash,
                               direct URLs, editable installs)
  * pyproject.toml            (PEP 621 project.dependencies / optional,
                               Poetry [tool.poetry] sections)
  * poetry.lock
  * Pipfile / Pipfile.lock

Only local files are read.
"""

from __future__ import annotations

import glob
import os
import re
import sys
from typing import Optional

from ..errors import ParseError
from ..hashing import normalize_lock_hash
from ..model import Component, DeclaredDependency, ProjectScan, RootProject, normalize_name
from ..pep508 import evaluate_marker, parse_requirement, parse_url_requirement

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - project requires 3.11+
    import tomli as tomllib  # type: ignore

_ECO = "python"

_REQUIREMENTS_DIRECTIVES = {
    "-i", "--index-url", "--extra-index-url", "--find-links", "-f",
    "--no-index", "--pre", "--no-deps", "--only-binary",
    "--prefer-binary", "--require-hashes", "--use-feature",
    "--trusted-host", "--constraints", "-c", "--no-binary",
    "--only-binary",
}


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

def parse_requirements_txt(path: str,
                           _seen: Optional[set] = None
                           ) -> list[DeclaredDependency]:
    """Parse a pip requirements file into declared dependencies.

    ``-r`` / ``--requirement`` includes are followed on the local disk.
    Unsupported options raise :class:`ParseError`.
    """

    path = os.path.abspath(path)
    _seen = _seen if _seen is not None else set()
    if path in _seen:
        raise ParseError(f"recursive -r include detected at {path}")
    _seen.add(path)

    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc

    deps: list[DeclaredDependency] = []
    logical = _join_continuations(raw)
    for lineno, line in enumerate(logical, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-e ") or stripped.startswith("--editable "):
            target = stripped.split(" ", 1)[1].strip()
            deps.append(_local_path_dependency(target, path))
            continue
        if stripped.startswith("-r ") or stripped.startswith("--requirement "):
            target = stripped.split(" ", 1)[1].strip().strip("'\"")
            included = os.path.join(os.path.dirname(path), target)
            deps.extend(parse_requirements_txt(included, _seen))
            continue
        if stripped.startswith("-"):
            token = stripped.split("=", 1)[0].split()[0]
            if token in _REQUIREMENTS_DIRECTIVES:
                continue
            raise ParseError(
                f"{path}:{lineno}: unsupported pip option: {token}")
        try:
            deps.append(_requirement_line(stripped, path))
        except ParseError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ParseError(
                f"{path}:{lineno}: invalid requirement: {stripped!r}") from exc
    return deps


def _join_continuations(text: str) -> list[str]:
    lines: list[str] = []
    buf = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
        else:
            buf += line
            lines.append(buf)
            buf = ""
    if buf:
        lines.append(buf)
    return lines


def _requirement_line(line: str, source: str) -> DeclaredDependency:
    # strip inline comment
    line = re.sub(r"\s+#.*$", "", line)
    hashes: dict[str, str] = {}
    # Pull out --hash=... pieces before requirement parsing.
    pieces = line.split()
    kept: list[str] = []
    for piece in pieces:
        m = re.match(r"--hash=([A-Za-z0-9]+)[=:]([A-Fa-f0-9]+)$", piece)
        if m:
            algo, value = normalize_lock_hash(f"{m.group(1)}={m.group(2)}")
            hashes[algo] = value
        elif piece.startswith("--"):
            key = piece.split("=", 1)[0]
            if key not in _REQUIREMENTS_DIRECTIVES:
                raise ParseError(f"unsupported option in requirement: {piece}")
        else:
            kept.append(piece)
    line = " ".join(kept)

    if "://" in line or line.startswith(("git+", "/", "./", "../", "~/")) \
            or line.startswith("file://"):
        name = line.split("@", 1)[0].strip()
        url = line
        if "@" in line and ("://" in line.split("@", 1)[1]
                            or line.split("@", 1)[1].startswith("/")):
            name, url = (p.strip() for p in line.split("@", 1))
        info = parse_url_requirement(url, default_name=name or None)
        if not info["name"]:
            raise ParseError(f"cannot determine package name from URL: {url}")
        norm = normalize_name(_ECO, info["name"])
        local_hash = _hash_local_reference(info["source_type"], url, source)
        hashes.update(local_hash)
        return DeclaredDependency(
            ecosystem=_ECO, name=info["name"], normalized_name=norm,
            spec=info["version"] or url, source_type=info["source_type"],
            source_file=source, hashes=hashes)

    parsed = parse_requirement(line)
    return DeclaredDependency(
        ecosystem=_ECO, name=parsed["name"],
        normalized_name=normalize_name(_ECO, parsed["name"]),
        spec=parsed["spec"], source_type="declared",
        source_file=source, markers=parsed["markers"],
        extras=tuple(parsed["extras"]), hashes=hashes)


def _local_path_dependency(target: str, source: str) -> DeclaredDependency:
    target = target.strip().strip("'\"")
    # editable VCS: "-e git+https://...#egg=foo"
    if "://" in target or target.startswith("git+"):
        info = parse_url_requirement(target)
        name = info["name"] or os.path.basename(target.rstrip("/"))
        stype = info["source_type"]
        spec = info["version"] or target
    else:
        name = os.path.basename(target.rstrip("/")) or target
        pyproject = os.path.join(os.path.dirname(source), target,
                                 "pyproject.toml")
        if os.path.isfile(pyproject):
            name = _read_project_name(pyproject) or name
        stype = "file"
        spec = "0.0.0-local"
    return DeclaredDependency(
        ecosystem=_ECO, name=name,
        normalized_name=normalize_name(_ECO, name),
        spec=spec, source_type=stype, source_file=source)


def _read_project_name(pyproject_path: str) -> Optional[str]:
    try:
        with open(pyproject_path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, _TomlError):
        return None
    return (data.get("project", {}).get("name")
            or data.get("tool", {}).get("poetry", {}).get("name"))


def _hash_local_reference(source_type: str, url: str,
                          manifest_path: str) -> dict[str, str]:
    """Hash a local file/dir referenced from a manifest, when present."""

    if source_type != "file":
        return {}
    from ..hashing import hash_path

    target = url[7:] if url.startswith("file://") else url
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(manifest_path), target)
    digest = hash_path(target)
    return {"SHA-256": digest} if digest else {}


# ---------------------------------------------------------------------------
# pyproject.toml (PEP 621 + Poetry)
# ---------------------------------------------------------------------------

def parse_pyproject_toml(path: str) -> tuple[RootProject,
                                             list[DeclaredDependency]]:
    data = _load_toml(path)
    project = data.get("project", {})
    poetry = data.get("tool", {}).get("poetry", {})

    deps: list[DeclaredDependency] = []
    if project:
        for spec_line in project.get("dependencies", []):
            deps.append(_declared_from_pep508(spec_line, path, "required"))
        for group in project.get("optional-dependencies", {}).values():
            for spec_line in group:
                dep = _declared_from_pep508(spec_line, path, "optional")
                deps.append(dep)
    if poetry:
        deps.extend(_poetry_dependencies(poetry.get("dependencies", {}),
                                         path, "required"))
        groups = poetry.get("group", {})
        if isinstance(groups, dict):
            for gname, group in groups.items():
                scope = "required" if gname == "main" else "optional"
                gdeps = group.get("dependencies", {}) if isinstance(
                    group, dict) else {}
                deps.extend(_poetry_dependencies(gdeps, path, scope))
        dev = poetry.get("dev-dependencies", {})
        if isinstance(dev, dict):
            deps.extend(_poetry_dependencies(dev, path, "optional"))

    name = project.get("name") or poetry.get("name") or \
        os.path.basename(os.path.dirname(os.path.abspath(path)))
    licenses = []
    if project.get("license"):
        lic = project["license"]
        if isinstance(lic, str):
            licenses.append(lic)
        elif isinstance(lic, dict) and lic.get("text"):
            licenses.append(lic["text"])
    if poetry.get("license"):
        licenses.append(poetry["license"])

    root = RootProject(
        ecosystem=_ECO, name=name,
        version=project.get("version") or poetry.get("version"),
        description=project.get("description") or poetry.get("description"),
        licenses=licenses, source_file=path)
    return root, deps


def _declared_from_pep508(line: str, source: str,
                          scope: str) -> DeclaredDependency:
    parsed = parse_requirement(line)
    dep = DeclaredDependency(
        ecosystem=_ECO, name=parsed["name"],
        normalized_name=normalize_name(_ECO, parsed["name"]),
        spec=parsed["spec"], source_file=source,
        markers=parsed["markers"], extras=tuple(parsed["extras"]),
        optional=(scope == "optional"))
    return dep


def _poetry_dependencies(table: dict, source: str,
                         scope: str) -> list[DeclaredDependency]:
    deps: list[DeclaredDependency] = []
    if not isinstance(table, dict):
        raise ParseError(f"{source}: poetry dependencies must be a table")
    for name, constraint in table.items():
        if name.lower() == "python":
            continue
        spec, stype, markers, extras = _poetry_constraint(constraint)
        deps.append(DeclaredDependency(
            ecosystem=_ECO, name=name,
            normalized_name=normalize_name(_ECO, name),
            spec=spec, source_type=stype, source_file=source,
            markers=markers, extras=tuple(extras),
            optional=(scope == "optional")))
    return deps


def _poetry_constraint(constraint) -> tuple[str, str, Optional[str], list]:
    if isinstance(constraint, str):
        return constraint, "declared", None, []
    if isinstance(constraint, dict):
        if "git" in constraint:
            ref = constraint.get("rev") or constraint.get("tag") \
                or constraint.get("branch") or ""
            return ref or "vcs", "vcs", None, []
        if "path" in constraint:
            return constraint.get("version", "0.0.0-local"), "file", None, []
        if "url" in constraint:
            return constraint["url"], "url", None, []
        spec = constraint.get("version", "*")
        markers = constraint.get("markers")
        extras = constraint.get("extras", [])
        if isinstance(extras, str):
            extras = [extras]
        return spec, "declared", markers, extras
    if isinstance(constraint, list):
        # Multiple constraints table (POETRY new style) — take versions.
        specs = []
        for item in constraint:
            s, _, m, e = _poetry_constraint(item)
            specs.append(s)
        return " || ".join(specs), "declared", None, []
    raise ParseError(f"unsupported poetry constraint: {constraint!r}")


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------

def parse_poetry_lock(path: str) -> list[Component]:
    data = _load_toml(path)
    if "package" not in data or not isinstance(data["package"], list):
        raise ParseError(f"{path}: missing [[package]] section")
    components: list[Component] = []
    for entry in data["package"]:
        if not isinstance(entry, dict) or "name" not in entry:
            raise ParseError(f"{path}: invalid lock package entry")
        name = entry["name"]
        version = entry.get("version")
        if not version:
            raise ParseError(f"{path}: package {name!r} has no version")
        licenses = [entry["license"]] if entry.get("license") else []
        hashes: dict[str, str] = {}
        for fentry in entry.get("files", []):
            if not isinstance(fentry, dict) or "hash" not in fentry:
                raise ParseError(
                    f"{path}: invalid 'files' entry in package {name!r}")
            try:
                algo, value = normalize_lock_hash(fentry["hash"])
            except ValueError as exc:
                raise ParseError(
                    f"{path}: invalid hash for {name}: {exc}") from exc
            hashes[algo] = value
        dep_names, dep_specs = _poetry_lock_deps(entry.get("dependencies"))
        components.append(Component(
            ecosystem=_ECO, name=name,
            normalized_name=normalize_name(_ECO, name),
            version=version, source_type="registry",
            source_file=path, description=entry.get("description"),
            licenses=licenses, hashes=hashes,
            dependencies=dep_names,
            dependency_specs=dep_specs))
    return components


def _poetry_lock_deps(raw) -> tuple[list[str], dict[str, str]]:
    names: list[str] = []
    specs: dict[str, str] = {}
    if not isinstance(raw, dict):
        return names, specs
    for name, constraint in raw.items():
        norm = normalize_name(_ECO, name)
        if isinstance(constraint, str):
            specs[norm] = constraint
        elif isinstance(constraint, dict):
            s, _, markers, _ = _poetry_constraint(constraint)
            specs[norm] = s
            if markers:
                # keep the marker constraint visible in the SBOM property
                specs[norm] = f"{s} ; {markers}"
        elif isinstance(constraint, list):
            # multiple marker-conditional constraints on the same dep
            variants = []
            for item in constraint:
                s, _, markers, _ = _poetry_constraint(item)
                variants.append(f"{s} ; {markers}" if markers else s)
            specs[norm] = " || ".join(variants)
        else:
            specs[norm] = "*"
        names.append(norm)
    return sorted(set(names)), specs


# ---------------------------------------------------------------------------
# Pipfile / Pipfile.lock
# ---------------------------------------------------------------------------

def parse_pipfile(path: str) -> tuple[RootProject, list[DeclaredDependency]]:
    data = _load_toml(path)
    deps: list[DeclaredDependency] = []
    for section, scope in (("packages", "required"),
                           ("dev-packages", "optional")):
        table = data.get(section, {})
        if not isinstance(table, dict):
            raise ParseError(f"{path}: [{section}] must be a table")
        for name, constraint in table.items():
            deps.append(_pipfile_dep(name, constraint, path, scope))
    name = data.get("name") or os.path.basename(
        os.path.dirname(os.path.abspath(path)))
    root = RootProject(ecosystem=_ECO, name=name,
                       version=data.get("version"), source_file=path)
    return root, deps


def _pipfile_dep(name, constraint, source, scope) -> DeclaredDependency:
    markers = None
    if isinstance(constraint, str):
        spec = constraint
        stype = "declared"
        if spec.startswith(("git+", "https://", "http://")):
            stype = "vcs" if "git" in spec else "url"
    elif isinstance(constraint, dict):
        if "git" in constraint:
            spec = constraint.get("ref") or constraint.get("tag") or "vcs"
            stype = "vcs"
        elif "path" in constraint:
            spec = constraint.get("version", "0.0.0-local")
            stype = "file"
        elif "version" in constraint:
            spec = constraint["version"]
            stype = "declared"
        else:
            raise ParseError(f"{source}: Pipfile dep {name} has no version")
        markers = constraint.get("markers")
    else:
        raise ParseError(f"{source}: invalid Pipfile constraint for {name}")
    return DeclaredDependency(
        ecosystem=_ECO, name=name,
        normalized_name=normalize_name(_ECO, name),
        spec=spec, source_type=stype, source_file=source,
        markers=markers)


def parse_pipfile_lock(path: str) -> list[Component]:
    data = _load_json(path)
    components: list[Component] = []
    for section in ("default", "develop"):
        table = data.get(section, {})
        if not isinstance(table, dict):
            raise ParseError(f"{path}: {section!r} must be an object")
        for name, entry in table.items():
            if not isinstance(entry, dict):
                raise ParseError(f"{path}: invalid entry for {name}")
            info = parse_url_requirement(entry.get("path", "")) \
                if "path" in entry else None
            stype = "registry"
            if "path" in entry:
                stype = "file"
            elif "git" in entry:
                stype = "vcs"
            elif "file" in entry:
                stype = "url"
            version = entry.get("version")
            if version:
                version = version.lstrip("=").lstrip()
            elif stype == "vcs":
                version = entry.get("ref") or "vcs"
            else:
                raise ParseError(
                    f"{path}: locked package {name!r} has no version")
            hashes: dict[str, str] = {}
            for raw in entry.get("hashes", []):
                try:
                    algo, value = normalize_lock_hash(raw)
                except ValueError:
                    raise ParseError(
                        f"{path}: invalid hash for {name}: {raw!r}")
                hashes[algo] = value
            components.append(Component(
                ecosystem=_ECO, name=name,
                normalized_name=normalize_name(_ECO, name),
                version=version, source_type=stype, source_file=path,
                hashes=hashes))
    return components


# ---------------------------------------------------------------------------
# Lock-from-requirements (requirements.txt with pinned versions / hashes)
# ---------------------------------------------------------------------------

def locked_components_from_requirements(
        deps: list[DeclaredDependency]) -> list[Component]:
    """Treat pinned requirements entries as locked components."""

    components: list[Component] = []
    for dep in deps:
        pinned = re.match(r"==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$",
                          (dep.spec or "").strip())
        version = pinned.group(1) if pinned else None
        if not pinned and dep.source_type in ("file", "vcs"):
            version = dep.spec
        components.append(Component(
            ecosystem=dep.ecosystem, name=dep.name,
            normalized_name=dep.normalized_name,
            version=version,
            source_type=dep.source_type if dep.source_type != "declared"
            else ("registry" if version else "declared"),
            source_file=dep.source_file, hashes=dict(dep.hashes),
            scope="required"))
    return components


# ---------------------------------------------------------------------------
# Project scanning
# ---------------------------------------------------------------------------

def scan_python_project(root_dir: str) -> ProjectScan | None:
    """Scan a directory for Python project files; None if none found."""

    root_dir = os.path.abspath(root_dir)
    pyproject = os.path.join(root_dir, "pyproject.toml")
    pipfile = os.path.join(root_dir, "Pipfile")
    req_files = sorted(
        os.path.basename(p) for p in glob.glob(os.path.join(
            root_dir, "requirements*.txt")))

    if not (os.path.isfile(pyproject) or os.path.isfile(pipfile)
            or req_files):
        return None

    declarations: list[DeclaredDependency] = []
    components: list[Component] = []
    manifest_files: list[str] = []
    warnings: list[str] = []
    root = RootProject(ecosystem=_ECO,
                       name=os.path.basename(root_dir) or "project")

    poetry_lock = os.path.join(root_dir, "poetry.lock")
    pipfile_lock = os.path.join(root_dir, "Pipfile.lock")

    if os.path.isfile(pyproject):
        root_p, deps_p = parse_pyproject_toml(pyproject)
        root = root_p
        declarations.extend(deps_p)
        manifest_files.append("pyproject.toml")
    if os.path.isfile(pipfile):
        root_f, deps_f = parse_pipfile(pipfile)
        if not manifest_files:
            root = root_f
        declarations.extend(deps_f)
        manifest_files.append("Pipfile")
    for req in req_files:
        full = os.path.join(root_dir, req)
        declarations.extend(parse_requirements_txt(full))
        manifest_files.append(req)

    if os.path.isfile(poetry_lock):
        components.extend(parse_poetry_lock(poetry_lock))
    if os.path.isfile(pipfile_lock):
        if components:
            raise ParseError(
                "multiple python lock files present (poetry.lock and "
                "Pipfile.lock); refusing ambiguous resolution")
        components.extend(parse_pipfile_lock(pipfile_lock))

    lock_file = None
    if os.path.isfile(poetry_lock):
        lock_file = "poetry.lock"
    elif os.path.isfile(pipfile_lock):
        lock_file = "Pipfile.lock"
    else:
        # A fully pinned requirements file (every dep ==X or hashed) acts
        # as its own lock; otherwise manifests have no lock.
        if declarations and all(
                d.source_type in ("file", "vcs", "url") or
                re.match(r"==\s*[A-Za-z0-9]", d.spec or "")
                for d in declarations):
            components = locked_components_from_requirements(declarations)
            lock_file = ", ".join(manifest_files)
        else:
            components = locked_components_from_requirements(declarations)

    if not lock_file:
        warnings.append(
            "no lock file found; components are derived from declarations "
            "and versions may be unresolved")

    _relativize_sources(declarations, components, root_dir)
    if os.path.isabs(root.source_file):
        root.source_file = os.path.relpath(root.source_file, root_dir)

    return ProjectScan(
        ecosystem=_ECO, root=root, declarations=declarations,
        components=components, manifest_files=manifest_files,
        lock_file=lock_file, warnings=warnings,
        root_direct={d.normalized_name: d.spec for d in declarations})


def _relativize_sources(declarations, components, root_dir: str) -> None:
    for items in (declarations, components):
        for item in items:
            sf = getattr(item, "source_file", "")
            if sf and os.path.isabs(sf):
                item.source_file = os.path.relpath(sf, root_dir)


# ---------------------------------------------------------------------------
# shared loaders
# ---------------------------------------------------------------------------

_TomlError = tomllib.TOMLDecodeError if hasattr(tomllib, "TOMLDecodeError") \
    else Exception


def _load_toml(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except _TomlError as exc:
        raise ParseError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc


def _load_json(path: str) -> dict:
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ParseError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc
