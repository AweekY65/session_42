"""Node.js ecosystem parser.

Recognised files:
  * package.json          (dependencies / devDependencies /
                           peerDependencies / optionalDependencies)
  * package-lock.json     (lockfileVersion 1, 2 and 3)
  * yarn.lock             (classic / v1 flat format)

Only local files are read.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from ..errors import ParseError
from ..hashing import normalize_lock_hash
from ..model import Component, DeclaredDependency, ProjectScan, RootProject, normalize_name

_ECO = "npm"
_MANIFEST_SECTIONS = (
    ("dependencies", "required"),
    ("devDependencies", "optional"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "optional"),
)


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------

def parse_package_json(path: str) -> tuple[RootProject, list[DeclaredDependency]]:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ParseError(f"{path}: package.json must contain an object")
    deps: list[DeclaredDependency] = []
    for section, scope in _MANIFEST_SECTIONS:
        table = data.get(section, {})
        if not isinstance(table, dict):
            raise ParseError(f"{path}: {section!r} must be an object")
        for name, spec in table.items():
            if not isinstance(spec, str):
                raise ParseError(
                    f"{path}: {section}.{name} must be a version string")
            deps.append(DeclaredDependency(
                ecosystem=_ECO, name=name,
                normalized_name=normalize_name(_ECO, name),
                spec=spec, source_type=_npm_source_type(spec),
                source_file=path, optional=(scope == "optional")))
    licenses = []
    if isinstance(data.get("license"), str):
        licenses = [data["license"]]
    elif isinstance(data.get("licenses"), list):
        licenses = [item.get("type") for item in data["licenses"]
                    if isinstance(item, dict) and item.get("type")]
    root = RootProject(
        ecosystem=_ECO,
        name=data.get("name") or os.path.basename(
            os.path.dirname(os.path.abspath(path))),
        version=data.get("version"), description=data.get("description"),
        licenses=licenses, source_file=path)
    return root, deps


def _npm_source_type(spec: str) -> str:
    if spec.startswith(("file:", "link:")):
        return "file"
    if spec.startswith("workspace:"):
        return "workspace"
    if spec.startswith(("git+", "git://", "http://", "https://",
                        "github:")):
        return "vcs"
    if "/" in spec and not spec.startswith("@") and not re.match(
            r"^[\^~>=<*0-9vxX ]", spec):
        return "file"
    return "declared"


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------

def parse_package_lock(path: str,
                       root_declarations: list[DeclaredDependency]
                       ) -> list[Component]:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ParseError(f"{path}: package-lock.json must contain an object")
    version = data.get("lockfileVersion")
    if version not in (1, 2, 3):
        raise ParseError(
            f"{path}: unsupported lockfileVersion {version!r} (expected 1-3)")

    root_direct: dict[str, str] = {}  # normalized name -> raw spec

    components: list[Component] = []
    seen: dict[tuple[str, str, str], Component] = {}

    def add_component(node_path: str, node: dict, default_link: bool = False):
        if not isinstance(node, dict):
            raise ParseError(f"{path}: lock entry {node_path!r} must be object")
        if node.get("extraneous") and not node.get("version"):
            return
        link = node.get("link", False)
        name = _node_name(node_path, node)
        if name is None:
            return
        ver = node.get("version") or "0.0.0-local"
        if link or default_link:
            stype = "workspace"
        elif "resolved" in node:
            resolved = node["resolved"] or ""
            stype = "file" if resolved.startswith(("file:", "/")) else "registry"
        elif "integrity" in node:
            stype = "registry"
        else:
            stype = "registry" if is_npm_version(ver) else "file"
        hashes: dict[str, str] = {}
        integrity = node.get("integrity")
        if integrity:
            try:
                algo, value = normalize_lock_hash(integrity)
            except ValueError:
                raise ParseError(
                    f"{path}: invalid integrity for {name}: {integrity!r}")
            hashes[algo] = value
        key = (normalize_name(_ECO, name), ver, stype)
        if key in seen:
            comp = seen[key]
        else:
            comp = Component(
                ecosystem=_ECO, name=name,
                normalized_name=normalize_name(_ECO, name),
                version=ver, source_type=stype, source_file=path,
                licenses=[node["license"]] if isinstance(
                    node.get("license"), str) else [],
                hashes=hashes)
            components.append(comp)
            seen[key] = comp
        return comp

    if version == 1:
        # v1: top-level "dependencies" tree; name keys, nested "dependencies".
        root_pkg = data.get("dependencies", {})
        if not isinstance(root_pkg, dict):
            raise ParseError(f"{path}: v1 'dependencies' must be an object")
        root_specs = {d.normalized_name: d.spec for d in root_declarations}
        _walk_v1(root_pkg, "", components, seen, add_component, path,
                 root_specs, root_direct)
    else:
        # v2/v3: "packages" keyed by node_modules path.
        packages = data.get("packages")
        if packages is None:
            raise ParseError(f"{path}: missing 'packages' section")
        if not isinstance(packages, dict):
            raise ParseError(f"{path}: 'packages' must be an object")
        v2root = packages.get("", {})
        if not isinstance(v2root, dict):
            raise ParseError(f"{path}: packages[''] must be an object")
        for pkg_path, node in packages.items():
            if pkg_path == "":
                continue
            add_component(pkg_path, node)
        # dependency edges from packages
        for pkg_path, node in packages.items():
            if pkg_path == "":
                continue
            comp = _component_for_path(pkg_path, node, seen)
            if comp is None:
                continue
            _attach_npm_deps(comp, node.get("requires"), pkg_path,
                             packages, seen)
        # direct edges from root package entry
        for section in ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies"):
            for name in (v2root.get(section) or {}):
                root_direct[normalize_name(_ECO, name)] = \
                    v2root[section][name]

    # order independent stable component order
    components.sort(key=lambda c: (c.normalized_name, c.version or "",
                                   c.source_type))
    return components, root_direct


def _walk_v1(tree, parent_path, components, seen, add_component, path,
             root_specs, root_direct):
    for name, node in tree.items():
        node_path = (parent_path + "/" if parent_path else "") + name
        comp = add_component(node_path, node)
        # v1 requires are in "requires"; nested deps shadow same-name parent
        requires = node.get("requires", {}) if isinstance(node, dict) else {}
        nested = node.get("dependencies", {}) if isinstance(node, dict) else {}
        nested_names = set(nested.keys())
        for req_name, req_spec in requires.items():
            if req_name in nested_names:
                # edge resolves to the nested copy
                nested_node = nested[req_name]
                child = add_component(node_path + "/" + req_name, nested_node)
            else:
                child = _find_top_level(components, req_name)
            if child is not None and child is not comp:
                if child.normalized_name not in comp.dependencies:
                    comp.dependencies.append(child.normalized_name)
                    comp.dependency_specs[child.normalized_name] = req_spec
        if parent_path == "":
            root_direct[comp.normalized_name] = \
                root_specs.get(comp.normalized_name, node.get("version", ""))
        if nested:
            _walk_v1(nested, node_path, components, seen, add_component,
                     path, root_specs, root_direct)


def _find_top_level(components, name):
    norm = normalize_name(_ECO, name)
    for comp in components:
        if comp.normalized_name == norm:
            return comp
    return None


def _node_name(pkg_path: str, node: dict) -> Optional[str]:
    from urllib.parse import unquote

    if node.get("name"):
        return node["name"]
    if not pkg_path:
        return None
    tail = pkg_path.split("node_modules/")[-1]
    return unquote(tail) if tail else None


def _find_seen(seen, norm):
    """Fallback when node resolution cannot locate a required package."""

    for (n, _v, _s), comp in sorted(seen.items(),
                                    key=lambda kv: kv[0][1] or ""):
        if n == norm:
            return comp
    return None


def _component_for_path(pkg_path, node, seen):
    name = _node_name(pkg_path, node)
    if name is None:
        return None
    ver = node.get("version") or "0.0.0-local"
    link = node.get("link", False)
    stype = "workspace" if link else None
    if stype is None:
        resolved = node.get("resolved") or ""
        stype = "file" if resolved.startswith(("file:", "/")) else "registry"
        if "resolved" not in node and "integrity" not in node and \
                not is_npm_version(ver):
            stype = "file"
    return seen.get((normalize_name(_ECO, name), ver, stype))


def _attach_npm_deps(comp, requires, pkg_path, packages, seen):
    if not isinstance(requires, dict):
        return
    for req_name, req_spec in requires.items():
        if isinstance(req_spec, str) and req_spec.startswith("workspace:"):
            req_spec = req_spec.split(":", 1)[1] or "*"
        norm = normalize_name(_ECO, req_name)
        resolved_path = _resolve_node_path(packages, pkg_path, req_name)
        child = None
        if resolved_path is not None:
            child = _component_for_path(resolved_path,
                                        packages[resolved_path], seen)
        if child is None:
            # Fallback by name (hoisting quirks); if still absent, the
            # dangling edge is recorded for integrity analysis.
            child = _find_seen(seen, norm)
        if child is None:
            if norm not in comp.dependencies:
                comp.dependencies.append(norm)
                comp.dependency_specs[norm] = req_spec
        elif child is not comp:
            if norm not in comp.dependencies:
                comp.dependencies.append(norm)
                comp.dependency_specs[norm] = req_spec


def _resolve_node_path(packages, owner_path: str, dep_name: str):
    """Node resolution: <owner>/node_modules/<dep>, then walk upward."""

    candidate = (owner_path + "/" if owner_path else "") + \
        f"node_modules/{dep_name}"
    if candidate in packages:
        return candidate
    # walk upward; scoped names already contain their '/' so this is fine
    dirs = owner_path.split("/") if owner_path else []
    while dirs:
        dirs.pop()
        base = "/".join(dirs)
        candidate = (base + "/" if base else "") + \
            f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate
    return None


def is_npm_version(value: str) -> bool:
    from ..versions import parse_npm_version

    return parse_npm_version(value or "") is not None


# ---------------------------------------------------------------------------
# yarn.lock (classic / v1)
# ---------------------------------------------------------------------------

def parse_yarn_lock(path: str,
                    root_declarations: list[DeclaredDependency]
                    ) -> list[Component]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    entries = _parse_yarn_blocks(text, path)
    components: list[Component] = []
    index: dict[str, Component] = {}
    for req_patterns, block in entries:
        version = block.get("version")
        resolved = block.get("resolved", "")
        if not version:
            raise ParseError(
                f"{path}: yarn entry {req_patterns!r} has no version")
        names = [_yarn_pattern_name(p) for p in req_patterns]
        name = names[0]
        stype = "file" if resolved.startswith(("file:", "/")) else "registry"
        comp = Component(
            ecosystem=_ECO, name=name,
            normalized_name=normalize_name(_ECO, name),
            version=version.strip('"'), source_type=stype,
            source_file=path)
        for rawhash in block.get("integrity", "").split():
            rawhash = rawhash.strip()
            if not rawhash:
                continue
            try:
                algo, value = normalize_lock_hash(rawhash)
            except ValueError:
                raise ParseError(
                    f"{path}: invalid integrity for {name}: {rawhash!r}")
            comp.hashes[algo] = value
        components.append(comp)
        for pattern in req_patterns:
            index[pattern] = comp
            index[_yarn_pattern_name(pattern)] = comp

    # yarn v1 records only direct edges ("dependencies" in each block)
    for req_patterns, block in entries:
        comp = index[req_patterns[0]]
        for dep_name, dep_spec in (block.get("dependencies") or {}).items():
            dep_spec = dep_spec.strip('"')
            child = index.get(f"{dep_name}@{dep_spec}")
            if child is None:
                child = index.get(dep_name)
            if child is not None and child is not comp:
                norm = normalize_name(_ECO, dep_name)
                if norm not in comp.dependencies:
                    comp.dependencies.append(norm)
                    comp.dependency_specs[norm] = dep_spec

    root_direct: dict[str, str] = {}
    for dep in root_declarations:
        root_direct[dep.normalized_name] = dep.spec

    components.sort(key=lambda c: (c.normalized_name, c.version or ""))
    return components, root_direct


_YARN_HEADER = re.compile(r'^(?:"(.*)"|([^\s"][^:]*)):\s*$')
_YARN_KV = re.compile(r'^(?P<key>[A-Za-z@][A-Za-z0-9._/@-]*)\s+(?P<val>.+)$')


def _parse_yarn_blocks(text: str, path: str):
    """Parse classic yarn.lock into ``(patterns, block)`` tuples.

    ``block`` maps scalar keys to strings and the nested ``dependencies``
    table to a dict.
    """

    entries = []
    current_header = None
    current_block: dict = {}
    nested_section: str | None = None  # "dependencies" etc.
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")):
            # top-level header
            m = _YARN_HEADER.match(raw_line)
            if not m:
                raise ParseError(f"{path}: malformed yarn.lock header: "
                                 f"{raw_line!r}")
            if current_header is not None:
                entries.append((current_header, current_block))
            patterns_raw = m.group(1) if m.group(1) is not None \
                else m.group(2)
            current_header = _split_yarn_patterns(patterns_raw.strip())
            current_block = {}
            nested_section = None
            continue
        if current_header is None:
            raise ParseError(f"{path}: orphaned yarn.lock line: {raw_line!r}")

        if re.match(r"^(dependencies|optionalDependencies|"
                    r"peerDependencies|bin|resolutions):$", stripped):
            nested_section = stripped[:-1]
            if nested_section in ("dependencies", "optionalDependencies",
                                  "peerDependencies"):
                current_block[nested_section] = {}
            continue

        m = _YARN_KV.match(stripped)
        if not m:
            raise ParseError(f"{path}: malformed yarn.lock line: "
                             f"{raw_line!r}")
        key, value = m.group("key"), m.group("val").strip()
        if nested_section in ("dependencies", "optionalDependencies",
                              "peerDependencies"):
            current_block[nested_section][key.strip('"')] = value
        else:
            current_block[key] = value
            nested_section = None
    if current_header is not None:
        entries.append((current_header, current_block))
    return entries


def _split_yarn_patterns(raw: str) -> list[str]:
    # quoted, comma separated list:  left-pad@^1.0.0, left-pad@^1.2.0
    return [p.strip().strip('"') for p in raw.split(",") if p.strip()]


def _yarn_pattern_name(pattern: str) -> str:
    if pattern.startswith("@"):
        # @scope/name@range -> split at last @ that is not position 0
        idx = pattern.rfind("@")
        if idx > 0:
            return pattern[:idx]
        return pattern
    return pattern.split("@", 1)[0]


# ---------------------------------------------------------------------------
# Project scanning
# ---------------------------------------------------------------------------

def scan_npm_project(root_dir: str) -> Optional[ProjectScan]:
    root_dir = os.path.abspath(root_dir)
    pkg_json = os.path.join(root_dir, "package.json")
    if not os.path.isfile(pkg_json):
        return None
    root, declarations = parse_package_json(pkg_json)

    npm_lock = os.path.join(root_dir, "package-lock.json")
    yarn_lock = os.path.join(root_dir, "yarn.lock")
    components: list[Component] = []
    lock_file = None
    warnings: list[str] = []
    root_direct: dict[str, str] = {}

    if os.path.isfile(npm_lock) and os.path.isfile(yarn_lock):
        raise ParseError(
            "both package-lock.json and yarn.lock present; refusing "
            "ambiguous resolution")
    if os.path.isfile(npm_lock):
        components, root_direct = parse_package_lock(npm_lock, declarations)
        lock_file = "package-lock.json"
    elif os.path.isfile(yarn_lock):
        components, root_direct = parse_yarn_lock(yarn_lock, declarations)
        lock_file = "yarn.lock"
    else:
        warnings.append(
            "no npm lock file found; components are derived from "
            "package.json declarations")
        for dep in declarations:
            components.append(Component(
                ecosystem=_ECO, name=dep.name,
                normalized_name=dep.normalized_name,
                version=None, source_type="declared",
                source_file=dep.source_file,
                scope="optional" if dep.optional else "required"))
        root_direct = {d.normalized_name: d.spec for d in declarations}

    for items in ((declarations,), (components,)):
        for item in items[0]:
            sf = getattr(item, "source_file", "")
            if sf and os.path.isabs(sf):
                item.source_file = os.path.relpath(sf, root_dir)
    if os.path.isabs(root.source_file):
        root.source_file = os.path.relpath(root.source_file, root_dir)

    scan = ProjectScan(
        ecosystem=_ECO, root=root, declarations=declarations,
        components=components, manifest_files=["package.json"],
        lock_file=lock_file, warnings=warnings, root_direct=root_direct)
    return scan


# ---------------------------------------------------------------------------
def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ParseError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc
