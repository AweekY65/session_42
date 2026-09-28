"""Parsers for Node.js dependency declarations and lock files.

Supported declarations: ``package.json``.
Supported locks: ``package-lock.json`` (v1, v2, v3) and classic ``yarn.lock`` (v1).
"""

from __future__ import annotations

import json
import os
import re

from ..errors import InputError
from ..hashing import parse_integrity
from ..models import (
    Ecosystem,
    LockData,
    LockedPkg,
    ProjectDecl,
    component_key,
)
from ..naming import normalize_name

_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"malformed JSON in {path}: {exc}") from exc


def _check_dep_table(table, path: str, section: str) -> dict:
    if not isinstance(table, dict):
        raise InputError(f"{section} must be an object in {path}")
    for name, spec in table.items():
        if not isinstance(name, str) or not isinstance(spec, str):
            raise InputError(f"{section} entries must map strings to strings in {path}")
    return table


# ------------------------------------------------------------ declaration

def parse_declaration(path: str) -> ProjectDecl:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise InputError(f"package.json must be a JSON object: {path}")
    decl = ProjectDecl(
        ecosystem=Ecosystem.NPM,
        project_name=data.get("name") if isinstance(data.get("name"), str) else None,
        project_version=data.get("version") if isinstance(data.get("version"), str) else None,
        source_file=path,
    )
    prod = _check_dep_table(data.get("dependencies") or {}, path, "dependencies")
    for name, spec in prod.items():
        if not spec.startswith(("file:", "link:", "git+", "github:", "http://", "https://", "git://")):
            decl.declared[normalize_name(name, Ecosystem.NPM)] = {
                "constraint": spec,
                "scope": "required",
            }
    for section in ("devDependencies", "optionalDependencies", "peerDependencies"):
        table = _check_dep_table(data.get(section) or {}, path, section)
        for name, spec in table.items():
            if spec.startswith(("file:", "link:", "git+", "github:", "http://", "https://", "git://")):
                continue
            n = normalize_name(name, Ecosystem.NPM)
            decl.declared.setdefault(n, {"constraint": spec, "scope": "optional"})
    return decl


# ------------------------------------------------------------------ locks

def parse_lock(path: str, fmt: str) -> LockData:
    if fmt == "npm":
        return _parse_package_lock(path)
    if fmt == "yarn":
        return _parse_yarn_lock(path)
    raise InputError(f"unknown node lock format: {fmt}")


def _pkg_name_from_path(pkg_path: str) -> str:
    # node_modules/foo, packages/x/node_modules/@scope/bar, node_modules/@scope/baz
    idx = pkg_path.rfind("node_modules/")
    rel = pkg_path[idx + len("node_modules/"):] if idx >= 0 else pkg_path
    return normalize_name(rel, Ecosystem.NPM)


def _dep_ref_to_name(ref: str) -> str | None:
    if ref.startswith("node_modules/"):
        ref = ref[len("node_modules/"):]
    if not ref or ref.startswith((".", "/")):
        return None
    return normalize_name(ref, Ecosystem.NPM)


def _extract_licenses(info: dict) -> list[str]:
    lic = info.get("license")
    if isinstance(lic, str) and lic.strip():
        return [lic.strip()]
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return [lic["type"].strip()]
    old = info.get("licenses")
    if isinstance(old, list):
        out = []
        for entry in old:
            if isinstance(entry, dict) and isinstance(entry.get("type"), str):
                out.append(entry["type"].strip())
        return out
    return []


def _parse_package_lock(path: str) -> LockData:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise InputError(f"package-lock.json must be a JSON object: {path}")
    lock = LockData(ecosystem=Ecosystem.NPM, source_file=path, lock_format="npm")
    version = int(data.get("lockfileVersion", 1))
    if version in (2, 3):
        packages = data.get("packages")
        if not isinstance(packages, dict):
            raise InputError(f"lockfileVersion {version} requires a 'packages' object in {path}")
        for pkg_path, info in packages.items():
            if not isinstance(info, dict):
                raise InputError(f"malformed package entry {pkg_path!r} in {path}")
            if pkg_path == "":
                continue  # root project
            if info.get("link") or info.get("extraneous"):
                continue
            if info.get("inBundle"):
                continue
            ver = info.get("version")
            if not isinstance(ver, str):
                raise InputError(f"package {pkg_path!r} missing string version in {path}")
            name = _pkg_name_from_path(pkg_path)
            locked = LockedPkg(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=ver,
                licenses=_extract_licenses(info),
                origin=path,
                path=pkg_path,
            )
            integrity = info.get("integrity")
            if isinstance(integrity, str):
                h = parse_integrity(integrity)
                if h is None:
                    raise InputError(f"bad integrity value for {pkg_path!r} in {path}")
                locked.hashes.append(h)
            if info.get("dev") or info.get("devOptional"):
                locked.scope = "optional"
            for section in ("dependencies", "peerDependencies"):
                for dep_name in (info.get(section) or {}):
                    locked.dependencies.add(
                        component_key(Ecosystem.NPM, normalize_name(dep_name, Ecosystem.NPM))
                    )
            lock.packages.append(locked)
        return lock
    if version == 1:
        root_deps = data.get("dependencies")
        if root_deps is not None and not isinstance(root_deps, dict):
            raise InputError(f"malformed 'dependencies' in {path}")
        seen: set[tuple[str, str]] = set()

        def walk(deps: dict, scope: str) -> None:
            for raw_name, info in deps.items():
                if not isinstance(info, dict):
                    raise InputError(f"malformed lock entry for {raw_name} in {path}")
                name = normalize_name(raw_name, Ecosystem.NPM)
                ver = info.get("version")
                if not isinstance(ver, str):
                    raise InputError(f"package {name} missing string version in {path}")
                if info.get("dev"):
                    scope = "optional"
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    locked = LockedPkg(
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        version=ver,
                        licenses=_extract_licenses(info),
                        scope=scope,
                        origin=path,
                        path=f"node_modules/{name}",
                    )
                    integrity = info.get("integrity")
                    if isinstance(integrity, str):
                        h = parse_integrity(integrity)
                        if h is None:
                            raise InputError(f"bad integrity value for {name} in {path}")
                        locked.hashes.append(h)
                    elif isinstance(info.get("shasum"), str) and info["shasum"]:
                        from ..hashing import Hash
                        locked.hashes.append(Hash("sha1", info["shasum"].lower(), "lock"))
                    for child in info.get("requires", {}) or {}:
                        locked.dependencies.add(
                            component_key(Ecosystem.NPM, normalize_name(child, Ecosystem.NPM))
                        )
                    lock.packages.append(locked)
                walk(info.get("dependencies") or {}, scope)

        walk(root_deps or {}, "required")
        return lock
    raise InputError(f"unsupported lockfileVersion {version} in {path}")


# ------------------------------------------------------------- yarn v1

_YARN_HEADER_RE = re.compile(r"^(?:'|\"|)(.+?)(?:'|\"|)\s*:\s*$")


def _parse_yarn_lock(path: str) -> LockData:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path} is not valid UTF-8: {exc}") from exc

    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("__metadata:") or "__metadata:" in text[:200]:
        raise InputError(
            f"only classic yarn.lock (v1) is supported; {path} appears to be yarn berry (v2+)"
        )

    lock = LockData(ecosystem=Ecosystem.NPM, source_file=path, lock_format="yarn")
    blocks = re.split(r"\n(?=\S)", text)  # split on unindented lines
    for block in blocks:
        lines = [ln for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        # leading comment blocks (e.g. the autogen banner)
        while lines and lines[0].lstrip().startswith("#"):
            lines.pop(0)
        if not lines:
            continue
        m = _YARN_HEADER_RE.match(lines[0])
        if not m:
            raise InputError(f"unparseable yarn.lock entry header {lines[0]!r} in {path}")
        specs = [s.strip().strip("'\"") for s in m.group(1).split(",")]
        names: set[str] = set()
        for spec in specs:
            spec = re.sub(r"@(npm:)?[^@]*$", "", spec) if spec.startswith("@") else spec.rsplit("@", 1)[0]
            if spec:
                names.add(normalize_name(spec, Ecosystem.NPM))
        body: dict[str, str] = {}
        nested_dep_names: list[str] = []
        i = 1
        while i < len(lines):
            ln = lines[i]
            i += 1
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip(" \t"))
            if indent == 0:
                raise InputError(f"bad indentation in yarn.lock entry {lines[0]!r} ({path})")
            # classic yarn v1 uses 'key "value"' (space); tolerate 'key:' too
            key_m = re.match(r"^\s+([A-Za-z0-9-]+)(?:\s*:\s*|\s+)(.*?)\s*$", ln)
            if not key_m:
                raise InputError(f"unparseable line {ln!r} in yarn.lock entry ({path})")
            key, val = key_m.group(1), (key_m.group(2) or "").strip()
            if key in ("dependencies", "optionalDependencies") and not val:
                while i < len(lines):
                    child = lines[i]
                    if not child.strip():
                        i += 1
                        continue
                    cindent = len(child) - len(child.lstrip(" \t"))
                    if cindent <= indent:
                        break
                    cm = re.match(r'^\s+(@?[\w][\w\-\.\/@]*)\s+["\'][^"\']+["\']\s*$', child)
                    if not cm:
                        raise InputError(f"unparseable nested dependency {child!r} in {path}")
                    nested_dep_names.append(cm.group(1))
                    i += 1
                continue
            body[key] = val.strip('"')
        if "version" not in body:
            raise InputError(f"yarn.lock entry {lines[0]!r} missing version in {path}")
        version = body["version"]
        for name in names:
            locked = LockedPkg(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                origin=path,
                path=f"node_modules/{name}",
            )
            integrity = body.get("resolved", "")
            if "integrity" in body:
                h = parse_integrity(body["integrity"])
                if h is None:
                    raise InputError(f"bad integrity value for {name} in {path}")
                locked.hashes.append(h)
            for dep_name in nested_dep_names:
                locked.dependencies.add(
                    component_key(Ecosystem.NPM, normalize_name(dep_name, Ecosystem.NPM))
                )
            lock.packages.append(locked)
    return lock
