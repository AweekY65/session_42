"""Parsers for Python dependency declarations and lock files.

Supported declarations: ``pyproject.toml`` (PEP 621 + Poetry), ``requirements.in``.
Supported locks: ``uv.lock``, ``Pipfile.lock``, hashed ``requirements.txt``.
"""

from __future__ import annotations

import json
import os
import re
import tomllib

from ..errors import InputError
from ..hashing import parse_hex_hash
from ..models import (
    Ecosystem,
    Hash,
    LockData,
    LockedPkg,
    ProjectDecl,
    component_key,
)
from ..naming import normalize_name

_NAME_RE = re.compile(r"^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$")
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"(.*?)\s*$",
    re.DOTALL,
)


# ---------------------------------------------------------------- PEP 508

def parse_requirement(text: str) -> tuple[str, str, str] | None:
    """Split a PEP 508 requirement into ``(name, specifier, marker)``."""

    text = text.strip()
    if not text or text.startswith("#"):
        return None
    marker = ""
    if ";" in text:
        text, marker = text.split(";", 1)
        text, marker = text.strip(), marker.strip()
    m = _REQ_RE.match(text)
    if not m:
        return None
    name, spec = m.group(1), m.group(2).strip()
    if not _NAME_RE.match(name):
        return None
    if spec and not re.match(r"^(===|==|!=|~=|>=|<=|>|<)", spec):
        return None
    return name, spec, marker


# ---------------------------------------------------- environment markers

_M_TOKEN_RE = re.compile(
    r"\s*(\(|\)|and|or|not|in|==|!=|>=|<=|>|<|~="
    r"|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[A-Za-z_][A-Za-z0-9_.]*)"
)

DEFAULT_MARKER_ENV = {
    "python_version": "3.12",
    "python_full_version": "3.12.0",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "platform_machine": "x86_64",
    "implementation_name": "cpython",
    "os_name": "posix",
    "extra": "",
}


def eval_marker(marker: str, env: dict | None = None) -> bool:
    """Evaluate a PEP 50 marker against a local environment description.

    Unknown marker variables evaluate conservatively to true (the dependency
    is kept).  Malformed markers also keep the dependency.
    """

    env = {**DEFAULT_MARKER_ENV, **(env or {})}
    try:
        toks = _tokenize_marker(marker)
        pos, value = _parse_or(toks, 0, env)
        return bool(value)
    except Exception:
        return True

def _tokenize_marker(marker: str) -> list[str]:
    toks, pos = [], 0
    while pos < len(marker):
        m = _M_TOKEN_RE.match(marker, pos)
        if not m:
            raise ValueError(f"bad marker at {pos}")
        toks.append(m.group(1))
        pos = m.end()
    return toks


def _lit(tok: str, env: dict):
    if len(tok) >= 2 and tok[0] in "'\"" and tok[-1] == tok[0]:
        return tok[1:-1]
    if tok in env:
        return env[tok]
    # unknown variable: return a sentinel the comparator recognizes as
    # "indeterminate", which makes the marker evaluate conservatively true
    raise _UnknownMarkerVar(tok)


class _UnknownMarkerVar(Exception):
    pass


def _cmp(a, op: str, b) -> bool:
    if op in ("==", "~="):
        return a == b
    if op == "!=":
        return a != b
    try:
        if op == ">=":
            return _ver(a) >= _ver(b)
        if op == "<=":
            return _ver(a) <= _ver(b)
        if op == ">":
            return _ver(a) > _ver(b)
        if op == "<":
            return _ver(a) < _ver(b)
    except Exception:
        return str(a) >= str(b)
    if op == "in":
        return str(a) in str(b)
    raise ValueError(op)


def _ver(v: str):
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.-]", str(v)))


def _parse_or(toks, i, env):
    i, val = _parse_and(toks, i, env)
    while i < len(toks) and toks[i] == "or":
        i, rhs = _parse_and(toks, i + 1, env)
        val = val or rhs
    return i, val


def _parse_and(toks, i, env):
    i, val = _parse_not(toks, i, env)
    while i < len(toks) and toks[i] == "and":
        i, rhs = _parse_not(toks, i + 1, env)
        val = val and rhs
    return i, val


def _parse_not(toks, i, env):
    if i < len(toks) and toks[i] == "not":
        i, val = _parse_not(toks, i + 1, env)
        return i, not val
    return _parse_atom(toks, i, env)


def _parse_atom(toks, i, env):
    if toks[i] == "(":
        i, val = _parse_or(toks, i + 1, env)
        if i >= len(toks) or toks[i] != ")":
            raise ValueError("missing )")
        return i + 1, val
    if i + 2 < len(toks) and toks[i + 1] in ("==", "!=", ">=", "<=", ">", "<", "~=", "in"):
        left = _lit(toks[i], env)
        op = toks[i + 1]
        right = _lit(toks[i + 2], env)
        return i + 3, _cmp(left, op, right)
    raise ValueError(f"unexpected token {toks[i:i+3]}")


# ------------------------------------------------------------ declarations

def parse_declaration(path: str) -> ProjectDecl:
    fname = os.path.basename(path)
    if fname == "pyproject.toml":
        return _parse_pyproject(path)
    return _parse_requirements_in(path)


def _add_decl(decl: ProjectDecl, raw_name: str, constraint: str, scope: str) -> None:
    name = normalize_name(raw_name, Ecosystem.PYTHON)
    prev = decl.declared.get(name)
    if prev is None or scope == "required":
        decl.declared[name] = {"constraint": constraint, "scope": scope}


def _parse_pyproject(path: str) -> ProjectDecl:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InputError(f"malformed pyproject.toml {path}: {exc}") from exc

    project = data.get("project") or {}
    decl = ProjectDecl(
        ecosystem=Ecosystem.PYTHON,
        project_name=project.get("name"),
        project_version=project.get("version"),
        source_file=path,
    )
    if isinstance(project, dict):
        for dep in project.get("dependencies", []) or []:
            parsed = parse_requirement(dep)
            if parsed:
                _add_decl(decl, parsed[0], parsed[1], "required")
        opt = project.get("optional-dependencies", {}) or {}
        if not isinstance(opt, dict):
            raise InputError(f"malformed [project.optional-dependencies] in {path}")
        for group, deps in opt.items():
            if not isinstance(deps, list):
                raise InputError(f"optional group {group!r} must be a list in {path}")
            for dep in deps:
                parsed = parse_requirement(dep)
                if parsed:
                    _add_decl(decl, parsed[0], parsed[1], "optional")

    poetry = (data.get("tool") or {}).get("poetry") or {}
    if isinstance(poetry, dict):
        decl.project_name = decl.project_name or poetry.get("name")
        decl.project_version = decl.project_version or poetry.get("version")
        for section, scope in (
            ("dependencies", "required"),
            ("dev-dependencies", "optional"),
        ):
            table = poetry.get(section) or {}
            if not isinstance(table, dict):
                raise InputError(f"malformed [tool.poetry.{section}] in {path}")
            for name, spec in table.items():
                if name.lower() == "python":
                    continue
                constraint = spec["version"] if isinstance(spec, dict) else str(spec)
                _add_decl(decl, name, constraint, scope)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for grp in groups.values():
                table = (grp or {}).get("dependencies") or {}
                for name, spec in table.items():
                    constraint = spec["version"] if isinstance(spec, dict) else str(spec)
                    _add_decl(decl, name, constraint, "optional")
    return decl


def _logical_requirement_lines(path: str) -> list[str]:
    """Read a requirements-style file, joining backslash continuations."""

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path} is not valid UTF-8: {exc}") from exc

    lines, buf = [], ""
    for line in raw.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        lines.append(buf + stripped)
        buf = ""
    if buf:
        lines.append(buf)
    return lines


def _parse_requirements_in(path: str) -> ProjectDecl:
    decl = ProjectDecl(
        ecosystem=Ecosystem.PYTHON,
        project_name=os.path.basename(os.path.dirname(path) or "."),
        project_version=None,
        source_file=path,
    )
    for line in _logical_requirement_lines(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint", "-e", "--editable")):
            continue
        if line.startswith("-"):
            continue  # pip options (--index-url, --find-links, ...)
        parsed = parse_requirement(line)
        if parsed is None:
            raise InputError(f"unparseable requirement {line!r} in {path}")
        _add_decl(decl, parsed[0], parsed[1], "required")
    return decl


# ------------------------------------------------------------------ locks

def parse_lock(path: str, fmt: str) -> LockData:
    if fmt == "uv":
        return _parse_uv_lock(path)
    if fmt == "pipfile":
        return _parse_pipfile_lock(path)
    if fmt == "requirements":
        return _parse_requirements_lock(path)
    raise InputError(f"unknown python lock format: {fmt}")


def _read_toml(path: str):
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InputError(f"malformed lock file {path}: {exc}") from exc


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"malformed JSON in {path}: {exc}") from exc


def _parse_uv_lock(path: str) -> LockData:
    data = _read_toml(path)
    lock = LockData(ecosystem=Ecosystem.PYTHON, source_file=path, lock_format="uv")
    if not isinstance(data, dict) or "package" not in data:
        # An uv.lock without [[package]] is valid (e.g. empty projects).
        if not isinstance(data, dict):
            raise InputError(f"malformed uv.lock {path}: top level must be a table")
        return lock
    packages = data["package"]
    if isinstance(packages, dict):
        packages = [packages]
    if not isinstance(packages, list):
        raise InputError(f"malformed uv.lock {path}: [[package]] must be an array")

    root_projects = data.get("project")
    root_names = set()
    if isinstance(root_projects, dict):
        root_projects = [root_projects]
    if isinstance(root_projects, list):
        root_names = {
            normalize_name(p.get("name", ""), Ecosystem.PYTHON)
            for p in root_projects
            if isinstance(p, dict) and p.get("name")
        }

    for pkg in packages:
        if not isinstance(pkg, dict) or "name" not in pkg or "version" not in pkg:
            raise InputError(f"malformed package entry in uv.lock {path}")
        name = normalize_name(str(pkg["name"]), Ecosystem.PYTHON)
        source = pkg.get("source") or {}
        if name in root_names and isinstance(source, dict) and (
            "editable" in source or "virtual" in source
        ):
            continue
        locked = LockedPkg(
            ecosystem=Ecosystem.PYTHON,
            name=name,
            version=str(pkg["version"]),
            origin=path,
        )
        deps_table = pkg.get("dependencies")
        if isinstance(deps_table, list):
            for dep in deps_table:
                if not isinstance(dep, dict) or "name" not in dep:
                    raise InputError(f"malformed dependency of {name} in {path}")
                marker = dep.get("marker", "")
                if marker and not eval_marker(marker):
                    continue
                locked.dependencies.add(
                    component_key(Ecosystem.PYTHON, normalize_name(str(dep["name"]), Ecosystem.PYTHON))
                )
        metadata = pkg.get("metadata") or {}
        if isinstance(metadata, dict):
            for req in metadata.get("requires-dist", []) or []:
                parsed = parse_requirement(str(req))
                if parsed and (not parsed[2] or eval_marker(parsed[2])):
                    locked.dependencies.add(
                        component_key(Ecosystem.PYTHON, normalize_name(parsed[0], Ecosystem.PYTHON))
                    )
            lic = metadata.get("license-expression")
            if isinstance(lic, str) and lic.strip():
                locked.licenses.append(lic.strip())
        for wheel in pkg.get("wheels", []) or []:
            if isinstance(wheel, dict) and wheel.get("url", "").startswith("file://"):
                h = parse_hex_hash("hash", f"{wheel.get('hash-algorithm','sha256')}={wheel.get('hash','')}")
                if h:
                    locked.hashes.append(h)
        lock.packages.append(locked)
    return lock


def _parse_pipfile_lock(path: str) -> LockData:
    data = _read_json(path)
    if not isinstance(data, dict) or "default" not in data:
        raise InputError(f"malformed Pipfile.lock {path}: missing 'default' section")
    lock = LockData(ecosystem=Ecosystem.PYTHON, source_file=path, lock_format="pipfile")
    for section, scope in (("default", "required"), ("develop", "optional")):
        table = data.get(section) or {}
        if not isinstance(table, dict):
            raise InputError(f"malformed Pipfile.lock {path}: '{section}' must be an object")
        for raw_name, info in table.items():
            if not isinstance(info, dict):
                raise InputError(f"malformed lock entry for {raw_name} in {path}")
            version_spec = str(info.get("version", ""))
            if not re.match(r"^===?", version_spec):
                raise InputError(
                    f"Pipfile.lock entry {raw_name} has unpinned version {version_spec!r} in {path}"
                )
            marker = info.get("markers", "")
            if marker and not eval_marker(marker):
                continue
            locked = LockedPkg(
                ecosystem=Ecosystem.PYTHON,
                name=normalize_name(raw_name, Ecosystem.PYTHON),
                version=version_spec.lstrip("="),
                scope=scope,
                origin=path,
            )
            for hh in info.get("hashes", []) or []:
                alg, _, value = str(hh).partition(":")
                h = parse_hex_hash("hash", f"{alg}={value}")
                if h is None:
                    raise InputError(f"bad hash {hh!r} for {raw_name} in {path}")
                locked.hashes.append(h)
            lock.packages.append(locked)
    return lock


def _parse_requirements_lock(path: str) -> LockData:
    lock = LockData(ecosystem=Ecosystem.PYTHON, source_file=path, lock_format="requirements")
    for line in _logical_requirement_lines(path):
        # comments may only contain --hash on continuations; strip plain comments
        line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        hashes: list[Hash] = []
        tokens = line.split()
        req_tokens, skip = [], False
        for tok in tokens:
            if tok.startswith("--hash="):
                h = parse_hex_hash("hash", tok.split("=", 1)[1])
                if h is None:
                    raise InputError(f"bad --hash value in {path}: {tok}")
                hashes.append(h)
            elif tok in ("--hash",):
                skip = True  # next token is the value
            elif skip:
                h = parse_hex_hash("hash", tok)
                if h is None:
                    raise InputError(f"bad --hash value in {path}: {tok}")
                hashes.append(h)
                skip = False
            elif tok.startswith("-"):
                continue
            else:
                req_tokens.append(tok)
        req_str = " ".join(req_tokens)
        parsed = parse_requirement(req_str)
        if parsed is None:
            raise InputError(f"unparseable requirement {req_str!r} in {path}")
        name, spec, marker = parsed
        if marker and not eval_marker(marker):
            continue
        pin = re.match(r"^==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$", spec)
        if not pin:
            raise InputError(
                f"lock entry {name!r} must be pinned with == (got {spec or 'no specifier'!r}) in {path}"
            )
        lock.packages.append(
            LockedPkg(
                ecosystem=Ecosystem.PYTHON,
                name=normalize_name(name, Ecosystem.PYTHON),
                version=pin.group(1),
                hashes=hashes,
                origin=path,
            )
        )
    return lock
