"""Read package metadata and content hashes from *local* install trees.

Supported trees:

* Python: ``site-packages`` / ``dist-packages`` directories containing
  ``.dist-info`` (and legacy ``.egg-info``) metadata;
* Node.js: ``node_modules`` package directories with ``package.json``.

No download or remote resolution ever happens -- a package that is not
present locally simply contributes no local evidence.
"""

from __future__ import annotations

import csv
import os
import re
from configparser import Error as CfgError
from email.parser import Parser

from .errors import SbomError
from .hashing import Hash, hash_file
from .models import Ecosystem, LockedPkg
from .naming import normalize_name

_PY_SEARCH = (
    "site-packages",
    os.path.join("lib", "python3"),
    "dist-packages",
    ".venv",
    "venv",
)


# ---------------------------------------------------------------- Python

_SPDX_LIKE_RE = re.compile(r"^[A-Za-z0-9.+-]+$")
_LICENSE_CLASSIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}


def find_python_site_packages(root: str) -> list[str]:
    """Auto-detect local Python package trees under ``root``."""

    found = []

    def add(path: str) -> None:
        if os.path.isdir(path) and path not in found:
            found.append(path)

    for name in ("site-packages", "dist-packages"):
        add(os.path.join(root, name))
    for venv in (".venv", "venv", "env"):
        base = os.path.join(root, venv, "lib")
        if os.path.isdir(base):
            for entry in os.listdir(base):
                if entry.startswith("python"):
                    add(os.path.join(base, entry, "site-packages"))
    # nested one level: root/.../site-packages (kept shallow to stay local)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.relpath(dirpath, root).count(os.sep)
        if depth >= 4:
            dirnames[:] = []
        for d in list(dirnames):
            if d in ("site-packages", "dist-packages"):
                add(os.path.join(dirpath, d))
    return found


def _read_dist_info(sp_dir: str, entry: str) -> tuple[str, str] | None:
    """Return (normalized-name, version) from a .dist-info/.egg-info dir."""

    m = re.match(r"^(?P<name>.+?)-(?P<ver>\d[^-]*)(?:\.dist-info|\.egg-info)$", entry)
    if not m:
        return None
    return normalize_name(m.group("name"), Ecosystem.PYTHON), m.group("ver")


def _dist_metadata(sp_dir: str, entry: str) -> dict:
    meta_path = os.path.join(sp_dir, entry, "METADATA")
    if not os.path.isfile(meta_path):
        meta_path = os.path.join(sp_dir, entry, "PKG-INFO")
    if not os.path.isfile(meta_path):
        return {"licenses": [], "record_hashes": [], "license_files": []}
    with open(meta_path, "r", encoding="utf-8", errors="replace") as fh:
        msg = Parser().parse(fh)
    licenses: list[str] = []
    expr = msg.get("License-Expression")
    if expr:
        for token in re.split(r"\s+OR\s+", expr):
            token = token.strip()
            if token and token not in licenses:
                licenses.append(token)
    lic_field = msg.get("License")
    if not licenses and lic_field and _SPDX_LIKE_RE.match(lic_field.strip()):
        licenses.append(lic_field.strip())
    for header in msg.get_all("Classifier") or []:
        if header in _LICENSE_CLASSIFIERS:
            spdx = _LICENSE_CLASSIFIERS[header]
            if spdx not in licenses:
                licenses.append(spdx)

    record_hashes = _read_record_hashes(os.path.join(sp_dir, entry, "RECORD"))
    license_files = []
    license_files_dir = os.path.join(sp_dir, entry, "licenses")
    if os.path.isdir(license_files_dir):
        license_files = sorted(
            os.path.join(license_files_dir, f)
            for f in os.listdir(license_files_dir)
            if os.path.isfile(os.path.join(license_files_dir, f))
        )
    return {
        "licenses": licenses,
        "record_hashes": record_hashes,
        "license_files": license_files,
    }


def _read_record_hashes(record_path: str) -> list[Hash]:
    if not os.path.isfile(record_path):
        return []
    out: list[Hash] = []
    with open(record_path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            # PEP 376 RECORD: path, "alg=hexdigest", size
            if len(row) >= 2 and "=" in row[1]:
                alg, digest = row[1].split("=", 1)
                # also tolerate pip's "hashlib=<alg>" second-column variant
                if alg == "hashlib" and len(row) >= 3:
                    alg, digest = digest, row[2]
                if digest and re.match(r"^[a-z0-9]+$", digest, re.I):
                    out.append(Hash(alg=alg.lower(), value=digest.lower(),
                                    origin="local-record"))
    return out


def scan_python_packages(search_dirs: list[str]) -> list[LockedPkg]:
    """Materialize locally installed Python packages as lock-like records."""

    packages: list[LockedPkg] = []
    seen: set[tuple[str, str]] = set()
    for sp_dir in search_dirs:
        if not os.path.isdir(sp_dir):
            continue
        try:
            entries = sorted(os.listdir(sp_dir))
        except OSError:
            continue
        for entry in entries:
            ident = _read_dist_info(sp_dir, entry)
            if ident is None:
                continue
            name, version = ident
            if (name, version) in seen:
                continue
            seen.add((name, version))
            meta = _dist_metadata(sp_dir, entry)
            locked = LockedPkg(
                ecosystem=Ecosystem.PYTHON,
                name=name,
                version=version,
                hashes=meta["record_hashes"],
                licenses=meta["licenses"],
                origin=os.path.join(sp_dir, entry),
            )
            # hashes of the license files themselves are direct local content
            for lf in meta["license_files"][:1]:
                try:
                    locked.hashes.append(Hash("sha256", hash_file(lf), "local-content"))
                except (OSError, SbomError):
                    pass
            packages.append(locked)
    return packages


# ----------------------------------------------------------------- Node

def find_node_modules(root: str) -> list[str]:
    """Return node_modules roots under ``root`` (nested modules included)."""

    roots = []
    for dirpath, dirnames, _filenames in os.walk(root):
        for d in list(dirnames):
            if d == "node_modules":
                roots.append(os.path.join(dirpath, d))
        # do not descend INTO node_modules via generic walk
        dirnames[:] = [d for d in dirnames if d != "node_modules"]
    return roots


def scan_node_packages(node_modules_roots: list[str]) -> list[LockedPkg]:
    """Scan one or more node_modules trees.

    Scoped packages (``@scope/pkg``) and nested ``node_modules`` directories
    are handled recursively.  When the same package name appears more than
    once inside one tree, the shallowest copy wins -- which mirrors npm
    resolution precedence.
    """

    import json

    packages: list[LockedPkg] = []
    seen: set[str] = set()

    def walk(nm_dir: str) -> None:
        try:
            entries = sorted(os.listdir(nm_dir))
        except OSError:
            return
        for entry in entries:
            if entry.startswith(".") or entry.startswith("@") and not os.path.isdir(os.path.join(nm_dir, entry)):
                continue
            pkg_dirs: list[str] = []
            if entry.startswith("@"):
                scope_dir = os.path.join(nm_dir, entry)
                if not os.path.isdir(scope_dir):
                    continue
                try:
                    for pkg in sorted(os.listdir(scope_dir)):
                        pkg_dirs.append(os.path.join(scope_dir, pkg))
                except OSError:
                    continue
            else:
                pkg_dirs.append(os.path.join(nm_dir, entry))
            for pkg_dir in pkg_dirs:
                if not os.path.isdir(pkg_dir):
                    continue
                pkg_json = os.path.join(pkg_dir, "package.json")
                rel = os.path.relpath(pkg_dir, nm_dir).replace(os.sep, "/")
                name = normalize_name(rel, Ecosystem.NPM)
                if os.path.isfile(pkg_json):
                    try:
                        with open(pkg_json, "r", encoding="utf-8") as fh:
                            data = json.load(fh)
                    except (OSError, json.JSONDecodeError) as exc:
                        raise SbomError(
                            f"malformed installed package manifest {pkg_json}: {exc}"
                        ) from exc
                    if not isinstance(data, dict):
                        continue
                    version = str(data.get("version", ""))
                    if version and name not in seen:
                        seen.add(name)
                        locked = LockedPkg(
                            ecosystem=Ecosystem.NPM,
                            name=name,
                            version=version,
                            origin=pkg_dir,
                            path=pkg_dir,
                        )
                        lic = data.get("license")
                        if isinstance(lic, str) and lic.strip():
                            locked.licenses.append(lic.strip())
                        elif isinstance(lic, dict) and isinstance(lic.get("type"), str):
                            locked.licenses.append(lic["type"].strip())
                        try:
                            locked.hashes.append(
                                Hash("sha256", hash_file(pkg_json), "local-content")
                            )
                        except OSError:
                            pass
                        for dep_name in (data.get("dependencies") or {}):
                            from ..models import component_key
                            locked.dependencies.add(
                                component_key(
                                    Ecosystem.NPM, normalize_name(dep_name, Ecosystem.NPM)
                                )
                            )
                        packages.append(locked)
                nested = os.path.join(pkg_dir, "node_modules")
                if os.path.isdir(nested):
                    walk(nested)

    for nm in node_modules_roots:
        walk(nm)
    return packages
