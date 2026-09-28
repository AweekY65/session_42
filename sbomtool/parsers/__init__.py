"""Parsers for local Python and Node.js dependency descriptions and lock files.

Nothing in this package performs network access.  Every parser raises
:class:`~sbomtool.errors.InputError` on structurally invalid input rather than
silently dropping data.
"""

from __future__ import annotations

import os

from ..errors import InputError
from ..models import Ecosystem, LockData, ProjectDecl
from . import node, python

# declaration filename -> ecosystem
_DECL_FILES = {
    "pyproject.toml": Ecosystem.PYTHON,
    "requirements.in": Ecosystem.PYTHON,
    "package.json": Ecosystem.NPM,
}
# lock filename -> (ecosystem, format tag)
_LOCK_FILES = {
    "requirements.txt": (Ecosystem.PYTHON, "requirements"),
    "uv.lock": (Ecosystem.PYTHON, "uv"),
    "Pipfile.lock": (Ecosystem.PYTHON, "pipfile"),
    "package-lock.json": (Ecosystem.NPM, "npm"),
    "yarn.lock": (Ecosystem.NPM, "yarn"),
}


def discover(root: str) -> tuple[dict[Ecosystem, str], dict[str, tuple[Ecosystem, str]]]:
    """Return ``(declarations, locks)`` found directly under ``root``.

    ``declarations`` maps ecosystem to file path; ``locks`` maps file path to
    ``(ecosystem, format)``.  ``requirements.txt`` is treated as a lock only
    when a ``requirements.in`` (the declaration) also exists; when there is no
    declaration it is used as a declaration file instead.
    """

    decls: dict[Ecosystem, str] = {}
    locks: dict[str, tuple[Ecosystem, str]] = {}
    present = set()
    try:
        present = {e.name for e in os.scandir(root) if e.is_file()}
    except OSError as exc:
        raise InputError(f"cannot read project directory {root!r}: {exc}") from exc

    for fname, eco in _DECL_FILES.items():
        if fname in present and eco not in decls:
            decls[eco] = os.path.join(root, fname)
    for fname, spec in _LOCK_FILES.items():
        if fname in present:
            locks[os.path.join(root, fname)] = spec

    req_txt = os.path.join(root, "requirements.txt")
    if req_txt in locks and os.path.join(root, "requirements.in") not in decls.values():
        # No .in declaration: requirements.txt plays the declaration role.
        del locks[req_txt]
        decls.setdefault(Ecosystem.PYTHON, req_txt)
    return decls, locks


def parse_declaration(path: str, ecosystem: Ecosystem) -> ProjectDecl:
    if ecosystem == Ecosystem.PYTHON:
        return python.parse_declaration(path)
    return node.parse_declaration(path)


def parse_lock(path: str, ecosystem: Ecosystem, fmt: str) -> LockData:
    if ecosystem == Ecosystem.PYTHON:
        return python.parse_lock(path, fmt)
    return node.parse_lock(path, fmt)
