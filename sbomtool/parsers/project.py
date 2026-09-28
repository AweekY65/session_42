"""Project scanning orchestration: detect ecosystems and merge scans."""

from __future__ import annotations

import os

from ..errors import InputError
from ..model import ProjectScan
from .npm_scan import scan_npm_project
from .python_scan import scan_python_project


def scan_project(root_dir: str) -> list[ProjectScan]:
    """Scan a directory for supported ecosystems.

    Raises :class:`InputError` when no supported project file exists.
    """

    if not os.path.isdir(root_dir):
        raise InputError(f"project directory not found: {root_dir}")
    scans: list[ProjectScan] = []
    py = scan_python_project(root_dir)
    if py is not None:
        scans.append(py)
    npm = scan_npm_project(root_dir)
    if npm is not None:
        scans.append(npm)
    if not scans:
        raise InputError(
            f"no supported project files found in {root_dir} "
            "(looked for requirements*.txt, pyproject.toml, Pipfile, "
            "package.json)")
    return scans
