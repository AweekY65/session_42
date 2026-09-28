"""Shared helpers for tests: tiny fixture-project builders."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def write_json(path: str, obj) -> None:
    write(path, json.dumps(obj, indent=2))


def npm_v3_lock(root_meta: dict, packages: dict) -> str:
    """Build package-lock.json content (lockfileVersion 3)."""

    pkgs = {"": root_meta}
    for name, meta in packages.items():
        key = f"node_modules/{name}"
        entry = {"version": meta["version"]}
        if "integrity" in meta:
            entry["integrity"] = meta["integrity"]
        if "license" in meta:
            entry["license"] = meta["license"]
        if "deps" in meta:
            entry["dependencies"] = dict.fromkeys(meta["deps"], "*")
        if meta.get("dev"):
            entry["dev"] = True
        pkgs[key] = entry
    return json.dumps({"name": root_meta.get("name"), "version": root_meta.get("version"),
                       "lockfileVersion": 3, "packages": pkgs}, indent=2)


def finding_codes(findings) -> list[str]:
    return sorted(f.code for f in findings)
