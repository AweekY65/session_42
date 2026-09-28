"""Tests for CycloneDX emission and local hashing helpers."""

from __future__ import annotations

import json

from sbomtool.cyclonedx import build_cyclonedx, make_purl
from sbomtool.parsers.project import scan_project
from sbomtool.report import stable_json
from sbomtool.hashing import (
    hash_bytes,
    hash_directory,
    hash_file,
    normalize_lock_hash,
)
import pytest


# ---------------------------------------------------------------------------
# hashes
# ---------------------------------------------------------------------------

def test_hash_bytes_known_value():
    # sha256 of empty string
    assert hash_bytes(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855")


def test_hash_file_and_directory(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert hash_file(str(f)) == hash_bytes(b"hello")
    d = tmp_path / "tree"
    (d / "sub").mkdir(parents=True)
    (d / "x.txt").write_text("x")
    (d / "sub" / "y.txt").write_text("y")
    h1 = hash_directory(str(d))
    (d / "sub" / "y.txt").write_text("z")
    h2 = hash_directory(str(d))
    assert h1 != h2  # content edit changes hash


def test_directory_hash_order_independent(tmp_path):
    import os
    import shutil

    a = tmp_path / "a"
    b = tmp_path / "b"
    for root in (a, b):
        (root / "sub").mkdir(parents=True)
        (root / "x.txt").write_text("x")
        (root / "sub" / "y.txt").write_text("y")
    assert hash_directory(str(a)) == hash_directory(str(b))


@pytest.mark.parametrize("raw,algo,hexpart", [
    ("sha256=abcd", "SHA-256", "abcd"),
    ("sha512-AA==", "SHA-512", "00"),       # base64 AA== -> 0x00
    ("00" * 32, "SHA-256", "00" * 32),     # bare hex defaults to sha256
])
def test_normalize_lock_hash(raw, algo, hexpart):
    out_algo, out_hex = normalize_lock_hash(raw)
    assert out_algo == algo
    assert out_hex.startswith(hexpart)


def test_normalize_lock_hash_errors():
    with pytest.raises(ValueError):
        normalize_lock_hash("md4=abcd")       # unsupported algo
    with pytest.raises(ValueError):
        normalize_lock_hash("sha256=zzzz")    # not hex
    with pytest.raises(ValueError):
        normalize_lock_hash("sha512-@@@")     # bad base64
    with pytest.raises(ValueError):
        normalize_lock_hash("garbage!!!")


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

def test_cyclonedx_structure_and_edges(py_poetry_project):
    scans = scan_project(py_poetry_project)
    doc = build_cyclonedx(scans, project_name="poetry-app")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["component"]["name"] == "poetry-app"

    libraries = [c for c in doc["components"] if c["type"] == "library"]
    by_name = {c["name"]: c for c in libraries}
    assert by_name["flask"]["version"] == "3.0.3"
    assert by_name["flask"]["purl"] == "pkg:pypi/flask@3.0.3"
    assert by_name["flask"]["licenses"] == [{"expression": "BSD-3-Clause"}]

    edges = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    flask_ref = by_name["flask"]["bom-ref"]
    jinja_ref = by_name["jinja2"]["bom-ref"]
    assert jinja_ref in edges[flask_ref]


def test_cyclonedx_npm_purl_and_integrity(npm_v3_project):
    scans = scan_project(npm_v3_project)
    doc = build_cyclonedx(scans)
    a = next(c for c in doc["components"]
             if c.get("purl", "").endswith("/a@1.4.0"))
    assert a["purl"] == "pkg:npm/a@1.4.0"
    assert any(h["alg"] == "SHA-512" and len(h["content"]) == 128
               for h in a["hashes"])


def test_cyclonedx_deterministic_bytes(py_poetry_project):
    scans = scan_project(py_poetry_project)
    doc1 = build_cyclonedx(scans)
    doc2 = build_cyclonedx(scans)
    assert stable_json(doc1) == stable_json(doc2)


def test_stable_json_sorted_keys():
    out = stable_json({"b": 1, "a": [3, 2, 1]})
    lines = [l.strip() for l in out.splitlines() if ":" in l]
    assert lines[0].startswith('"a"')
    # ends with trailing newline
    assert out.endswith("\n")
