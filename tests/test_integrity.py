"""Tests for integrity analysis (missing/duplicate/mismatch/drift)."""

from __future__ import annotations

import json
import os

import pytest

from sbomtool.cyclonedx import build_cyclonedx
from sbomtool.integrity import analyze_integrity
from sbomtool.parsers.project import scan_project


def _codes(project_dir):
    scan = scan_project(project_dir)
    issues = analyze_integrity(scan)
    return {(i["code"], i.get("component")): i for i in issues}, scan


def test_clean_poetry_project_has_no_errors(py_poetry_project):
    issues, _ = _codes(py_poetry_project)
    errors = [i for i in issues.values() if i["severity"] == "error"]
    assert errors == []


def test_missing_package_detected(npm_missing_project):
    issues, _ = _codes(npm_missing_project)
    issue = issues[("MISSING_PACKAGE", "absent")]
    assert issue["severity"] == "error"
    assert "package-lock.json" in issue["message"]


def test_version_mismatch_python(py_poetry_mismatch_project):
    issues, _ = _codes(py_poetry_mismatch_project)
    issue = issues[("VERSION_MISMATCH", "flask")]
    assert issue["severity"] == "error"
    assert issue["details"]["declared"] == "^2.0.0"
    assert issue["details"]["locked"] == ["3.0.3"]


def test_version_mismatch_npm_range(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "app",
        "dependencies": {"a": "~1.0.0"}}))  # only 1.0.x allowed
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "~1.0.0"}},
            "node_modules/a": {"version": "1.5.0"},
        }}))
    issues, _ = _codes(str(tmp_path))
    assert ("VERSION_MISMATCH", "a") in issues


def test_duplicate_versions_npm_warning(npm_dup_project):
    issues, _ = _codes(npm_dup_project)
    issue = issues[("DUPLICATE_COMPONENT", "d")]
    assert issue["severity"] == "warning"
    assert set(issue["details"]["versions"]) == {"1.5.0", "2.0.0"}


def test_duplicate_declaration_in_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==1.0\nFlask==2.0\n")
    issues, _ = _codes(str(tmp_path))
    # both declarations normalize to flask -> duplicate declaration warning
    assert any(i["code"] == "DUPLICATE_DECLARATION"
               and i["component"].lower() == "flask"
               for i in issues.values())


def test_missing_lock_is_error(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=1.0\nrequests\n")
    issues, _ = _codes(str(tmp_path))
    assert ("LOCK_MISSING", None) in issues
    assert issues[("LOCK_MISSING", None)]["severity"] == "error"


def test_broken_dependency_edge(tmp_path):
    """Lock entry references a dependency not present anywhere."""

    (tmp_path / "package.json").write_text(json.dumps({
        "name": "app", "dependencies": {"a": "^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0",
                               "requires": {"ghost": "^9.9.9"}},
        }}))
    issues, _ = _codes(str(tmp_path))
    edge = issues.get(("BROKEN_DEPENDENCY_EDGE", "a"))
    assert edge is not None
    assert "ghost" in edge["message"]


def test_missing_hash_warning(py_poetry_project):
    # poetry.lock entries in the fixture have no file hashes
    issues, _ = _codes(py_poetry_project)
    missing = [i for i in issues.values() if i["code"] == "MISSING_HASH"]
    assert missing
    assert any(i["component"] == "flask" for i in missing)


def test_present_hash_no_warning(npm_v3_project):
    issues, _ = _codes(npm_v3_project)
    assert not [i for i in issues.values()
                if i["code"] == "MISSING_HASH"]


def test_input_order_does_not_change_issues(npm_v3_project):
    """Re-ordering files on disk must yield the same issue set."""

    _, scan1 = _codes(npm_v3_project)
    doc1 = build_cyclonedx(scan1)
    lock_path = os.path.join(npm_v3_project, "package-lock.json")
    data = json.load(open(lock_path))
    # shuffle packages dict order
    import random

    items = list(data["packages"].items())
    random.Random(7).shuffle(items)
    data["packages"] = dict(items)
    json.dump(data, open(lock_path, "w"))
    _, scan2 = _codes(npm_v3_project)
    doc2 = build_cyclonedx(scan2)
    assert json.dumps(doc1, sort_keys=True) == \
        json.dumps(doc2, sort_keys=True)
