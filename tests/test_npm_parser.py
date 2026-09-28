"""Tests for Node.js ecosystem parsing."""

from __future__ import annotations

import json

import pytest

from sbomtool.errors import ParseError
from sbomtool.parsers.npm_scan import (
    parse_package_json,
    parse_package_lock,
    parse_yarn_lock,
)
from sbomtool.parsers.project import scan_project


def test_package_json_sections(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "name": "app", "version": "1.0.0", "license": "MIT",
        "dependencies": {"a": "^1.0.0"},
        "devDependencies": {"b": "~2.0.0"},
        "optionalDependencies": {"c": "file:../c"},
        "peerDependencies": {"d": ">=3.0.0"},
    }))
    root, deps = parse_package_json(str(f))
    assert root.name == "app"
    assert root.licenses == ["MIT"]
    by = {d.normalized_name: d for d in deps}
    assert by["a"].spec == "^1.0.0"
    assert by["b"].optional is True
    assert by["c"].source_type == "file"
    assert by["d"].optional is True


def test_package_json_bad_section(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({"name": "app", "dependencies": []}))
    with pytest.raises(ParseError, match="must be an object"):
        parse_package_json(str(f))


def test_package_json_invalid_json(tmp_path):
    f = tmp_path / "package.json"
    f.write_text("{ not valid")
    with pytest.raises(ParseError, match="invalid JSON"):
        parse_package_json(str(f))


def test_npm_scope_normalization(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "name": "scope-app",
        "dependencies": {"@Scope/Pkg": "^1.0.0"}}))
    _, deps = parse_package_json(str(f))
    assert deps[0].normalized_name == "@scope/pkg"


# ---------------------------------------------------------------------------
# package-lock v3
# ---------------------------------------------------------------------------

def test_lockfile_v3_components_and_transitive(npm_v3_project):
    scan = scan_project(npm_v3_project)[0]
    assert scan.lock_file == "package-lock.json"
    by = {c.normalized_name: c for c in scan.components}
    assert set(by) == {"a", "b", "c", "d"}
    assert by["a"].version == "1.4.0"
    # integrity converted from base64 sha512 to hex
    assert "SHA-512" in by["a"].hashes
    assert len(by["a"].hashes["SHA-512"]) == 128
    # transitive: a -> d
    assert by["a"].dependencies == ["d"]
    # dev dependency is a root direct dep
    assert "c" in scan.root_direct


def test_lockfile_v1(npm_v1_project):
    scan = scan_project(npm_v1_project)[0]
    assert scan.lock_file == "package-lock.json"
    by = {c.normalized_name: c for c in scan.components}
    assert by["left-pad"].version == "1.3.0"
    assert "SHA-1" in by["left-pad"].hashes


def test_lockfile_unsupported_version(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "x"}))
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 99, "packages": {}}))
    with pytest.raises(ParseError, match="unsupported lockfileVersion"):
        scan_project(str(tmp_path))


def test_lockfile_duplicate_nested_versions(npm_dup_project):
    scan = scan_project(npm_dup_project)[0]
    d_versions = sorted(c.version for c in scan.components
                        if c.normalized_name == "d")
    assert d_versions == ["1.5.0", "2.0.0"]
    # edge from b resolves to its nested copy of d@2
    b = next(c for c in scan.components if c.normalized_name == "b")
    a = next(c for c in scan.components if c.normalized_name == "a")
    # edges recorded regardless of duplication
    assert b.dependencies == ["d"]
    assert a.dependencies == ["d"]


def test_lockfile_missing_declared(npm_missing_project):
    scan = scan_project(npm_missing_project)[0]
    present = {c.normalized_name for c in scan.components}
    assert "present" in present
    assert "absent" not in present
    from sbomtool.integrity import analyze_integrity

    issues = analyze_integrity([scan])
    missing = [i for i in issues if i["code"] == "MISSING_PACKAGE"]
    assert len(missing) == 1
    assert missing[0]["component"] == "absent"


def test_lockfile_bad_integrity(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "x",
                               "dependencies": {"a": "^1.0.0"}}))
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0",
                               "integrity": "not-a-real-hash!!"},
        }}))
    with pytest.raises(ParseError, match="invalid integrity"):
        scan_project(str(tmp_path))


# ---------------------------------------------------------------------------
# yarn.lock classic
# ---------------------------------------------------------------------------

def test_yarn_lock_parsing(npm_yarn_project):
    scan = scan_project(npm_yarn_project)[0]
    assert scan.lock_file == "yarn.lock"
    by = {c.normalized_name: c for c in scan.components}
    assert by["chalk"].version == "4.1.2"
    assert by["left-pad"].version == "1.3.0"
    assert by["supports-color"].version == "7.2.0"
    assert "SHA-512" in by["chalk"].hashes
    # transitive edge chalk -> supports-color
    assert by["chalk"].dependencies == ["supports-color"]


def test_yarn_lock_malformed(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "x"}))
    yarn = tmp_path / "yarn.lock"
    yarn.write_text("  orphan indented line\n")
    with pytest.raises(ParseError, match="orphaned yarn.lock line"):
        scan_project(str(tmp_path))


def test_yarn_lock_entry_without_version(tmp_path):
    f = tmp_path / "yarn.lock"
    f.write_text('foo@^1.0.0:\n  resolved "x"\n')
    with pytest.raises(ParseError, match="has no version"):
        parse_yarn_lock(str(f), [])


# ---------------------------------------------------------------------------
# no lock / dual lock
# ---------------------------------------------------------------------------

def test_no_lock_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "nolock", "dependencies": {"a": "^1.0.0"}}))
    scan = scan_project(str(tmp_path))[0]
    assert scan.lock_file is None
    comp = scan.components[0]
    assert comp.source_type == "declared"
    assert comp.version is None


def test_dual_locks_rejected(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {}}))
    (tmp_path / "yarn.lock").write_text("")
    with pytest.raises(ParseError, match="both package-lock.json and yarn"):
        scan_project(str(tmp_path))


def test_no_project_files(tmp_path):
    from sbomtool.errors import InputError

    with pytest.raises(InputError, match="no supported project files"):
        scan_project(str(tmp_path))
