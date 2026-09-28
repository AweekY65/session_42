"""Tests for Python ecosystem parsing."""

from __future__ import annotations

import pytest

from sbomtool.errors import ParseError
from sbomtool.parsers.project import scan_project
from sbomtool.parsers.python_scan import (
    parse_pipfile,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
)


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

def test_requirements_basic(py_pinned_project):
    import os

    deps = parse_requirements_txt(
        os.path.join(py_pinned_project, "requirements.txt"))
    names = {d.normalized_name for d in deps}
    assert names == {"certifi", "requests"}
    certifi = next(d for d in deps if d.normalized_name == "certifi")
    assert certifi.spec == "==2024.2.2"
    assert certifi.hashes == {"SHA-256": "aaaabbbbccccdddd"}


def test_requirements_include_and_normalization(py_unpinned_project):
    import os

    deps = parse_requirements_txt(
        os.path.join(py_unpinned_project, "requirements.txt"))
    names = {d.normalized_name for d in deps}
    # -r extra.txt followed; Click/Flask normalization collapses _ . -
    assert {"flask", "requests", "click"} <= names


def test_requirements_unsupported_option(tmp_path):
    f = tmp_path / "req.txt"
    f.write_text("flask==1.0\n--unknown-flag=yes\n")
    with pytest.raises(ParseError, match="unsupported pip option"):
        parse_requirements_txt(str(f))


def test_requirements_recursive_include(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("-r b.txt\n")
    b.write_text("-r a.txt\n")
    with pytest.raises(ParseError, match="recursive"):
        parse_requirements_txt(str(a))


def test_pep508_name_normalization(tmp_path):
    """PEP 503: Some_Pkg.Name == some-pkg-name."""

    f = tmp_path / "r.txt"
    f.write_text("Some_Pkg.Name>=1.0\n")
    deps = parse_requirements_txt(str(f))
    assert deps[0].normalized_name == "some-pkg-name"
    assert deps[0].name == "Some_Pkg.Name"


def test_requirements_inline_hash_and_url(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text(
        "pkg @ https://example.invalid/pkg-1.0.tar.gz "
        "--hash=sha256=0123456789abcdef0123456789abcdef\n")
    deps = parse_requirements_txt(str(f))
    assert deps[0].normalized_name == "pkg"
    assert deps[0].source_type == "url"


def test_requirements_missing_file():
    with pytest.raises(ParseError, match="cannot read"):
        parse_requirements_txt("/nonexistent/requirements.txt")


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

def test_pyproject_pep621(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text(
        '[project]\nname="app"\nversion="0.1"\nlicense={text="Apache-2.0"}\n'
        'dependencies=["flask>=2.0", "requests==2.31.0"]\n'
        '[project.optional-dependencies]\ndev=["pytest==7"]\n')
    root, deps = parse_pyproject_toml(str(f))
    assert root.name == "app"
    assert root.licenses == ["Apache-2.0"]
    assert {d.normalized_name for d in deps} == {
        "flask", "requests", "pytest"}
    assert next(d for d in deps if d.normalized_name == "pytest").optional


def test_pyproject_poetry_sections(py_poetry_project):
    import os

    root, deps = parse_pyproject_toml(
        os.path.join(py_poetry_project, "pyproject.toml"))
    assert root.name == "poetry-app"
    specs = {d.normalized_name: d.spec for d in deps}
    assert specs["flask"] == "^3.0"
    assert specs["pytest"] == "7.4.4"


def test_pyproject_invalid_toml(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text("[project\nname = broken\n")
    with pytest.raises(ParseError, match="invalid TOML"):
        parse_pyproject_toml(str(f))


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------

def test_poetry_lock_components_and_edges(py_poetry_project):
    import os

    comps = parse_poetry_lock(os.path.join(py_poetry_project, "poetry.lock"))
    by = {c.normalized_name: c for c in comps}
    assert by["flask"].version == "3.0.3"
    assert by["flask"].licenses == ["BSD-3-Clause"]
    # transitive edges
    assert set(by["flask"].dependencies) == {"werkzeug", "jinja2"}
    assert by["jinja2"].dependencies == ["markupsafe"]
    assert by["pytest"].dependencies == ["iniconfig"]
    assert by["pytest"].dependency_specs["iniconfig"] == "*"


def test_poetry_lock_bad_package(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text("[[package]]\nname = \"x\"\n")
    with pytest.raises(ParseError, match="no version"):
        parse_poetry_lock(str(f))


def test_poetry_lock_files_hashes(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text(
        '[[package]]\nname = "a"\nversion = "1.0"\n'
        'files = [{file = "a.whl", hash = "sha256=' + ("ab" * 32) + '"}]\n')
    comp = parse_poetry_lock(str(f))[0]
    assert comp.hashes == {"SHA-256": "ab" * 32}


def test_poetry_lock_bad_files_entry(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text(
        '[[package]]\nname = "a"\nversion = "1.0"\n'
        'files = [{file = "a.whl", hash = "md4=deadbeef"}]\n')
    with pytest.raises(ParseError, match="invalid hash"):
        parse_poetry_lock(str(f))


def test_poetry_lock_malformed_files_entry(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text(
        '[[package]]\nname = "a"\nversion = "1.0"\n'
        'files = [{file = "a.whl"}]\n')
    with pytest.raises(ParseError, match="invalid 'files' entry"):
        parse_poetry_lock(str(f))


def test_poetry_lock_not_table(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text('package = "not-a-list"\n')
    with pytest.raises(ParseError, match="missing"):
        parse_poetry_lock(str(f))


# ---------------------------------------------------------------------------
# Pipfile / Pipfile.lock
# ---------------------------------------------------------------------------

def test_pipfile_and_lock(py_pipfile_project):
    import os

    root, deps = parse_pipfile(os.path.join(py_pipfile_project, "Pipfile"))
    assert {d.normalized_name for d in deps} == {
        "requests", "flask", "pytest"}
    scan = scan_project(py_pipfile_project)[0]
    assert scan.lock_file == "Pipfile.lock"
    locked = {c.normalized_name: c for c in scan.components}
    assert locked["requests"].version == "2.31.0"
    assert locked["requests"].hashes["SHA-256"] == "abc123"
    assert locked["pytest"].version == "7.4.4"


def test_pipfile_lock_missing_version(tmp_path):
    f = tmp_path / "Pipfile.lock"
    f.write_text('{"default": {"broken": {}}}')
    from sbomtool.parsers.python_scan import parse_pipfile_lock

    with pytest.raises(ParseError, match="no version"):
        parse_pipfile_lock(str(f))


# ---------------------------------------------------------------------------
# Project scan + lock/manifest consistency
# ---------------------------------------------------------------------------

def test_scan_poetry_resolved_and_direct(py_poetry_project):
    scan = scan_project(py_poetry_project)[0]
    assert scan.ecosystem == "python"
    assert scan.lock_file == "poetry.lock"
    names = {c.normalized_name for c in scan.components}
    # root direct deps include the dev group dep
    assert {"flask", "pytest", "requests"} <= set(scan.root_direct)
    # transitive components also present
    assert {"jinja2", "markupsafe", "werkzeug", "iniconfig"} <= names


def test_scan_pinned_requirements_self_lock(py_pinned_project):
    scan = scan_project(py_pinned_project)[0]
    assert scan.lock_file is not None
    cert = next(c for c in scan.components
                if c.normalized_name == "certifi")
    assert cert.version == "2024.2.2"
    assert cert.hashes["SHA-256"] == "aaaabbbbccccdddd"


def test_scan_no_lock_marks_unresolved(py_unpinned_project):
    scan = scan_project(py_unpinned_project)[0]
    assert scan.lock_file is None
    issues_msgs = " ".join(scan.warnings)
    assert "no lock file" in issues_msgs
    flask = next(c for c in scan.components if c.normalized_name == "flask")
    assert flask.version is None
