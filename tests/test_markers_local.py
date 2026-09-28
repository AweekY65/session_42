"""Tests for PEP 508 markers, local path deps and editable installs."""

from __future__ import annotations

import pytest

from sbomtool.errors import ParseError
from sbomtool.pep508 import evaluate_marker, parse_requirement
from sbomtool.parsers.python_scan import parse_requirements_txt


def test_parse_requirement_with_marker_and_extras():
    r = parse_requirement('requests[security,socks]>=2.0; python_version < "4"')
    assert r["name"] == "requests"
    assert r["extras"] == ["security", "socks"]
    assert r["spec"] == ">=2.0"
    assert r["markers"] == 'python_version < "4"'


def test_parse_requirement_direct_reference():
    r = parse_requirement("pkg @ https://example.invalid/pkg-1.0.tar.gz")
    assert r["name"] == "pkg"
    assert r["url"] == "https://example.invalid/pkg-1.0.tar.gz"


def test_parse_requirement_invalid():
    with pytest.raises(ParseError):
        parse_requirement("!!!")


@pytest.mark.parametrize("marker,expected", [
    ('python_version >= "3.10"', True),
    ('python_version < "3.0"', False),
    ('sys_platform == "linux"', True),
    ('sys_platform == "win32"', False),
    ('os_name == "posix" and python_version >= "3.10"', True),
    ('sys_platform == "win32" or sys_platform == "linux"', True),
    ('python_version != "3.10"', True),
    ('python_version in "3.12"', True),
])
def test_evaluate_marker(marker, expected):
    assert evaluate_marker(marker) is expected


def test_marker_invalid_raises():
    with pytest.raises(ParseError):
        evaluate_marker("totally invalid marker $$$")


def test_requirements_marker_filtering(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(
        'winpkg==1.0; sys_platform == "win32"\n'
        'nixpkg==2.0; sys_platform == "linux"\n')
    deps = parse_requirements_txt(str(f))
    assert {d.normalized_name for d in deps} == {"winpkg", "nixpkg"}
    # integrity analysis skips deps whose markers evaluate False
    from sbomtool.integrity import analyze_integrity
    from sbomtool.parsers.project import scan_project

    scan = scan_project(str(tmp_path))
    issues = analyze_integrity(scan)
    missing = [i for i in issues if i["code"] == "MISSING_PACKAGE"]
    # both deps are pinned (==) so they self-resolve; the winpkg marker is
    # False on this platform and must never be reported missing
    assert all(i["component"] != "winpkg" for i in missing)


def test_editable_install_local(tmp_path):
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    (pkg_dir / "pyproject.toml").write_text(
        '[project]\nname = "mypkg"\nversion = "0.1.0"\n')
    req = tmp_path / "requirements.txt"
    req.write_text("-e ./mypkg\n")
    deps = parse_requirements_txt(str(req))
    assert deps[0].normalized_name == "mypkg"
    assert deps[0].source_type == "file"


def test_local_path_dependency_hash(tmp_path):
    vendored = tmp_path / "vendor" / "libx"
    vendored.mkdir(parents=True)
    (vendored / "content.txt").write_text("payload")
    req = tmp_path / "requirements.txt"
    req.write_text("libx @ file://./vendor/libx\n")
    deps = parse_requirements_txt(str(req))
    assert deps[0].source_type == "file"
    assert "SHA-256" in deps[0].hashes

    # hash changes when local content changes
    (vendored / "content.txt").write_text("tampered")
    deps2 = parse_requirements_txt(str(req))
    assert deps2[0].hashes["SHA-256"] != deps[0].hashes["SHA-256"]


def test_vcs_dependency_parsing(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "git+https://example.invalid/repo.git@v1.2.3#egg=mytool\n")
    deps = parse_requirements_txt(str(req))
    assert deps[0].normalized_name == "mytool"
    assert deps[0].source_type == "vcs"
    assert deps[0].spec == "v1.2.3"
