"""Tests for version parsing and constraint matching."""

from __future__ import annotations

import pytest

from sbomtool.errors import ParseError
from sbomtool.versions import (
    compare_versions,
    npm_spec_matches,
    parse_npm_version,
    parse_python_version,
    python_spec_matches,
)


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec,version,expected", [
    ("==2.0", "2.0.0", True),
    ("==2.0", "2.0.1", False),
    ("==2.0", "2.0a1", False),
    ("==2.0.*", "2.0.9", True),
    ("==2.0.*", "2.1.0", False),
    ("==2.0a1", "2.0a1", True),
    ("!=1.0", "1.0.1", True),
    ("!=1.0", "1.0", False),
    ("!=1.0.*", "1.0.5", False),
    (">=1.0", "1.0", True),
    (">=1.0", "0.9", False),
    ("<=1.0", "1.0", True),
    ("<1.0", "1.0", False),
    (">1.0", "1.0", False),
    (">1.0", "1.0.1", True),
    ("~=1.4.2", "1.4.9", True),
    ("~=1.4.2", "1.5.0", False),
    ("~=2.2", "2.99", True),
    ("~=2.2", "3.0", False),
    (">=1.0,<2.0", "1.99", True),
    (">=1.0,<2.0", "2.0", False),
    ("===1.0", "1.0", True),
])
def test_python_spec_matching(spec, version, expected):
    assert python_spec_matches(spec, version) is expected


def test_python_prerelease_order():
    assert parse_python_version("1.0a1") < parse_python_version("1.0")
    assert parse_python_version("1.0") < parse_python_version("1.0.post1")
    assert compare_versions("1.10", "1.9", "python") > 0
    assert compare_versions("2.0a1", "2.0", "python") < 0


def test_python_bad_tilde_raises():
    with pytest.raises(ParseError):
        python_spec_matches("~=1", "1.0")


def test_python_unparseable():
    assert python_spec_matches("not-a-spec", "1.0") is False
    assert python_spec_matches("==1.0", "not-a-version") is False
    assert python_spec_matches("", "1.0") is False


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec,version,expected", [
    ("1.2.3", "1.2.3", True),
    ("1.2.3", "1.2.4", False),
    ("^1.2.3", "1.9.0", True),
    ("^1.2.3", "2.0.0", False),
    ("^0.2.3", "0.2.9", True),
    ("^0.2.3", "0.3.0", False),
    ("^0.0.3", "0.0.3", True),
    ("^0.0.3", "0.0.4", False),
    ("~1.2.3", "1.2.9", True),
    ("~1.2.3", "1.3.0", False),
    ("~1.2", "1.2.9", True),
    ("1.x", "1.9.0", True),
    ("1.x", "2.0.0", False),
    ("*", "9.9.9", True),
    (">=1.0.0 <2.0.0", "1.5.0", True),
    (">=1.0.0 <2.0.0", "2.0.0", False),
    ("1.2.3 - 2.3.4", "2.3.4", True),
    ("1.2.3 - 2.3.4", "2.3.5", False),
    ("1.x || 2.x", "2.5.0", True),
    ("1.x || 2.x", "3.0.0", False),
    (">1.2.3", "1.2.4", True),
    (">1.2", "1.3.0", True),
    (">1", "2.0.0", True),
    ("<1.2", "1.1.9", True),
    ("<=1.2.3", "1.2.3", True),
    ("=1.2.3", "1.2.3", True),
])
def test_npm_spec_matching(spec, version, expected):
    assert npm_spec_matches(spec, version) is expected


def test_npm_tags_dont_match():
    # A dist-tag such as "latest" cannot be verified offline
    assert npm_spec_matches("latest", "1.2.3") is False
    assert npm_spec_matches("", "1.2.3") is False
    assert npm_spec_matches("^1.0.0", "garbage") is False


def test_npm_parse():
    assert parse_npm_version("1.2.3")[0] == (1, 2, 3)
    assert parse_npm_version("v1.2.3")[0] == (1, 2, 3)
    assert parse_npm_version("01.2.3") is None
    assert parse_npm_version("1.2") is None
    # prerelease sorts below release
    a, _ = parse_npm_version("1.0.0-alpha")
    b, _ = parse_npm_version("1.0.0")
    assert parse_npm_version("1.0.0-alpha") < parse_npm_version("1.0.0")


def test_compare_versions_fallback():
    assert compare_versions("weird-a", "weird-b", "npm") < 0
