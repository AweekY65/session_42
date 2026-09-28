"""Tests for SBOM diff (order-independent, add/remove/upgrade/hash)."""

from __future__ import annotations

import copy
import json

import pytest

from sbomtool.diff import diff_sboms
from sbomtool.errors import SBOMError


def _doc(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": components}


def _lib(eco, name, version, algo=None, digest=None):
    comp = {
        "type": "library",
        "bom-ref": f"pkg:{eco}/{name}@{version}",
        "name": name.split("/")[-1],
        "version": version,
        "purl": f"pkg:{'pypi' if eco == 'python' else 'npm'}/{name}@{version}",
        "properties": [{"name": "sbom:ecosystem", "value": eco}],
    }
    if algo:
        comp["hashes"] = [{"alg": algo, "content": digest}]
    return comp


def test_diff_add_remove_upgrade():
    old = _doc([
        _lib("python", "alpha", "1.0.0"),
        _lib("python", "beta", "2.0.0"),
        _lib("npm", "gamma", "3.0.0"),
    ])
    new = _doc([
        _lib("python", "alpha", "1.0.0"),          # unchanged
        _lib("python", "beta", "2.5.0"),           # upgraded
        _lib("npm", "delta", "1.0.0"),             # added
    ])
    result = diff_sboms(old, new)
    assert result["summary"] == {
        "added": 1, "removed": 1, "upgraded": 1,
        "downgraded": 0, "changed": 0, "unchanged": 1}
    assert result["added"][0]["name"] == "delta"
    assert result["removed"][0]["name"] == "gamma"
    up = result["upgraded"][0]
    assert up["name"] == "beta"
    assert up["old_version"] == "2.0.0"
    assert up["new_version"] == "2.5.0"


def test_diff_downgrade_detected():
    old = _doc([_lib("python", "a", "2.0.0")])
    new = _doc([_lib("python", "a", "1.0.0")])
    result = diff_sboms(old, new)
    assert result["downgraded"][0]["name"] == "a"
    assert result["upgraded"] == []


def test_diff_hash_change_same_version():
    old = _doc([_lib("python", "a", "1.0.0", "SHA-256", "aaa")])
    new = _doc([_lib("python", "a", "1.0.0", "SHA-256", "bbb")])
    result = diff_sboms(old, new)
    assert result["changed"][0]["change"] == "hash"
    assert result["changed"][0]["hashes"] == {
        "algorithm": "SHA-256", "old": "aaa", "new": "bbb"}


def test_diff_input_order_irrelevant():
    base = [
        _lib("python", "a", "1.0.0"),
        _lib("npm", "b", "2.0.0"),
        _lib("python", "c", "3.0.0"),
    ]
    old = _doc(base)
    new = _doc(list(reversed(base)))
    result = diff_sboms(old, new)
    assert result["summary"] == {
        "added": 0, "removed": 0, "upgraded": 0, "downgraded": 0,
        "changed": 0, "unchanged": 3}


def test_diff_application_components_ignored():
    # metadata/application components must not pollute package diffs
    root = {"type": "application", "bom-ref": "root:x", "name": "x"}
    old = _doc([root, _lib("python", "a", "1.0.0")])
    new = _doc([root, _lib("python", "a", "1.0.0")])
    result = diff_sboms(old, new)
    assert result["summary"]["unchanged"] == 1


def test_diff_scoped_npm_names():
    old = _doc([_lib("npm", "@scope/pkg", "1.0.0")])
    new = _doc([_lib("npm", "@scope/pkg", "1.1.0")])
    result = diff_sboms(old, new)
    assert result["upgraded"][0]["name"] == "@scope/pkg"


def test_diff_rejects_non_cyclonedx():
    with pytest.raises(SBOMError, match="CycloneDX"):
        diff_sboms({"bomFormat": "SPDX"}, _doc([]))
    with pytest.raises(SBOMError, match="JSON object"):
        diff_sboms([1, 2, 3], _doc([]))


def test_diff_empty_documents():
    result = diff_sboms(_doc([]), _doc([]))
    assert all(v == 0 for v in result["summary"].values())
