"""Tests for offline license policy enforcement."""

from __future__ import annotations

import json

import pytest

from sbomtool.errors import PolicyError
from sbomtool.model import Component
from sbomtool.policy import (
    evaluate_policy,
    load_license_catalogue,
    load_policy,
    validate_policy,
)


def _comp(name, license_id=None, eco="python", version="1.0.0"):
    return Component(
        ecosystem=eco, name=name, normalized_name=name.lower(),
        version=version, licenses=[license_id] if license_id else [])


# ---------------------------------------------------------------------------
# policy validation
# ---------------------------------------------------------------------------

def test_policy_not_object():
    with pytest.raises(PolicyError, match="must be a JSON object"):
        validate_policy([1, 2, 3])


def test_policy_unknown_keys():
    with pytest.raises(PolicyError, match="unknown policy keys"):
        validate_policy({"policy": "denylist", "bogus": True})


def test_policy_bad_mode():
    with pytest.raises(PolicyError, match="policy.mode"):
        validate_policy({"policy": "madness"})


def test_policy_bad_on_unknown():
    with pytest.raises(PolicyError, match="onUnknown"):
        validate_policy({"onUnknown": "explode"})


def test_allowlist_requires_allow():
    with pytest.raises(PolicyError, match="at least one allowed"):
        validate_policy({"policy": "allowlist", "allow": []})


def test_policy_lists_must_be_strings():
    with pytest.raises(PolicyError, match="list of non-empty strings"):
        validate_policy({"policy": "denylist", "deny": [1, 2]})
    with pytest.raises(PolicyError, match="list of non-empty strings"):
        validate_policy({"policy": "denylist", "deny": [""]})


def test_policy_duplicate_entries():
    with pytest.raises(PolicyError, match="duplicate license entries"):
        validate_policy({"policy": "allowlist",
                         "allow": ["MIT", "mit"]})


def test_policy_bad_version():
    with pytest.raises(PolicyError, match="unsupported policy version"):
        validate_policy({"version": 2, "policy": "denylist"})


def test_load_policy_corrupt_file(tmp_path):
    f = tmp_path / "p.json"
    f.write_text("{broken")
    with pytest.raises(PolicyError, match="invalid JSON policy"):
        load_policy(str(f))


def test_load_policy_missing_file(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(str(tmp_path / "nope.json"))


def test_catalogue_validation(tmp_path):
    f = tmp_path / "cat.json"
    f.write_text(json.dumps({"python": {"flask": "BSD-3-Clause"},
                             "cobol": {"x": "y"}}))
    with pytest.raises(PolicyError, match="unknown ecosystem"):
        load_license_catalogue(str(f))
    f.write_text(json.dumps({"python": {"flask": 5}}))
    with pytest.raises(PolicyError, match="map package names"):
        load_license_catalogue(str(f))


def test_catalogue_corrupt(tmp_path):
    f = tmp_path / "cat.json"
    f.write_text("nope")
    with pytest.raises(PolicyError):
        load_license_catalogue(str(f))


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

ALLOW = validate_policy({
    "policy": "allowlist",
    "allow": ["MIT", "Apache-2.0", "BSD-3-Clause"],
    "deny": ["GPL-3.0-only"],
    "onUnknown": "error",
})


def test_allowed_package_passes():
    assert evaluate_policy(ALLOW, [_comp("a", "MIT")]) == []


def test_denied_license_reported():
    violations = evaluate_policy(ALLOW, [_comp("evil", "GPL-3.0-only")])
    assert len(violations) == 1
    v = violations[0]
    assert v["code"] == "DENIED_LICENSE"
    assert v["severity"] == "error"
    assert v["component"] == "evil"


def test_unallowed_license_reported():
    violations = evaluate_policy(ALLOW, [_comp("weird", "WTFPL")])
    assert violations[0]["code"] == "LICENSE_NOT_ALLOWED"


def test_unknown_license_modes():
    comp = _comp("mystery", None)
    err = evaluate_policy(ALLOW, [comp])
    assert err[0]["code"] == "UNKNOWN_LICENSE"
    assert err[0]["severity"] == "error"

    warn_policy = {**ALLOW, "onUnknown": "warn"}
    v = evaluate_policy(warn_policy, [comp])
    assert v[0]["severity"] == "warning"

    pass_policy = {**ALLOW, "onUnknown": "allow"}
    assert evaluate_policy(pass_policy, [comp]) == []


def test_deny_wins_over_allow():
    policy = validate_policy({
        "policy": "allowlist",
        "allow": ["MIT", "GPL-3.0-only"],
        "deny": ["GPL-3.0-only"],
    })
    violations = evaluate_policy(policy, [_comp("g", "GPL-3.0-only")])
    assert violations[0]["code"] == "DENIED_LICENSE"


def test_spdx_or_expression():
    dual = _comp("dual", "MIT OR GPL-3.0-only")
    # one branch denied, one allowed -> overall allowed via OR
    assert evaluate_policy(ALLOW, [dual]) == []
    all_bad = _comp("bador", "WTFPL OR GPL-3.0-only")
    v = evaluate_policy(ALLOW, [all_bad])
    assert len(v) == 1


def test_spdx_and_expression():
    dual = _comp("dual", "MIT AND Apache-2.0")
    assert evaluate_policy(ALLOW, [dual]) == []
    partial = _comp("partial", "MIT AND WTFPL")
    assert evaluate_policy(ALLOW, [partial])


def test_ignore_list():
    policy = {**ALLOW, "ignore": ["mystery", "npm:evil"]}
    comps = [_comp("mystery", None),
             _comp("evil", "GPL-3.0-only", eco="npm")]
    assert evaluate_policy(policy, comps) == []


def test_case_insensitive_matching():
    assert evaluate_policy(ALLOW, [_comp("a", "mit")]) == []
    assert evaluate_policy(ALLOW, [_comp("b", "gpl-3.0-only")])


def test_denylist_mode():
    policy = validate_policy({
        "policy": "denylist",
        "deny": ["GPL-3.0-only"],
        "onUnknown": "error",
    })
    assert evaluate_policy(policy, [_comp("x", "WTFPL")]) == []
    assert evaluate_policy(policy, [_comp("g", "GPL-3.0-only")])
    unknown = evaluate_policy(policy, [_comp("u", None)])
    assert unknown[0]["code"] == "UNKNOWN_LICENSE"


def test_license_from_catalogue():
    catalogue = {"python": {"flask": "BSD-3-Clause"}}
    comp = _comp("Flask", None)  # no embedded license
    assert evaluate_policy(ALLOW, [comp], catalogue) == []
    mystery = _comp("unknown-pkg", None)
    v = evaluate_policy(ALLOW, [mystery], catalogue)
    assert v[0]["code"] == "UNKNOWN_LICENSE"
