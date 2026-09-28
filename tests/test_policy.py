"""Tests for offline license policy loading and enforcement."""

import json
import os
import tempfile
import unittest

from sbomtool.errors import PolicyError
from sbomtool.models import Component, Ecosystem
from sbomtool.policy import Policy, evaluate, load_policy
from tests.support import write


def _comp(name, licenses=(), version="1.0.0"):
    return Component(ecosystem=Ecosystem.NPM, name=name, version=version,
                     licenses=list(licenses), source_type="lock")


class PolicyLoadingTests(unittest.TestCase):
    def _load(self, obj):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "policy.json")
        write(path, json.dumps(obj))
        return load_policy(path)

    def test_valid_policy(self):
        p = self._load({"policy_version": 1, "action_on_unknown": "deny",
                        "allow": ["MIT", "Apache-2.0"], "deny": ["GPL-3.0-only"]})
        self.assertEqual(p.action_on_unknown, "deny")

    def test_missing_file_is_policy_error(self):
        with self.assertRaises(PolicyError):
            load_policy("/nonexistent/policy.json")

    def test_broken_json_rejected(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "p.json")
        write(path, "{ not json")
        with self.assertRaises(PolicyError):
            load_policy(path)

    def test_unknown_action_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"action_on_unknown": "explode"})

    def test_unknown_key_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"allow": ["MIT"], "extra_key": 1})

    def test_wrong_types_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"allow": "MIT"})
        with self.assertRaises(PolicyError):
            self._load({"allow": [1, 2]})

    def test_allow_deny_overlap_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"allow": ["MIT"], "deny": ["MIT"]})

    def test_bad_license_id_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"allow": ["not a license!!"]})

    def test_unsupported_version_rejected(self):
        with self.assertRaises(PolicyError):
            self._load({"policy_version": 99})

    def test_top_level_must_be_object(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "p.json")
        write(path, "[1,2,3]")
        with self.assertRaises(PolicyError):
            load_policy(path)


class PolicyEvaluationTests(unittest.TestCase):
    def test_denied_license(self):
        p = Policy(deny={"GPL-3.0-only"})
        comps = {"npm:x": _comp("x", ["GPL-3.0-only"])}
        findings = evaluate(p, comps)
        self.assertEqual([f.code for f in findings], ["LICENSE_DENIED"])

    def test_allowed_license_passes(self):
        p = Policy(allow={"MIT", "Apache-2.0"}, action_on_unknown="deny")
        comps = {"npm:x": _comp("x", ["MIT"])}
        self.assertEqual(evaluate(p, comps), [])

    def test_dual_licensed_one_allowed(self):
        p = Policy(allow={"MIT"}, action_on_unknown="deny")
        comps = {"npm:x": _comp("x", ["GPL-3.0-only", "MIT"])}
        # denial still wins if a denied license is present
        p2 = Policy(allow={"MIT"}, deny={"GPL-3.0-only"})
        self.assertEqual([f.code for f in evaluate(p2, comps)], ["LICENSE_DENIED"])
        # without deny list, any allowed license clears the component
        self.assertEqual(evaluate(p, comps), [])

    def test_unknown_license_modes(self):
        comps = {"npm:x": _comp("x", ["Weird-License"])}
        self.assertEqual(
            [f.code for f in evaluate(Policy(allow={"MIT"}, action_on_unknown="warn"), comps)],
            ["LICENSE_NOT_LISTED"])
        denied = evaluate(Policy(allow={"MIT"}, action_on_unknown="deny"), comps)
        self.assertEqual(denied[0].severity.value, "error")
        self.assertEqual(
            evaluate(Policy(allow={"MIT"}, action_on_unknown="allow"), comps), [])

    def test_no_license_declared(self):
        comps = {"npm:x": _comp("x", [])}
        findings = evaluate(Policy(action_on_unknown="warn"), comps)
        self.assertEqual(findings[0].code, "LICENSE_UNKNOWN")
        findings = evaluate(Policy(action_on_unknown="deny"), comps)
        self.assertEqual(findings[0].code, "LICENSE_UNKNOWN_DENIED")

    def test_component_override_for_internal(self):
        comps = {"npm:internal-lib": _comp("internal-lib", [])}
        p = Policy(action_on_unknown="deny",
                   allow_unknown_components={"internal-lib"})
        self.assertEqual(evaluate(p, comps), [])

    def test_violations_name_specific_components(self):
        comps = {
            "npm:good": _comp("good", ["MIT"]),
            "npm:bad": _comp("bad", ["GPL-3.0-only"]),
        }
        p = Policy(deny={"GPL-3.0-only"})
        findings = evaluate(p, comps)
        self.assertEqual(len(findings), 1)
        self.assertIn("bad", findings[0].component)


if __name__ == "__main__":
    unittest.main(verbosity=2)
