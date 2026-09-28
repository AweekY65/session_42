"""Tests for SBOM diff: add/remove/upgrade, hash changes, order stability."""

import json
import os
import tempfile
import unittest

from sbomtool.cyclonedx import dumps
from sbomtool.analyzer import analyze
from sbomtool.diff import diff_sboms
from sbomtool.errors import InputError
from tests.support import write, write_json


def _build(tmp, deps, packages):
    write_json(os.path.join(tmp, "package.json"),
               {"name": "app", "version": "1.0.0", "dependencies": deps})
    pkgs = {"": {"name": "app", "version": "1.0.0"}}
    for name, meta in packages.items():
        entry = {"version": meta["version"]}
        if "integrity" in meta:
            entry["integrity"] = meta["integrity"]
        if meta.get("license"):
            entry["license"] = meta["license"]
        pkgs[f"node_modules/{name}"] = entry
    write_json(os.path.join(tmp, "package-lock.json"),
               {"name": "app", "version": "1.0.0", "lockfileVersion": 3,
                "packages": pkgs})


def _gen(tmp):
    return analyze(tmp, use_local=False)


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.v1 = os.path.join(self.dir, "v1")
        self.v2 = os.path.join(self.dir, "v2")
        os.makedirs(self.v1)
        os.makedirs(self.v2)
        _build(self.v1,
               {"a": "^1", "b": "^2", "c": "^1"},
               {"a": {"version": "1.2.0", "integrity": "sha512-QU0="},
                "b": {"version": "2.3.0", "integrity": "sha512-QU1="},
                "c": {"version": "1.0.0", "integrity": "sha512-QU0="}})

    def _emit(self, project, name):
        path = os.path.join(self.dir, name)
        write(path, dumps(_gen(project)))
        return path

    def test_added_removed_upgraded_hash(self):
        _build(self.v2,
               {"a": "^1", "b": "^2", "d": "^3"},
               # a: same version, changed hash; b: upgraded; c removed; d added
               {"a": {"version": "1.2.0", "integrity": "sha512-WV0="},
                "b": {"version": "2.4.0", "integrity": "sha512-QU1="},
                "d": {"version": "3.0.1", "integrity": "sha512-ZZ0="}})
        p1, p2 = self._emit(self.v1, "s1.json"), self._emit(self.v2, "s2.json")
        d = diff_sboms(p1, p2)
        self.assertEqual(d.added, ["npm:d"])
        self.assertEqual(d.removed, ["npm:c"])
        self.assertEqual(len(d.upgraded), 1)
        self.assertEqual(d.upgraded[0]["component"], "npm:b")
        self.assertEqual(d.upgraded[0]["from"], "2.3.0")
        self.assertEqual(d.upgraded[0]["to"], "2.4.0")
        self.assertEqual(len(d.version_same_hash_changed), 1)
        self.assertEqual(d.version_same_hash_changed[0]["component"], "npm:a")

    def test_input_order_does_not_matter(self):
        # rebuild v2 as an identical component SET written in reverse order
        _build(self.v2,
               {"c": "^1", "b": "^2", "a": "^1"},
               {"c": {"version": "1.0.0", "integrity": "sha512-QU0="},
                "b": {"version": "2.3.0", "integrity": "sha512-QU1="},
                "a": {"version": "1.2.0", "integrity": "sha512-QU0="}})
        p1, p2 = self._emit(self.v1, "a.json"), self._emit(self.v2, "b.json")
        d = diff_sboms(p1, p2)
        self.assertTrue(d.is_empty, d.to_dict())

    def test_identical_documents_diff_empty(self):
        p1 = self._emit(self.v1, "x.json")
        p2 = self._emit(self.v1, "y.json")
        self.assertTrue(diff_sboms(p1, p2).is_empty)

    def test_downgrade_detected(self):
        _build(self.v2, {"a": "^1", "b": "^2", "c": "^1"},
               {"a": {"version": "1.2.0", "integrity": "sha512-QU0="},
                "b": {"version": "2.1.0", "integrity": "sha512-QU0="},
                "c": {"version": "1.0.0", "integrity": "sha512-QU0="}})
        p1, p2 = self._emit(self.v1, "d1.json"), self._emit(self.v2, "d2.json")
        d = diff_sboms(p1, p2)
        self.assertEqual(len(d.downgraded), 1)
        self.assertEqual(d.downgraded[0]["component"], "npm:b")

    def test_license_change_detected(self):
        _build(self.v2, {"a": "^1", "b": "^2", "c": "^1"},
               {"a": {"version": "1.2.0", "integrity": "sha512-QU0=",
                      "license": "GPL-3.0-only"},
                "b": {"version": "2.3.0", "integrity": "sha512-QU1="},
                "c": {"version": "1.0.0", "integrity": "sha512-QU0="}})
        p1, p2 = self._emit(self.v1, "l1.json"), self._emit(self.v2, "l2.json")
        d = diff_sboms(p1, p2)
        self.assertEqual(len(d.license_changed), 1)
        self.assertEqual(d.license_changed[0]["component"], "npm:a")

    def test_dependency_edge_diff(self):
        _build(self.v2, {"a": "^1", "b": "^2", "c": "^1"},
               {"a": {"version": "1.2.0", "integrity": "sha512-QU0="},
                "b": {"version": "2.3.0", "integrity": "sha512-QU0="},
                "c": {"version": "1.0.0", "integrity": "sha512-QU0="}})
        # add an edge a->c in v2
        lock = json.loads(open(os.path.join(self.v2, "package-lock.json")).read())
        lock["packages"]["node_modules/a"]["dependencies"] = {"c": "^1"}
        write_json(os.path.join(self.v2, "package-lock.json"), lock)
        p1, p2 = self._emit(self.v1, "e1.json"), self._emit(self.v2, "e2.json")
        d = diff_sboms(p1, p2)
        self.assertTrue(any("npm:a->npm:c" in e for e in d.dependency_edges_added))

    def test_corrupt_sbom_rejected(self):
        bad = os.path.join(self.dir, "bad.json")
        write(bad, "{broken")
        with self.assertRaises(InputError):
            diff_sboms(self._emit(self.v1, "ok.json"), bad)

    def test_non_cyclonedx_rejected(self):
        bad = os.path.join(self.dir, "other.json")
        write(bad, json.dumps({"hello": "world"}))
        with self.assertRaises(InputError):
            diff_sboms(bad, bad)


class OutputStabilityTests(unittest.TestCase):
    def test_byte_stable_across_runs(self):
        tmp = tempfile.mkdtemp()
        _build(tmp, {"z": "^1", "a": "^1"},
               {"z": {"version": "1.0.0", "integrity": "sha512-QU0="},
                "a": {"version": "1.0.0", "integrity": "sha512-WV0="}})
        first = dumps(_gen(tmp))
        second = dumps(_gen(tmp))
        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(parsed["bomFormat"], "CycloneDX")


if __name__ == "__main__":
    unittest.main(verbosity=2)
