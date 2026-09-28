"""Tests for integrity checks: missing/duplicate/mismatch/broken deps."""

import json
import os
import tempfile
import unittest

from sbomtool.analyzer import analyze, integrity_findings
from sbomtool.models import (
    Component, Ecosystem, SBOM, Severity, SOURCE_LOCK,
)
from tests.support import write, write_json, finding_codes


def _npm_project(tmp, declared, locked_packages):
    write_json(os.path.join(tmp, "package.json"),
               {"name": "app", "version": "1.0.0", "dependencies": declared})
    packages = {"": {"name": "app", "version": "1.0.0"}}
    for name, meta in locked_packages.items():
        entry = {"version": meta["version"]}
        if "integrity" in meta:
            entry["integrity"] = meta["integrity"]
        if meta.get("deps"):
            entry["dependencies"] = dict.fromkeys(meta["deps"], "*")
        packages[f"node_modules/{name}"] = entry
    write_json(os.path.join(tmp, "package-lock.json"),
               {"name": "app", "version": "1.0.0", "lockfileVersion": 3,
                "packages": packages})


class IntegrityTests(unittest.TestCase):
    def test_missing_declared_package(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"ghost": "^1.0.0"},
                     {"present": {"version": "1.0.0",
                                  "integrity": "sha512-QU0="}})
        sbom = analyze(tmp, use_local=False)
        codes = finding_codes(integrity_findings(sbom))
        self.assertIn("MISSING_PACKAGE", codes)

    def test_version_mismatch_detected(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"a": "~1.2.0"},
                     {"a": {"version": "1.5.0", "integrity": "sha512-QU0="}})
        sbom = analyze(tmp, use_local=False)
        findings = [f for f in integrity_findings(sbom)
                    if f.code == "VERSION_MISMATCH"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.ERROR)

    def test_version_match_no_false_positive(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"a": "^1.2.0"},
                     {"a": {"version": "1.9.9", "integrity": "sha512-QU0="}})
        sbom = analyze(tmp, use_local=False)
        self.assertNotIn("VERSION_MISMATCH",
                         finding_codes(integrity_findings(sbom)))

    def test_duplicate_component_multiple_versions(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"a": "^1.0.0"},
                     {"a": {"version": "1.0.0", "integrity": "sha512-QU0="}})
        # add a second lock file (yarn) resolving the same name differently
        write(os.path.join(tmp, "yarn.lock"),
              'a@^1.0.0:\n  version "1.5.0"\n  integrity sha512-WV0=\n')
        sbom = analyze(tmp, use_local=False)
        findings = [f for f in integrity_findings(sbom)
                    if f.code == "DUP_VERSION"]
        self.assertEqual(len(findings), 1)
        self.assertIn("1.0.0", findings[0].message)
        self.assertIn("1.5.0", findings[0].message)

    def test_broken_transitive_dependency(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"a": "^1.0.0"},
                     {"a": {"version": "1.0.0", "integrity": "sha512-QU0=",
                            "deps": ["vanished"]}})
        sbom = analyze(tmp, use_local=False)
        codes = finding_codes(integrity_findings(sbom))
        self.assertIn("BROKEN_DEPENDENCY", codes)

    def test_missing_hash_warning(self):
        tmp = tempfile.mkdtemp()
        _npm_project(tmp, {"a": "^1.0.0"}, {"a": {"version": "1.0.0"}})
        sbom = analyze(tmp, use_local=False)
        findings = [f for f in integrity_findings(sbom)
                    if f.code == "NO_CONTENT_HASH"]
        self.assertEqual(len(findings), 1)

    def test_python_lock_declaration_drift(self):
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "pyproject.toml"),
              '[project]\nname="d"\ndependencies=["flask==2.0.0"]\n')
        write(os.path.join(tmp, "uv.lock"),
              'version = 1\n[[package]]\nname = "flask"\nversion = "3.0.0"\n')
        sbom = analyze(tmp, use_local=False)
        findings = [f for f in integrity_findings(sbom)
                    if f.code == "VERSION_MISMATCH"]
        self.assertEqual(len(findings), 1)


class ManualSBOMTests(unittest.TestCase):
    def _comp(self, name, version, deps=(), hashes=(), source=SOURCE_LOCK):
        return Component(
            ecosystem=Ecosystem.NPM, name=name, version=version,
            source_type=source,
            dependencies=set(deps),
            hashes=list(hashes),
        )

    def test_findings_deterministic_order(self):
        sbom = SBOM("p", "1.0", "/x")
        for name in ("zebra", "alpha", "mid"):
            sbom.components[f"npm:{name}"] = self._comp(name, "1.0.0")
        f1 = integrity_findings(sbom)
        f2 = integrity_findings(sbom)
        self.assertEqual([f.message for f in f1], [f.message for f in f2])
        self.assertTrue(all(f.severity == Severity.WARNING for f in f1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
