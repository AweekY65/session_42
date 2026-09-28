"""Tests for local install-tree scanning (site-packages / node_modules)."""

import os
import tempfile
import unittest

from sbomtool.analyzer import analyze, integrity_findings
from sbomtool.localmeta import (
    scan_node_packages,
    scan_python_packages,
    find_python_site_packages,
    find_node_modules,
)
from sbomtool.models import SOURCE_LOCK_LOCAL, SOURCE_LOCAL
from tests.support import write, write_json, finding_codes


class LocalSitePackagesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.sp = os.path.join(
            self.tmp, ".venv", "lib", "python3.12", "site-packages")
        os.makedirs(self.sp)

    def _dist(self, name, version, license_expr=None, record=None,
              classifier=None):
        d = os.path.join(self.sp, f"{name}-{version}.dist-info")
        os.makedirs(d, exist_ok=True)
        lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
        if license_expr:
            lines.append(f"License-Expression: {license_expr}")
        if classifier:
            lines.append(f"Classifier: {classifier}")
        write(os.path.join(d, "METADATA"), "\n".join(lines) + "\n")
        if record:
            write(os.path.join(d, "RECORD"), record)

    def test_metadata_license_and_record_hashes(self):
        self._dist("requests", "2.31.0", "Apache-2.0",
                   "requests/api.py,sha256=" + "a" * 64 + ",12\n")
        pkgs = scan_python_packages([self.sp])
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0].licenses, ["Apache-2.0"])
        self.assertTrue(pkgs[0].hashes)
        self.assertEqual(pkgs[0].hashes[0].origin, "local-record")

    def test_license_classifier_mapped(self):
        self._dist("oldpkg", "1.0", classifier="License :: OSI Approved :: MIT License")
        pkgs = scan_python_packages([self.sp])
        self.assertIn("MIT", pkgs[0].licenses)

    def test_local_only_package_flagged_lock_miss(self):
        self._dist("rogue", "9.9.9")
        write(os.path.join(self.tmp, "pyproject.toml"),
              '[project]\nname="app"\ndependencies=[]\n')
        write(os.path.join(self.tmp, "uv.lock"), "version = 1\n")
        sbom = analyze(self.tmp)
        comp = sbom.components["python:rogue"]
        self.assertEqual(comp.source_type, SOURCE_LOCAL)
        codes = finding_codes(integrity_findings(sbom))
        self.assertIn("LOCK_MISS", codes)

    def test_lock_plus_local_enrichment(self):
        self._dist("flask", "3.0.0", "BSD-3-Clause",
                   "flask/app.py,sha256=" + "f" * 64 + ",9\n")
        write(os.path.join(self.tmp, "pyproject.toml"),
              '[project]\nname="app"\ndependencies=["flask==3.0.0"]\n')
        write(os.path.join(self.tmp, "uv.lock"),
              'version = 1\n[[package]]\nname = "flask"\nversion = "3.0.0"\n')
        sbom = analyze(self.tmp)
        comp = sbom.components["python:flask"]
        self.assertEqual(comp.source_type, SOURCE_LOCK_LOCAL)
        self.assertTrue(any(h.origin == "local-record" for h in comp.hashes))
        self.assertIn("BSD-3-Clause", comp.licenses)

    def test_auto_discovery_finds_venv(self):
        self.assertIn(self.sp, find_python_site_packages(self.tmp))


class LocalNodeModulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.nm = os.path.join(self.tmp, "node_modules")

    def test_scoped_and_nested_packages(self):
        write_json(os.path.join(self.nm, "left-pad", "package.json"),
                   {"name": "left-pad", "version": "1.3.0", "license": "WTFPL"})
        write_json(os.path.join(self.nm, "@scope", "x", "package.json"),
                   {"name": "@scope/x", "version": "2.0.0"})
        # nested node_modules (npm hoisting boundary)
        write_json(
            os.path.join(self.nm, "left-pad", "node_modules", "ms",
                         "package.json"),
            {"name": "ms", "version": "2.0.0"})
        roots = find_node_modules(self.tmp)
        pkgs = scan_node_packages(roots)
        by_name = {p.name: p for p in pkgs}
        self.assertIn("left-pad", by_name)
        self.assertIn("@scope/x", by_name)
        self.assertIn("ms", by_name)
        # installed package.json content hash is recorded
        self.assertTrue(any(h.origin == "local-content"
                            for h in by_name["left-pad"].hashes))
        self.assertEqual(by_name["left-pad"].licenses, ["WTFPL"])

    def test_corrupt_installed_manifest_raises(self):
        write(os.path.join(self.nm, "bad", "package.json"), "{ broken")
        from sbomtool.errors import SbomError
        with self.assertRaises(SbomError):
            scan_node_packages([self.nm])


class MixedEcosystemTests(unittest.TestCase):
    def test_python_and_node_in_one_project(self):
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "pyproject.toml"),
              '[project]\nname="app"\ndependencies=["click==8.1.7"]\n')
        write(os.path.join(tmp, "uv.lock"),
              'version = 1\n[[package]]\nname = "click"\nversion = "8.1.7"\n')
        write_json(os.path.join(tmp, "package.json"),
                   {"name": "app", "dependencies": {"ms": "^2.0.0"}})
        write_json(os.path.join(tmp, "package-lock.json"), {
            "lockfileVersion": 3,
            "packages": {"node_modules/ms": {"version": "2.1.3",
                                             "integrity": "sha512-QU0="}}})
        sbom = analyze(tmp, use_local=False)
        self.assertIn("python:click", sbom.components)
        self.assertIn("npm:ms", sbom.components)


if __name__ == "__main__":
    unittest.main(verbosity=2)
