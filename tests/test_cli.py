"""End-to-end CLI tests (subprocess) covering exit codes and report gates."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.support import write, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args):
    proc = subprocess.run(
        [sys.executable, "-m", "sbomtool", *args],
        cwd=ROOT, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _clean_project(tmp):
    write_json(os.path.join(tmp, "package.json"),
               {"name": "app", "version": "1.0.0",
                "dependencies": {"left-pad": "^1.0.0", "ms": "^2.0.0"}})
    write_json(os.path.join(tmp, "package-lock.json"), {
        "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.3.0",
                                      "integrity": "sha512-QU0=",
                                      "license": "MIT",
                                      "dependencies": {"ms": "*"}},
            "node_modules/ms": {"version": "2.1.3", "integrity": "sha512-WV0="},
        }})


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        _clean_project(self.tmp)

    def test_version_flag(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn("localsbom", out)

    def test_generate_stdout_valid_cdx(self):
        code, out, err = run("generate", self.tmp, "--no-local")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        names = {c["name"] for c in doc["components"]}
        self.assertEqual(names, {"left-pad", "ms"})
        # dependency relation present
        edges = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
        self.assertIn("npm:ms@2.1.3", edges["npm:left-pad@1.3.0"])

    def test_generate_to_file(self):
        out_path = os.path.join(self.tmp, "sbom.json")
        code, _, err = run("generate", self.tmp, "--no-local", "-o", out_path)
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isfile(out_path))

    def test_check_clean_exit_zero_with_allow_warnings(self):
        # ms has a hash; no integrity errors; licenses unknown -> warnings
        code, out, _ = run("check", self.tmp, "--no-local",
                           "--policy", self._policy("warn"),
                           "--allow-warnings")
        self.assertEqual(code, 0, out)

    def test_check_deny_unknown_fails_gate(self):
        code, out, _ = run("check", self.tmp, "--no-local",
                           "--policy", self._policy("deny"))
        self.assertEqual(code, 1)
        self.assertIn("LICENSE_UNKNOWN_DENIED", out)

    def _policy(self, action):
        path = os.path.join(self.tmp, "policy.json")
        write_json(path, {"policy_version": 1, "action_on_unknown": action,
                          "allow": ["MIT"]})
        return path

    def test_corrupt_policy_exit_2_no_success_report(self):
        bad = os.path.join(self.tmp, "bad.json")
        write(bad, "{ this is not json")
        code, out, err = run("check", self.tmp, "--no-local", "--policy", bad)
        self.assertEqual(code, 2)
        self.assertIn("policy error", err)
        self.assertNotIn("no issues found", out)

    def test_corrupt_lock_exit_2(self):
        write(os.path.join(self.tmp, "package-lock.json"), "not json at all")
        code, out, err = run("check", self.tmp, "--no-local")
        self.assertEqual(code, 2)
        self.assertIn("input error", err)

    def test_json_report_structure(self):
        code, out, _ = run("check", self.tmp, "--no-local", "--json",
                           "--policy", self._policy("allow"))
        self.assertIn(code, (0, 1))
        report = json.loads(out)
        self.assertIn("findings", report)
        self.assertEqual(report["component_count"], 2)

    def test_diff_cli_exit_codes(self):
        v1 = os.path.join(self.tmp, "s1.json")
        code, _, err = run("generate", self.tmp, "--no-local", "-o", v1)
        self.assertEqual(code, 0, err)
        # unchanged -> exit 0
        v2 = os.path.join(self.tmp, "s2.json")
        run("generate", self.tmp, "--no-local", "-o", v2)
        code, out, _ = run("diff", v1, v2)
        self.assertEqual(code, 0)
        self.assertIn("no differences", out)
        # changed -> exit 1
        write_json(os.path.join(self.tmp, "package-lock.json"), {
            "lockfileVersion": 3,
            "packages": {"node_modules/ms": {"version": "9.9.9",
                                             "integrity": "sha512-Tm0="}}})
        v3 = os.path.join(self.tmp, "s3.json")
        run("generate", self.tmp, "--no-local", "-o", v3)
        code, out, _ = run("diff", v1, v3)
        self.assertEqual(code, 1)
        self.assertIn("upgraded", out)

    def test_missing_project_dir_exit_2(self):
        code, _, err = run("generate", "/no/such/directory/anywhere", "--no-local")
        self.assertEqual(code, 2)
        self.assertIn("input error", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
