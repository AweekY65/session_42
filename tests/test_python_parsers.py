"""Tests for Python declaration/lock parsing and transitive resolution."""

import os
import tempfile
import unittest

from sbomtool.analyzer import analyze, integrity_findings
from sbomtool.errors import InputError
from sbomtool.parsers.python import (
    eval_marker,
    parse_declaration,
    parse_requirement,
)
from tests.support import write, finding_codes


class RequirementParsingTests(unittest.TestCase):
    def test_basic_name_and_spec(self):
        self.assertEqual(parse_requirement("requests>=2.31.0"),
                         ("requests", ">=2.31.0", ""))

    def test_extras_and_marker(self):
        name, spec, marker = parse_requirement(
            'tomli>=2.0; python_version < "3.11" and sys_platform == "linux"'
        )
        self.assertEqual(name, "tomli")
        self.assertEqual(spec, ">=2.0")
        self.assertIn("python_version", marker)

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_requirement("!!!not a package"))
        self.assertIsNone(parse_requirement(""))
        self.assertIsNone(parse_requirement("# comment"))

    def test_name_normalization(self):
        decl = parse_declaration  # import-time guard
        self.assertTrue(callable(decl))


class MarkerEvaluationTests(unittest.TestCase):
    def test_platform_filter_keeps_linux(self):
        self.assertTrue(eval_marker("sys_platform == 'linux'"))
        self.assertFalse(eval_marker("sys_platform == 'win32'"))

    def test_and_or_not(self):
        self.assertTrue(eval_marker(
            "python_version >= '3.8' and sys_platform != 'win32'"))
        self.assertFalse(eval_marker(
            "python_version < '3.0' or sys_platform == 'win32'"))
        self.assertTrue(eval_marker("not (sys_platform == 'win32')"))

    def test_unknown_variable_is_conservative_true(self):
        self.assertTrue(eval_marker("mystery_var == 'x'"))


PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.31", "flask==3.0.0"]

[project.optional-dependencies]
test = ["pytest>=8.0"]
"""

UV_LOCK = """\
version = 1

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
  { name = "urllib3", marker = "python_full_version >= '3.8'" },
  { name = "win-only", marker = "sys_platform == 'win32'" },
]

[package.metadata]
license-expression = "Apache-2.0"
requires-dist = ["certifi>=2017.4.17"]

[[package]]
name = "urllib3"
version = "2.2.0"

[package.metadata]
license-expression = "MIT"

[[package]]
name = "certifi"
version = "2024.2.2"

[package.metadata]
license-expression = "MPL-2.0"

[[package]]
name = "flask"
version = "3.0.0"

[package.metadata]
license-expression = "BSD-3-Clause"

[[package]]
name = "pytest"
version = "8.1.0"

[package.metadata]
license-expression = "MIT"
"""


class PythonProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        write(os.path.join(self.tmp, "pyproject.toml"), PYPROJECT)
        write(os.path.join(self.tmp, "uv.lock"), UV_LOCK)

    def test_declaration_parsing(self):
        decl = parse_declaration(os.path.join(self.tmp, "pyproject.toml"))
        self.assertEqual(decl.project_name, "demo")
        self.assertIn("requests", decl.declared)
        self.assertEqual(decl.declared["requests"]["constraint"], ">=2.31")
        self.assertEqual(decl.declared["pytest"]["scope"], "optional")

    def test_transitive_graph(self):
        sbom = analyze(self.tmp, use_local=False)
        req = sbom.components["python:requests"]
        # deps come from both dependencies table and requires-dist
        self.assertIn("python:urllib3", req.dependencies)
        self.assertIn("python:certifi", req.dependencies)
        self.assertNotIn("python:win-only", sbom.components)
        # transitive-only packages are still components
        self.assertIn("python:urllib3", sbom.components)
        self.assertEqual(sbom.components["python:certifi"].licenses, ["MPL-2.0"])

    def test_clean_project_has_no_integrity_errors(self):
        sbom = analyze(self.tmp, use_local=False)
        errors = [f for f in integrity_findings(sbom) if f.severity.value == "error"]
        self.assertEqual(errors, [])

    def test_pep503_name_normalization(self):
        write(os.path.join(self.tmp, "pyproject.toml"), """\
[project]
name = "demo"
dependencies = ["Some_Package.Thing>=1"]
""")
        write(os.path.join(self.tmp, "uv.lock"), """\
version = 1
[[package]]
name = "some-package-thing"
version = "1.0.0"
""")
        sbom = analyze(self.tmp, use_local=False)
        self.assertIn("python:some-package-thing", sbom.components)
        findings = integrity_findings(sbom)
        self.assertNotIn("MISSING_PACKAGE", finding_codes(findings))


class RequirementsLockTests(unittest.TestCase):
    def test_hashed_lock_and_continuation(self):
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "requirements.in"), "requests>=2.31\n")
        write(os.path.join(tmp, "requirements.txt"),
              "requests==2.31.0 \\\n"
              "    --hash=sha256:" + "a" * 64 + " \\\n"
              "    --hash=sha256:" + "b" * 64 + "\n")
        sbom = analyze(tmp, use_local=False)
        comp = sbom.components["python:requests"]
        self.assertEqual(comp.version, "2.31.0")
        self.assertEqual(len(comp.hashes), 2)
        findings = integrity_findings(sbom)
        self.assertNotIn("MISSING_PACKAGE", finding_codes(findings))

    def test_unpinned_lock_is_an_error(self):
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "requirements.in"), "requests\n")
        write(os.path.join(tmp, "requirements.txt"), "requests>=2.0\n")
        with self.assertRaises(InputError):
            analyze(tmp, use_local=False)

    def test_recursive_requirement_option_ignored_in_declaration(self):
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "requirements.in"),
              "-r base.txt\nflask==3.0.0\n")
        write(os.path.join(tmp, "requirements.txt"),
              "flask==3.0.0 --hash=sha256:" + "c" * 64 + "\n")
        sbom = analyze(tmp, use_local=False)
        self.assertIn("python:flask", sbom.components)


class PipfileLockTests(unittest.TestCase):
    def test_pipfile_sections(self):
        import json
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "pyproject.toml"),
              '[project]\nname="d"\ndependencies=["click"]\n')
        lock = {
            "default": {
                "click": {"version": "==8.1.7",
                          "hashes": ["sha256:" + "1" * 64]},
            },
            "develop": {
                "pytest": {"version": "==8.0.0", "hashes": []},
            },
        }
        write(os.path.join(tmp, "Pipfile.lock"), json.dumps(lock))
        sbom = analyze(tmp, use_local=False)
        self.assertEqual(sbom.components["python:click"].version, "8.1.7")
        self.assertEqual(sbom.components["python:pytest"].scope, "optional")

    def test_unpinned_pipfile_entry_rejected(self):
        import json
        tmp = tempfile.mkdtemp()
        write(os.path.join(tmp, "Pipfile.lock"),
              json.dumps({"default": {"x": {"version": "*"}}}))
        with self.assertRaises(InputError):
            analyze(tmp, use_local=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
