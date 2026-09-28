"""End-to-end CLI tests: generate / validate / diff exit codes and files."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(*args):
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    proc = subprocess.run(
        [sys.executable, "-m", "sbomtool", *args],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT)
    return proc.returncode, proc.stdout, proc.stderr


POLICY = json.dumps({
    "version": 1, "policy": "allowlist",
    "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
    "deny": ["WTFPL"], "onUnknown": "error",
})


def test_generate_writes_sbom_and_report(py_poetry_project, tmp_path):
    sbom = tmp_path / "sbom.json"
    report = tmp_path / "report.json"
    policy = tmp_path / "policy.json"
    policy.write_text(POLICY)
    code, out, err = run_cli(
        "generate", py_poetry_project,
        "--sbom", str(sbom), "--report", str(report),
        "--policy", str(policy))
    assert code == 0, err
    assert sbom.exists() and report.exists()
    doc = json.loads(sbom.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    rep = json.loads(report.read_text())
    assert rep["status"] in ("pass", "warn")
    assert "integrityIssues" in rep


def test_generate_fails_exit1_on_policy_violation(npm_v3_project, tmp_path):
    # npm fixture packages are MIT/ISC -> passes; craft denial instead
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "policy": "allowlist", "allow": ["MIT"],
        "deny": [], "onUnknown": "error"}))
    sbom = tmp_path / "sbom.json"
    code, _, err = run_cli("generate", npm_v3_project,
                           "--sbom", str(sbom), "--policy", str(policy))
    assert code == 1
    # SBOM is still produced even when policy fails (evidence), but exit
    # code communicates failure
    assert sbom.exists()


def test_generate_corrupt_manifest_exit2(tmp_path):
    (tmp_path / "package.json").write_text("{ broken")
    code, _, err = run_cli("generate", str(tmp_path),
                           "--sbom", str(tmp_path / "o.json"))
    assert code == 2
    assert "invalid JSON" in err
    assert not (tmp_path / "o.json").exists()


def test_generate_corrupt_policy_exit2(npm_v3_project, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"policy": "allowlist", "allow": []}')
    code, _, err = run_cli("generate", npm_v3_project,
                           "--sbom", str(tmp_path / "o.json"),
                           "--policy", str(policy))
    assert code == 2
    assert "at least one allowed" in err


def test_validate_requires_policy(npm_v3_project):
    code, _, err = run_cli("validate", npm_v3_project)
    assert code == 2
    assert "--policy" in err


def test_validate_detects_sbom_drift(npm_v3_project, tmp_path):
    sbom = tmp_path / "sbom.json"
    run_cli("generate", npm_v3_project, "--sbom", str(sbom))
    # tamper with the stored SBOM: remove a component
    doc = json.loads(sbom.read_text())
    doc["components"] = [c for c in doc["components"]
                         if c.get("name") != "d"]
    sbom.write_text(json.dumps(doc))
    policy = tmp_path / "policy.json"
    policy.write_text(POLICY)
    report = tmp_path / "r.json"
    code, out, err = run_cli(
        "validate", npm_v3_project, "--sbom", str(sbom),
        "--policy", str(policy), "--report", str(report))
    assert code == 1
    rep = json.loads(report.read_text())
    codes = {i["code"] for i in rep["integrityIssues"]}
    assert "SBOM_DRIFT" in codes


def test_diff_cli_exit_codes(npm_v3_project, tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    run_cli("generate", npm_v3_project, "--sbom", str(a))
    run_cli("generate", npm_v3_project, "--sbom", str(b))
    code, out, _ = run_cli("diff", str(a), str(b))
    assert code == 0
    summary = json.loads(out)["summary"]
    assert summary["unchanged"] >= 4

    # change b -> non-empty diff, exit 1
    doc = json.loads(b.read_text())
    for c in doc["components"]:
        if c.get("name") == "a":
            c["version"] = "1.9.9"
            c["bom-ref"] = "pkg:npm/a@1.9.9"
            c["purl"] = "pkg:npm/a@1.9.9"
    b.write_text(json.dumps(doc))
    code, _, _ = run_cli("diff", str(a), str(b))
    assert code == 1


def test_diff_corrupt_sbom_exit2(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text("not json")
    b.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    code, _, err = run_cli("diff", str(a), str(b))
    assert code == 2
    assert "invalid JSON" in err


def test_generate_nonexistent_directory_exit2(tmp_path):
    code, _, err = run_cli(
        "generate", str(tmp_path / "missing"),
        "--sbom", str(tmp_path / "o.json"))
    assert code == 2
    assert "not found" in err
