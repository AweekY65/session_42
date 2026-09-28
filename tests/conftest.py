"""Shared pytest fixtures: tiny on-disk projects for every parser."""

from __future__ import annotations

import base64
import json
import os

import pytest


def _integrity(seed: int, size: int = 64) -> str:
    """Deterministic, always-valid base64 integrity string."""

    digest = bytes((seed * 7 + i) % 256 for i in range(size))
    return "sha512-" + base64.b64encode(digest).decode()


def _write(path: str, content: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


@pytest.fixture()
def py_pinned_project(tmp_path):
    """requirements.txt fully pinned + hashed (acts as its own lock)."""

    root = tmp_path / "py-pinned"
    root.mkdir()
    _write(str(root / "requirements.txt"), """\
# pinned example
certifi==2024.2.2 --hash=sha256:aaaabbbbccccdddd
requests==2.31.0
""")
    return str(root)


@pytest.fixture()
def py_unpinned_project(tmp_path):
    root = tmp_path / "py-unpinned"
    root.mkdir()
    _write(str(root / "requirements.txt"), """\
flask>=2.0
requests
-r extra.txt
""")
    _write(str(root / "extra.txt"), "click==8.1.7\n")
    return str(root)


@pytest.fixture()
def py_poetry_project(tmp_path):
    root = tmp_path / "py-poetry"
    root.mkdir()
    _write(str(root / "pyproject.toml"), """\
[tool.poetry]
name = "poetry-app"
version = "1.0.0"
license = "MIT"

[tool.poetry.dependencies]
python = ">=3.10"
flask = "^3.0"
requests = "2.31.0"

[tool.poetry.group.dev.dependencies]
pytest = "7.4.4"
""")
    _write(str(root / "poetry.lock"), """\
# generated lock
[[package]]
name = "flask"
version = "3.0.3"
description = "web framework"
license = "BSD-3-Clause"

[package.dependencies]
werkzeug = ">=3.0.0"
jinja2 = ">=3.1.2"

[[package]]
name = "jinja2"
version = "3.1.4"
license = "BSD-3-Clause"

[package.dependencies]
markupsafe = ">=2.0"

[[package]]
name = "markupsafe"
version = "2.1.5"
license = "BSD-3-Clause"

[[package]]
name = "pytest"
version = "7.4.4"
license = "MIT"

[package.dependencies]
iniconfig = "*"

[[package]]
name = "iniconfig"
version = "2.0.0"
license = "MIT"

[[package]]
name = "requests"
version = "2.31.0"
license = "Apache-2.0"

[[package]]
name = "werkzeug"
version = "3.0.3"
license = "BSD-3-Clause"
""")
    return str(root)


@pytest.fixture()
def py_poetry_mismatch_project(tmp_path):
    """Manifest requests ^2.0 flask but lock resolves 3.x."""

    root = tmp_path / "py-poetry-mismatch"
    root.mkdir()
    _write(str(root / "pyproject.toml"), """\
[tool.poetry]
name = "mismatch-app"
version = "0.1.0"

[tool.poetry.dependencies]
python = ">=3.10"
flask = "^2.0.0"
""")
    _write(str(root / "poetry.lock"), """\
[[package]]
name = "flask"
version = "3.0.3"
license = "BSD-3-Clause"
""")
    return str(root)


@pytest.fixture()
def py_pipfile_project(tmp_path):
    root = tmp_path / "py-pipfile"
    root.mkdir()
    _write(str(root / "Pipfile"), """\
[packages]
requests = "==2.31.0"
flask = ">=2.0"

[dev-packages]
pytest = "*"
""")
    lock = {
        "_meta": {"hash": {"sha256": "deadbeef"}},
        "default": {
            "requests": {"version": "==2.31.0",
                         "hashes": ["sha256=abc123"]},
            "flask": {"version": "==3.0.3",
                      "hashes": ["sha256=def456"]},
        },
        "develop": {
            "pytest": {"version": "==7.4.4",
                       "hashes": ["sha256=999aaa"]},
        },
    }
    _write(str(root / "Pipfile.lock"), json.dumps(lock))
    return str(root)


@pytest.fixture()
def npm_v3_project(tmp_path):
    root = tmp_path / "npm-v3"
    root.mkdir()
    _write(str(root / "package.json"), json.dumps({
        "name": "npm-app", "version": "1.0.0", "license": "MIT",
        "dependencies": {"a": "^1.0.0", "b": "~2.1.0"},
        "devDependencies": {"c": "^3.0.0"},
    }))
    lock = {
        "name": "npm-app", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "npm-app", "version": "1.0.0",
                 "dependencies": {"a": "^1.0.0", "b": "~2.1.0"},
                 "devDependencies": {"c": "^3.0.0"}},
            "node_modules/a": {"version": "1.4.0",
                               "resolved": "https://example.invalid/a.tgz",
                               "integrity": _integrity(1),
                               "license": "MIT",
                               "requires": {"d": "^1.0.0"}},
            "node_modules/b": {"version": "2.1.3",
                               "resolved": "https://example.invalid/b.tgz",
                               "integrity": _integrity(2),
                               "license": "ISC"},
            "node_modules/c": {"version": "3.2.0",
                               "resolved": "https://example.invalid/c.tgz",
                               "integrity": _integrity(3),
                               "license": "MIT"},
            "node_modules/d": {"version": "1.0.1",
                               "resolved": "https://example.invalid/d.tgz",
                               "integrity": _integrity(4),
                               "license": "MIT"},
        },
    }
    _write(str(root / "package-lock.json"), json.dumps(lock))
    return str(root)


@pytest.fixture()
def npm_v1_project(tmp_path):
    root = tmp_path / "npm-v1"
    root.mkdir()
    _write(str(root / "package.json"), json.dumps({
        "name": "v1-app", "version": "0.0.1",
        "dependencies": {"left-pad": "^1.0.0"},
    }))
    lock = {
        "name": "v1-app", "version": "0.0.1", "lockfileVersion": 1,
        "requires": True,
        "dependencies": {
            "left-pad": {"version": "1.3.0",
                         "resolved": "https://example.invalid/lp.tgz",
                         "integrity": "sha1-MJIMmRIbkfDeAyqiMCqJvFvrYtU=",
                         "requires": {}},
        },
    }
    _write(str(root / "package-lock.json"), json.dumps(lock))
    return str(root)


@pytest.fixture()
def npm_dup_project(tmp_path):
    """Same dependency d at two nested versions (npm diamond)."""

    root = tmp_path / "npm-dup"
    root.mkdir()
    _write(str(root / "package.json"), json.dumps({
        "name": "dup-app", "version": "1.0.0",
        "dependencies": {"a": "^1.0.0", "b": "^1.0.0"},
    }))
    lock = {
        "name": "dup-app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}},
            "node_modules/a": {"version": "1.0.0",
                               "requires": {"d": "^1.0.0"}},
            "node_modules/b": {"version": "1.0.0",
                               "requires": {"d": "^2.0.0"}},
            "node_modules/d": {"version": "1.5.0"},
            "node_modules/b/node_modules/d": {"version": "2.0.0"},
        },
    }
    _write(str(root / "package-lock.json"), json.dumps(lock))
    return str(root)


@pytest.fixture()
def npm_missing_project(tmp_path):
    """package.json declares z but lock doesn't contain it."""

    root = tmp_path / "npm-missing"
    root.mkdir()
    _write(str(root / "package.json"), json.dumps({
        "name": "miss-app", "version": "1.0.0",
        "dependencies": {"present": "^1.0.0", "absent": "^1.0.0"},
    }))
    lock = {
        "name": "miss-app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"present": "^1.0.0",
                                  "absent": "^1.0.0"}},
            "node_modules/present": {"version": "1.2.0"},
        },
    }
    _write(str(root / "package-lock.json"), json.dumps(lock))
    return str(root)


@pytest.fixture()
def npm_yarn_project(tmp_path):
    root = tmp_path / "npm-yarn"
    root.mkdir()
    _write(str(root / "package.json"), json.dumps({
        "name": "yarn-app", "version": "2.0.0",
        "dependencies": {"left-pad": "^1.0.0", "chalk": "^4.0.0"},
    }))
    _write(str(root / "yarn.lock"), f"""\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT.

chalk@^4.0.0:
  version "4.1.2"
  resolved "https://example.invalid/chalk-4.1.2.tgz#1234"
  integrity {_integrity(10)}
  dependencies:
    supports-color "^7.0.0"

left-pad@^1.0.0:
  version "1.3.0"
  resolved "https://example.invalid/left-pad-1.3.0.tgz#5678"
  integrity {_integrity(11)}

supports-color@^7.0.0:
  version "7.2.0"
  resolved "https://example.invalid/supports-color-7.2.0.tgz#9012"
  integrity {_integrity(12)}
""")
    return str(root)
