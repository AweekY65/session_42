"""Minimal offline PEP 508 requirement / marker parsing.

Only the pieces needed to read local manifests are implemented; anything
that cannot be parsed raises :class:`ParseError`.
"""

from __future__ import annotations

import re
import sys

from .errors import ParseError

_IDENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_RE_REQ = re.compile(
    rf"^(?P<name>{_IDENT})(?:\[(?P<extras>[^\]]+)\])?(?P<rest>.*)$"
)
_RE_URL_NAME = re.compile(r"egg=(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
                          r"(?:-(?P<ver>[0-9][^&]*))?$")


def parse_requirement(line: str) -> dict:
    """Parse a single PEP 508 requirement string.

    Returns a dict with keys: name, extras (list), spec (version clauses),
    markers (str|None), url (str|None).
    """

    text = line.strip()
    # Direct references: name @ url
    m = _RE_REQ.match(text)
    if not m:
        raise ParseError(f"invalid requirement: {line!r}")
    name = m.group("name")
    extras = [e.strip() for e in m.group("extras").split(",")] \
        if m.group("extras") else []
    rest = m.group("rest").strip()
    markers = None
    url = None
    spec = ""
    if rest:
        if rest.startswith("@"):
            tail = rest[1:].strip()
            if ";" in tail:
                url_part, marker_part = tail.split(";", 1)
                url = url_part.strip()
                markers = marker_part.strip()
            else:
                url = tail
        else:
            if ";" in rest:
                spec_part, marker_part = rest.split(";", 1)
                spec = spec_part.strip()
                markers = marker_part.strip()
            else:
                spec = rest
    return {"name": name, "extras": extras, "spec": spec,
            "markers": markers, "url": url}


def parse_url_requirement(url: str, default_name: str | None = None) -> dict:
    """Extract name/version from an archive URL or direct VCS URL."""

    result = {"name": default_name, "version": None, "source_type": "url"}
    lower = url.lower()
    is_vcs = lower.startswith(("git+", "hg+", "svn+", "bzr+")) or \
        ("://" in lower and lower.split("://", 1)[1].startswith(
            ("git", "hg", "svn", "bzr")))
    if is_vcs:
        result["source_type"] = "vcs"
        egg = _url_query_field(url, "egg")
        if egg:
            result["name"], result["version"] = _split_egg(egg)
        rev = _url_query_field(url, "rev") or _url_query_field(url, "tag") \
            or _url_query_field(url, "ref")
        if rev:
            result["version"] = rev
        else:
            result["version"] = _vcs_revision(url)
        return result
    if lower.startswith(("file://", "/", "./", "../", "~/")):
        result["source_type"] = "file"
    egg = _url_query_field(url, "egg")
    if egg:
        result["name"], result["version"] = _split_egg(egg)
    if not result["version"]:
        # strip archive suffix and take trailing component
        tail = url.split("/")[-1].split("#", 1)[0]
        for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".whl",
                       ".tgz", ".tar"):
            if tail.lower().endswith(suffix):
                stem = tail[: -len(suffix)]
                parts = stem.split("-")
                if len(parts) >= 2 and re.match(r"^\d", parts[1]):
                    result["name"] = result["name"] or parts[0]
                    result["version"] = parts[1]
                break
    return result


def _vcs_revision(url: str) -> str | None:
    """Extract ``@<rev>`` from the path part of a VCS URL (before #egg)."""

    path = url.split("#", 1)[0]
    # strip any vcs+ scheme prefix
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        if path.lower().startswith(prefix):
            path = path[len(prefix):]
            break
    # only split on @ that follows the host portion (after ://)
    if "://" in path:
        _, path_tail = path.split("://", 1)
        # find @ after the first /
        slash = path_tail.find("/")
        candidate = path_tail[slash:] if slash >= 0 else ""
    else:
        candidate = path
    if "@" in candidate:
        return candidate.rsplit("@", 1)[-1] or None
    return None


def _url_query_field(url: str, field: str) -> str | None:
    if "#" not in url:
        return None
    query = url.split("#", 1)[1]
    for item in query.split("&"):
        if "=" in item:
            k, v = item.split("=", 1)
            if k == field:
                return v
    return None


def _split_egg(egg: str) -> tuple[str, str | None]:
    parts = egg.rsplit("-", 1)
    if len(parts) == 2 and re.match(r"^\d", parts[1]):
        return parts[0], parts[1]
    return egg, None


# ---------------------------------------------------------------------------
# Environment markers (PEP 508 subset)
# ---------------------------------------------------------------------------

_MARKER_OPS = ("==", "!=", ">=", "<=", ">", "<", "~=", "in", "not in")

#: Conservative default marker environment (offline; current interpreter).
DEFAULT_ENV = {
    "os_name": "posix",
    "sys_platform": sys.platform,
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_system": {"linux": "Linux", "darwin": "Darwin",
                        "win32": "Windows"}.get(sys.platform, ""),
    "python_version": "%d.%d" % sys.version_info[:2],
    "python_full_version": "%d.%d.%d" % sys.version_info[:3],
    "implementation_name": "cpython",
    "extra": "",
}


def evaluate_marker(marker: str | None, env: dict | None = None) -> bool:
    """Evaluate a marker expression. Returns True when marker is satisfied."""

    if not marker:
        return True
    env = dict(DEFAULT_ENV)
    if env:
        env.update(env)
    try:
        ors = marker.split(" or ")
        for or_clause in ors:
            ands = or_clause.split(" and ")
            if all(_eval_comparison(part.strip(), env) for part in ands):
                return True
        return False
    except ParseError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ParseError(f"invalid environment marker: {marker!r}") from exc


def _eval_comparison(expr: str, env: dict) -> bool:
    op = next((o for o in _MARKER_OPS if f" {o} " in expr), None)
    if op is None:
        raise ParseError(f"unsupported marker expression: {expr!r}")
    left, right = expr.split(f" {op} ", 1)
    lv = _marker_value(left.strip(), env)
    rv = _marker_value(right.strip(), env)
    if op == "==":
        return lv == rv
    if op == "!=":
        return lv != rv
    if op == ">=":
        return _cmp_str(lv, rv) >= 0
    if op == "<=":
        return _cmp_str(lv, rv) <= 0
    if op == ">":
        return _cmp_str(lv, rv) > 0
    if op == "<":
        return _cmp_str(lv, rv) < 0
    if op == "~=":
        return rv == lv or lv.startswith(rv + ".")
    if op == "in":
        return str(lv) in str(rv)
    if op == "not in":
        return str(lv) not in str(rv)
    raise ParseError(f"unsupported marker operator: {op}")


def _marker_value(token: str, env: dict):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    if token in env:
        return str(env[token])
    raise ParseError(f"unknown marker variable: {token!r}")


def _cmp_str(a: str, b: str) -> int:
    if a.replace(".", "").isdigit() and b.replace(".", "").isdigit():
        ta = tuple(int(x) for x in a.split("."))
        tb = tuple(int(x) for x in b.split("."))
        n = max(len(ta), len(tb))
        ta += (0,) * (n - len(ta))
        tb += (0,) * (n - len(tb))
        return (ta > tb) - (ta < tb)
    return (a > b) - (a < b)
