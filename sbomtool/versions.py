"""Offline version parsing and constraint matching.

Two ecosystems, two dialects:

* Python — a pragmatic subset of PEP 440 / PEP 508 version specifiers.
* npm    — a pragmatic subset of semantic-version range syntax.

Only comparison primitives from the standard library are used; nothing is
downloaded.
"""

from __future__ import annotations

import re
from typing import Optional

from .errors import ParseError


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_PYTHON_VER = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:(?P<pre_l>a|b|rc|alpha|beta|c|preview)[.\-]?(?P<pre_n>\d*))?"
    r"(?:[.\-]?(?P<post>post)[.\-]?(?P<post_n>\d*))?"
    r"(?:[.\-]?(?P<dev>dev)[.\-]?(?P<dev_n>\d*))?"
    r"(?:\+(?P<local>[0-9a-zA-Z.]+))?$",
    re.IGNORECASE,
)

_PRE_LABELS = {"a": "a", "alpha": "a", "b": "b", "beta": "b",
               "c": "rc", "rc": "rc", "preview": "rc"}


def parse_python_version(version: str) -> Optional[tuple]:
    """Parse a Python package version into a comparable tuple.

    Returns ``None`` when the string is not recognisable as a version.
    """

    if version is None:
        return None
    text = version.strip()
    m = _PYTHON_VER.match(text)
    if not m:
        return None
    release = tuple(int(x) for x in m.group("release").split("."))
    pre_l = m.group("pre_l")
    if pre_l:
        pre = (_PRE_LABELS[pre_l.lower()], int(m.group("pre_n") or 0))
    elif m.group("dev"):
        # "1.0.dev1" sorts before "1.0"
        pre = ("z", int(m.group("dev_n") or 0))
    else:
        pre = None
    post = int(m.group("post_n") or 0) if m.group("post") else None
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None
    # Comparison tuple semantics (PEP 440 style):
    #   release, pre-priority (release-version beats pre-release),
    #   pre tuple, post, dev
    if pre is None:
        pre_cmp = (1,)       # final > prerelease
        pre_tup = (0, 0)
    elif pre[0] == "z":
        pre_cmp = (0,)
        pre_tup = (ord("z"), pre[1])
    else:
        pre_cmp = (0,)
        pre_tup = (ord(pre[0]), pre[1])
    post_cmp = post if post is not None else -1
    dev_cmp = dev if dev is not None else 1 << 30  # non-dev > dev
    return release, pre_cmp, pre_tup, post_cmp, dev_cmp


_NPM_VER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.\-]+))?(?:\+([0-9A-Za-z.\-]+))?$"
)


def parse_npm_version(version: str) -> Optional[tuple]:
    """Parse a strict ``major.minor.patch`` semver string (or None)."""

    if version is None:
        return None
    m = _NPM_VER.match(version.strip())
    if not m:
        return None
    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    pre = m.group(4)
    # prerelease sorts below an empty prerelease; compare by dot identifiers
    if pre is None:
        pre_key: tuple = (1,)
    else:
        parts: list = []
        for ident in pre.split("."):
            if ident.isdigit():
                parts.append((0, int(ident), ""))
            else:
                parts.append((1, 0, ident))
        pre_key = (0, tuple(parts))
    return (major, minor, patch), pre_key


# ---------------------------------------------------------------------------
# Generic comparison used by SBOM diff
# ---------------------------------------------------------------------------

def compare_versions(a: Optional[str], b: Optional[str],
                     ecosystem: str = "python") -> int:
    """Return -1/0/1 for a<b / a==b / a>b; falls back to string compare."""

    parser = parse_python_version if ecosystem == "python" else parse_npm_version
    ta, tb = parser(a) if a else None, parser(b) if b else None
    if ta is not None and tb is not None:
        return (ta > tb) - (ta < tb)
    sa, sb = a or "", b or ""
    return (sa > sb) - (sa < sb)


def is_version(v: Optional[str], ecosystem: str) -> bool:
    if not v:
        return False
    parser = parse_python_version if ecosystem == "python" else parse_npm_version
    return parser(v) is not None


# ---------------------------------------------------------------------------
# Python constraint matching (PEP 508 subset)
# ---------------------------------------------------------------------------

_PY_OPS = ("===", "==", "!=", "~=", ">=", "<=", ">", "<")


def python_spec_matches(spec: str, version: str) -> bool:
    """Evaluate a comma-separated PEP 508 specifier set against a version.

    Supported operators: ``==`` (incl. ``.*`` prefix), ``!=``, ``>=``,
    ``<=``, ``>``, ``<``, ``~=``, ``===``.  Unparseable constraints or
    versions return ``False`` (the caller treats that as "cannot verify").
    """

    target = parse_python_version(version)
    if target is None or not spec or not spec.strip():
        return False
    for clause in _split_top_level(spec, ","):
        clause = clause.strip()
        if not clause:
            continue
        op = next((o for o in _PY_OPS if clause.startswith(o)), None)
        if op is None:
            return False
        raw_ver = clause[len(op):].strip()
        prefix = raw_ver.endswith(".*")
        if prefix:
            raw_ver = raw_ver[:-2].rstrip(".")
        want = parse_python_version(raw_ver)
        if want is None:
            return False
        rel = _cmp_release_prefix(target, want, prefix)
        if op in ("==", "==="):
            if prefix:
                if rel != 0:
                    return False
            elif _has_pre_post_dev(want):
                if target != want:
                    return False
            else:
                # ==2.0 matches 2.0.0/2.0.1? No — PEP 440: ==2.0 matches
                # release 2.0.0 exactly (release padding) but never pre/post.
                if target[0][: len(want[0])] != want[0] or _has_pre_post_dev(target):
                    return False
                if target[0][len(want[0]):] and any(
                        x != 0 for x in target[0][len(want[0]):]):
                    return False
        elif op == "!=":
            if prefix:
                if rel == 0:
                    return False
            elif _has_pre_post_dev(want):
                if target == want:
                    return False
            else:
                if target[0][: len(want[0])] == want[0] \
                        and not _has_pre_post_dev(target) \
                        and not any(x != 0 for x in
                                    target[0][len(want[0]):]):
                    return False
        elif op == ">=":
            if _python_cmp(target, want) < 0:
                return False
        elif op == "<=":
            if _python_cmp(target, want) > 0:
                return False
        elif op == ">":
            if _python_cmp(target, want) <= 0:
                return False
        elif op == "<":
            if _python_cmp(target, want) >= 0:
                return False
        elif op == "~=":
            # ~=X.Y means >=X.Y, ==X.* ; ~=X.Y.Z means >=X.Y.Z, ==X.Y.*
            want_release = want[0]
            if len(want_release) < 2:
                raise ParseError(f"invalid ~= specifier: {spec}")
            if _python_cmp(target, want) < 0:
                return False
            floor_release = want_release[:-1]
            tgt_release = target[0]
            if tgt_release[: len(floor_release)] != floor_release:
                return False
    return True


def _split_top_level(text: str, separator: str) -> list[str]:
    return [part for part in text.split(separator)]


def _has_pre_post_dev(parsed: tuple) -> bool:
    _, pre_cmp, _, post_cmp, _ = parsed
    return pre_cmp == (0,) or post_cmp >= 0


def _cmp_release_prefix(target: tuple, want: tuple, prefix: bool) -> int:
    tr = target[0]
    wr = want[0]
    if prefix:
        n = len(wr)
        a, b = tr[:n], wr
        return (a > b) - (a < b)
    return (target > want) - (target < want)


def _python_cmp(target: tuple, want: tuple) -> int:
    """PEP 440 style comparison with release-segment zero-padding."""

    tr, wr = target[0], want[0]
    n = max(len(tr), len(wr))
    a = tr + (0,) * (n - len(tr))
    b = wr + (0,) * (n - len(wr))
    if a != b:
        return (a > b) - (a < b)
    # equal release series: compare full tuples for pre/post/dev ordering
    return (target > want) - (target < want)


# ---------------------------------------------------------------------------
# npm semver range matching
# ---------------------------------------------------------------------------

def npm_spec_matches(spec: str, version: str) -> bool:
    """Evaluate an npm semver range against a concrete ``x.y.z`` version.

    Supported: exact versions, ``*``/``x`` wildcards, ``^``/``~`` ranges,
    comparison operators, ``||`` unions, hyphen ranges, space-intersected
    comparator sets, and ``tag``-like non-ranges (those return False — they
    cannot be verified offline).
    """

    parsed = parse_npm_version(version)
    if parsed is None or not spec or not spec.strip():
        return False
    target, _ = parsed

    for alternative in spec.split("||"):
        if _npm_and_set_matches(alternative.strip(), target):
            return True
    return False


def _npm_and_set_matches(text: str, target: tuple) -> bool:
    text = text.strip()
    if not text:
        return False
    # "1.2.3 - 2.3.4" hyphen range
    hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", text)
    if hyphen:
        lo = _partial_bound(hyphen.group(1), lower=True)
        hi = _partial_bound(hyphen.group(2), lower=False)
        if lo is None or hi is None:
            return False
        return lo <= target <= hi

    tokens = text.split()
    if len(tokens) == 1 and tokens[0].lower() in ("", "x", "*", "latest"):
        if tokens[0].lower() == "latest":
            return False
        return True
    for token in tokens:
        if not _npm_comparator_matches(token, target):
            return False
    return True


def _npm_comparator_matches(token: str, target: tuple) -> bool:
    token = token.strip()
    if token in ("*", "x", "X", ""):
        return True
    m = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*v?(.+)$", token)
    if not m:
        return False
    op = m.group(1) or "="
    rest = m.group(2).strip()

    parsed = _parse_partial(rest)
    if parsed is None:
        return False
    # (major, minor|None, patch|None)
    major, minor, patch = parsed

    if op in ("=", "^", "~"):
        low = (major, minor or 0, patch or 0)
        if op == "^":
            if major > 0:
                high = (major + 1, 0, 0)
            elif minor not in (None, 0):
                high = (0, (minor or 0) + 1, 0)
            else:
                high = (0, 0, (patch or 0) + 1)
        elif op == "~":
            if minor is None:
                high = (major + 1, 0, 0)
            else:
                high = (major, minor + 1, 0)
        else:  # plain "1.2.x" style
            if minor is None:
                high = (major + 1, 0, 0)
            elif patch is None:
                high = (major, minor + 1, 0)
            else:
                return target == (major, minor, patch)
        return low <= target < high

    low = (major, minor or 0, patch or 0)
    if op == ">=":
        return target >= low
    if op == "<":
        return target < low
    if op == ">":
        # ">1.2.3" -> tuple greater; ">1.2" -> >=1.3.0; ">1" -> >=2.0.0
        if patch is not None:
            return target > (major, minor or 0, patch)
        if minor is not None:
            return target >= (major, minor + 1, 0)
        return target >= (major + 1, 0, 0)
    if op == "<=":
        if patch is not None:
            return target <= (major, minor or 0, patch)
        if minor is not None:
            return target < (major, minor + 1, 0)
        return target < (major + 1, 0, 0)
    return False


def _parse_partial(rest: str):
    """Return (major, minor|None, patch|None); wildcard digits become None."""

    m = re.match(r"^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-.+)?$",
                 rest, re.IGNORECASE)
    if not m:
        return None
    major = int(m.group(1))
    minor_s, patch_s = m.group(2), m.group(3)
    minor = None if minor_s is None or minor_s.lower() in ("x", "*") \
        else int(minor_s)
    patch = None if patch_s is None or patch_s.lower() in ("x", "*") \
        else int(patch_s)
    return major, minor, patch


def _partial_bound(token: str, lower: bool):
    parsed = _parse_partial(token.lstrip("v"))
    if parsed is None:
        return None
    major, minor, patch = parsed
    if lower:
        return (major, minor or 0, patch or 0)
    # Inclusive upper bound of a hyphen range.
    if patch is not None:
        return (major, minor or 0, patch)
    big = 1 << 30
    if minor is not None:
        return (major, minor, big)
    return (major, big, big)
