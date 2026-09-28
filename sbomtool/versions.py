"""Version comparison and constraint satisfaction.

No network lookups are performed; the comparison is "good enough" for the
version strings found in Python and npm lock files.  When a specifier uses a
syntax we cannot interpret exactly, :func:`satisfies` returns ``None`` rather
than guessing, so integrity checks never raise a false version-mismatch.
"""

from __future__ import annotations

import re

from .models import Ecosystem

_SPLIT_RE = re.compile(r"[.\-_+]")
_PRE_TAGS = {"a", "b", "rc", "alpha", "beta", "pre", "dev", "snapshot", "m"}
_DIGIT_RE = re.compile(r"^[0-9]+$")


def _vtok(t: str):
    if _DIGIT_RE.match(t):
        return int(t)
    low = t.lower()
    if low in _PRE_TAGS:
        return low
    return t


def version_key(v: str):
    """Build a sortable key.

    Numeric segments sort as ints, prerelease segments before releases,
    non-numeric segments lexicographically; missing segments pad as 0 so
    ``1.2`` equals ``1.2.0``.
    """

    core = v.strip()
    pre: list = []
    m = re.match(r"^([0-9][0-9.]*)(.*)$", core)
    if m:
        core = m.group(1).rstrip(".")
        tail = m.group(2)
        if tail:
            pre = [_vtok(x) for x in _SPLIT_RE.split(tail.lstrip(".-_+")) if x]
    else:
        core = v
    toks = [_vtok(x) for x in core.split(".") if x != ""]
    rank = []
    for t in toks:
        rank.append((0, t) if isinstance(t, int) else (1, t))
    return (rank, pre)


def _cmp_key(v: str, length: int):
    rank, pre = version_key(v)
    rank = rank + [(0, 0)] * max(0, length - len(rank))
    # no prerelease sorts after any prerelease
    return (rank, 0 if pre else 1, pre)


def compare(a: str, b: str) -> int:
    """Return -1/0/1 for a<b / a==b / a>b, best effort."""

    n = max(len(_strip_pre(a).split(".")), len(_strip_pre(b).split(".")), 3)
    ka, kb = _cmp_key(a, n), _cmp_key(b, n)
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


def _strip_pre(v: str) -> str:
    m = re.match(r"^[0-9.]+", v.strip())
    return m.group(0) if m else v


# ---------------------------------------------------------------- specifiers

_OP_RE = re.compile(r"^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$")
_COMPOUND_SPLIT_RE = re.compile(r"\s*,\s*")


def _numeric_parts(v: str) -> list[int] | None:
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v.strip())
    if not m:
        return None
    return [int(x) if x is not None else 0 for x in m.groups()]


def _bump(parts: list[int], idx: int) -> str:
    """Increment ``parts[idx]`` and zero every segment after it."""

    p = list(parts)
    while len(p) <= idx:
        p.append(0)
    p[idx] += 1
    for j in range(idx + 1, len(p)):
        p[j] = 0
    return ".".join(str(x) for x in p)


def _caret_bounds(spec: str) -> tuple[str, str] | None:
    """npm ``^a.b.c`` upper bound (exclusive)."""

    v = spec[1:]
    parts = _numeric_parts(v)
    if parts is None:
        return None
    if parts[0] > 0:
        upper = _bump(parts, 0)
    elif parts[1] and parts[1] > 0:
        upper = _bump(parts, 1)
    elif parts[2] and parts[2] > 0:
        upper = _bump(parts, 2)
    else:  # ^0.0.x / ^0.0.0: exact
        upper = None
    base = ".".join(str(x) for x in parts[:3])
    return base, upper if upper else base + "-zzz-excl"


def _tilde_bounds(spec: str) -> tuple[str, str] | None:
    """npm ``~a.b.c`` allows patch changes; ``~a`` allows minor changes."""

    v = spec[1:]
    raw_parts = [p for p in re.split(r"[.]", v) if p != ""]
    parts = _numeric_parts(v)
    if parts is None:
        return None
    # ~1.2.3 and ~1.2 lock the minor (allow patch); ~1 locks the major.
    idx = min(len(raw_parts) - 1, 1)
    upper = _bump(parts, idx)
    return ".".join(str(x) for x in parts[:3]), upper


def _single_satisfies(version: str, spec: str, ecosystem: Ecosystem) -> bool | None:
    spec = spec.strip()
    if not spec:
        return True
    if spec in ("*", "latest", "x", "X"):
        return True

    # npm operators
    if spec.startswith("^"):
        bounds = _caret_bounds(spec)
        if bounds is None:
            return None
        low, high = bounds
        if compare(version, low) < 0 or compare(version, high) >= 0:
            return False
        return True
    if spec.startswith("~") and not spec.startswith("~="):
        bounds = _tilde_bounds(spec)
        if bounds is None:
            return None
        low, high = bounds
        if compare(version, low) < 0 or compare(version, high) >= 0:
            return False
        return True

    m = _OP_RE.match(spec)
    if m:
        op, target = m.group(1), m.group(2).strip()
        if op == "===" or op == "==":
            if "*" in target or "x" in target.lower():
                return _prefix_match(version, target)
            return compare(version, target) == 0
        if op == "!=":
            if "*" in target or "x" in target.lower():
                return not _prefix_match(version, target)
            return compare(version, target) != 0
        c = compare(version, target)
        if op == ">=":
            return c >= 0
        if op == "<=":
            return c <= 0
        if op == ">":
            return c > 0
        if op == "<":
            return c < 0
        if op == "~=":  # compatible release: >=v, next-to-last segment fixed
            segs = [s for s in target.split(".") if s]
            if len(segs) < 2:
                return None
            upper = _bump([int(s) if _DIGIT_RE.match(s) else 0 for s in segs] + [0], len(segs) - 2)
            return c >= 0 and compare(version, upper) < 0
        return None

    # "1.x" / "1.2.x" style
    if "x" in spec.lower() or spec.endswith(".*"):
        return _prefix_match(version, spec)

    # hyphen range "1.2.0 - 2.0.0" is handled by caller split on " - "
    # Bare version: exact for npm-like; Python bare requirement means ==
    if _numeric_parts(spec) is not None:
        return compare(version, spec) == 0
    return None


def _prefix_match(version: str, pattern: str) -> bool:
    p = pattern.lstrip("v=").rstrip(".*").split(".")
    p = [seg for seg in p if seg.lower() != "x" and seg != "*"]
    got = _SPLIT_RE.split(version)
    if len(got) < len(p):
        return False
    for a, b in zip(got, p):
        if a != b:
            return False
    return True


def satisfies(version: str, constraint: str | None, ecosystem: Ecosystem) -> bool | None:
    """Check a locked version against a declaration constraint.

    Returns ``None`` when the constraint cannot be interpreted with
    confidence; callers should treat that as "no verdict", never a failure.
    """

    if not constraint or constraint.strip() in ("", "*"):
        return True
    spec = constraint.strip()
    # strip extras/markers already removed by caller, but be defensive
    spec = spec.split(";", 1)[0].strip()
    parts = re.split(_COMPOUND_SPLIT_RE, spec)
    for part in parts:
        part = part.strip()
        if " - " in part:
            lo, hi = [x.strip() for x in part.split(" - ", 1)]
            if _numeric_parts(lo) is None or _numeric_parts(hi) is None:
                return None
            if not (compare(version, lo) >= 0 and compare(version, hi) <= 0):
                return False
            continue
        ok = _single_satisfies(version, part, ecosystem)
        if ok is False:
            return False
        if ok is None:
            return None
    return True
