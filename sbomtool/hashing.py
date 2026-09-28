"""Local content hashing helpers.

All hashes are computed over bytes that already exist on the local machine —
nothing is downloaded.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

#: Hash names found in lock files -> canonical CycloneDX algorithm name.
ALGORITHM_ALIASES = {
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha1": "SHA-1",
    "md5": "MD5",
}


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def hash_file(path: str, algorithm: str = "sha256",
              bufsize: int = 1024 * 1024) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(bufsize)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_directory(path: str, algorithm: str = "sha256") -> str:
    """Stable hash of a directory tree.

    Files are visited in sorted relative-path order; both the relative path
    (UTF-8) and the file content are fed into the digest, so renames and
    content edits both change the result while mtime/permission changes do
    not.
    """

    h = hashlib.new(algorithm)
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            with open(full, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            h.update(b"\0")
    return h.hexdigest()


def hash_path(path: str, algorithm: str = "sha256") -> Optional[str]:
    """Hash a local file or directory; return None if it does not exist."""

    if os.path.isdir(path):
        return hash_directory(path, algorithm)
    if os.path.isfile(path):
        return hash_file(path, algorithm)
    return None


def normalize_lock_hash(raw: str) -> tuple[str, str]:
    """Normalise a hash string taken from a lock file.

    Accepts:
      * ``sha256=<hex>``            (pip / requirements --hash)
      * ``sha512-<base64>``         (npm integrity strings)
      * bare hex                    (algorithm assumed sha256)

    Returns ``(canonical_algorithm, lowercase_hex)``.
    Raises ``ValueError`` for malformed strings.
    """

    raw = raw.strip()
    if "=" in raw and "-" not in raw.split("=", 1)[0]:
        algo, value = raw.split("=", 1)
        algo = algo.strip().lower()
        value = value.strip()
        if algo not in ALGORITHM_ALIASES:
            raise ValueError(f"unsupported hash algorithm: {algo}")
        if _looks_hex(value):
            return ALGORITHM_ALIASES[algo], value.lower()
        raise ValueError("hash value is not hexadecimal")

    if "-" in raw:
        algo, value = raw.split("-", 1)
        algo = algo.strip().lower()
        if algo not in ALGORITHM_ALIASES:
            raise ValueError(f"unsupported hash algorithm: {algo}")
        value = value.strip()
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("hash value is not valid base64") from exc
        return ALGORITHM_ALIASES[algo], decoded.hex()

    if _looks_hex(raw):
        return "SHA-256", raw.lower()
    raise ValueError("unrecognised hash format")


def _looks_hex(value: str) -> bool:
    if not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
