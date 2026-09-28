"""Content-hash helpers -- all computed from local data only."""

from __future__ import annotations

import base64
import hashlib

from .errors import SbomError
from .models import Hash

_KNOWN_ALGS = {"sha1", "sha256", "sha384", "sha512", "md5", "blake2b"}


def hash_file(path: str, alg: str = "sha256") -> str:
    """Return the lowercase hex digest of a local file."""

    if alg not in _KNOWN_ALGS:
        raise SbomError(f"unsupported hash algorithm: {alg}")
    h = hashlib.new(alg)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_hex_hash(alg_or_url: str, value: str, origin: str = "lock") -> Hash | None:
    """Parse hash specs in the shapes used by local lock files.

    Accepted forms:

    * explicit call ``parse_hex_hash("sha256", "<hex>")``
    * combined  ``alg=hexdigest`` (PEP 503 / requirements ``--hash=``)
    * pip style ``alg:hexdigest`` (Pipfile.lock hashes)
    * URL fragment ``https://...#sha256=<hex>``
    """

    alg = alg_or_url.lower()
    if "=" in value and alg_or_url in ("", "hash"):
        alg, value = value.split("=", 1)
        alg = alg.lower()
    if alg.startswith("http") and "#" in alg:
        frag = alg.split("#", 1)[1]
        if "=" in frag:
            alg, value = frag.split("=", 1)
            alg = alg.lower()
    if alg_or_url in ("", "hash") and ":" in value and "=" not in value:
        alg, _, value = value.partition(":")
        alg = alg.lower()
    value = value.strip()
    if not value or not all(c in "0123456789abcdefABCDEF" for c in value):
        return None
    if alg not in _KNOWN_ALGS:
        return None
    return Hash(alg=alg, value=value.lower(), origin=origin)


def parse_integrity(integrity: str) -> Hash | None:
    """Parse an npm ``integrity`` string: ``sha256-base64=<b64digest>``."""

    if not integrity or "-" not in integrity:
        return None
    alg, b64 = integrity.split("-", 1)
    alg = alg.lower()
    if alg not in _KNOWN_ALGS:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    return Hash(alg=alg, value=raw.hex(), origin="lock")
