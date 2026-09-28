"""Exception hierarchy for the SBOM tool.

Any malformed or illegal input raises :class:`SBOMError` (or a subclass).
Callers (the CLI in particular) convert these into non-zero exit codes so a
corrupt configuration can never be reported as a successful run.
"""

from __future__ import annotations


class SBOMError(Exception):
    """Base class for every error raised by the tool."""


class ParseError(SBOMError):
    """A manifest or lock file cannot be parsed."""


class PolicyError(SBOMError):
    """A policy / license catalogue file is invalid."""


class InputError(SBOMError):
    """Generic invalid user input (missing files, bad arguments, ...)."""
