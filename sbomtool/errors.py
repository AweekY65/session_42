"""Exception hierarchy for the local SBOM tool.

Any malformed or unreadable input raises :class:`SbomError` (or a subclass).
Callers -- especially the CLI -- must never swallow these and report success:
a damaged input always produces a non-zero exit status.
"""


class SbomError(Exception):
    """Base class for all tool-level failures."""


class InputError(SbomError):
    """A project manifest/lock file is missing, unreadable or malformed."""


class PolicyError(SbomError):
    """An offline policy file is missing, malformed or semantically invalid."""
