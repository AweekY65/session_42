"""Local SBOM: a fully offline software supply-chain SBOM generator and checker.

Everything (dependency manifests, lock files, package metadata, hashes,
license policies, reports) is read from and written to the local filesystem.
The package deliberately uses only the Python standard library so that no
package installation can trigger network access.
"""

__version__ = "1.0.0"
