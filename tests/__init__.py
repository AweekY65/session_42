"""Automated tests for the local SBOM tool (standard-library unittest).

Run from the repository root:

    python tests/run_tests.py            # or: python -m unittest discover -s tests

Every test builds its own fixture project under a temp directory; nothing is
ever downloaded and no network service is contacted.
"""
