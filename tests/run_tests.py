#!/usr/bin/env python3
"""Terminal test runner: discovers and runs every test with clear output.

Usage (from the repository root):

    python tests/run_tests.py
"""

from __future__ import annotations

import os
import sys
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    loader = unittest.TestLoader()
    start = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start, pattern="test_*.py")
    print("=" * 70)
    print(" local SBOM tool — automated test suite")
    print("=" * 70)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("-" * 70)
    print(f"tests run : {result.testsRun}")
    print(f"failures  : {len(result.failures)}")
    print(f"errors    : {len(result.errors)}")
    print(f"skipped   : {len(result.skipped)}")
    if result.wasSuccessful():
        print("RESULT    : ALL TESTS PASSED")
        return 0
    print("RESULT    : FAILURES PRESENT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
