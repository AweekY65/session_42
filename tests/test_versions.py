"""Unit tests for version comparison internals."""

import unittest

from sbomtool.versions import compare, satisfies


class CompareTests(unittest.TestCase):
    def test_basic_ordering(self):
        self.assertEqual(compare("1.0.0", "1.0.1"), -1)
        self.assertEqual(compare("2.0", "1.9"), 1)
        self.assertEqual(compare("1.2", "1.2.0"), 0)

    def test_prerelease_before_release(self):
        self.assertEqual(compare("1.0.0-alpha", "1.0.0"), -1)
        self.assertEqual(compare("1.0.0-rc1", "1.0.0-beta"), 1)

    def test_python_specifiers(self):
        self.assertTrue(satisfies("2.31.0", ">=2.31", "python"))
        self.assertFalse(satisfies("2.30", ">=2.31", "python"))
        # PEP 440: ~=2.6 == >=2.6,==2.* ; ~=2.6.0 == >=2.6.0,==2.6.*
        self.assertTrue(satisfies("2.7.0", "~=2.6", "python"))
        self.assertFalse(satisfies("3.0.0", "~=2.6", "python"))
        self.assertTrue(satisfies("2.6.9", "~=2.6.0", "python"))
        self.assertFalse(satisfies("2.7.0", "~=2.6.0", "python"))
        self.assertTrue(satisfies("1.2.3", ">=1.0,<2", "python"))
        self.assertFalse(satisfies("2.0", ">=1.0,<2", "python"))
        self.assertFalse(satisfies("3.0.1", "==3.0.0", "python"))

    def test_npm_caret(self):
        self.assertTrue(satisfies("1.9.9", "^1.2.0", "npm"))
        self.assertFalse(satisfies("2.0.0", "^1.2.0", "npm"))
        self.assertTrue(satisfies("0.2.9", "^0.2.3", "npm"))
        self.assertFalse(satisfies("0.3.0", "^0.2.3", "npm"))
        self.assertTrue(satisfies("0.0.3", "^0.0.3", "npm"))
        self.assertFalse(satisfies("0.0.4", "^0.0.3", "npm"))

    def test_npm_tilde(self):
        self.assertTrue(satisfies("2.1.9", "~2.1.0", "npm"))
        self.assertFalse(satisfies("2.2.0", "~2.1.0", "npm"))

    def test_star_and_prefix(self):
        self.assertTrue(satisfies("1.2.3", "1.2.x", "npm"))
        self.assertFalse(satisfies("1.3.0", "1.2.x", "npm"))
        self.assertTrue(satisfies("9.9.9", "*", "npm"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
