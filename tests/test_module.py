# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import unittest


class TestModule(unittest.TestCase):
    """Class to test the module."""

    def test_foo_bar(self):
        """Test the 'test_foo_bar' method."""
        elems = [1, 2, 3]
        self.assertEqual(len(elems), 3)


if __name__ == "__main__":
    unittest.main()
