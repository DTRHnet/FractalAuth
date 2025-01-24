# tests/mocks/key_management/test_key_management_mocks.py

import unittest
from unittest.mock import MagicMock
from key_management.key_generation import KeyGenerator

class TestKeyManagementMocks(unittest.TestCase):
    def setUp(self):
        self.key_generator = KeyGenerator()

    def test_mocked_key_generation(self):
        # Create a mock for the generate_key_pair method
        self.key_generator.generate_key_pair = MagicMock(return_value=("mock_private_key", "mock_public_key"))

        private_key, public_key = self.key_generator.generate_key_pair('RSA', 2048)

        self.key_generator.generate_key_pair.assert_called_once_with('RSA', 2048)
        self.assertEqual(private_key, "mock_private_key")
        self.assertEqual(public_key, "mock_public_key")

if __name__ == '__main__':
    unittest.main()
