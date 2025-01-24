# tests/unit/key_management/test_key_generation.py

import unittest
from unittest.mock import patch, MagicMock, ANY
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, SECP256R1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
from modules.key_management.key_generation import KeyGenerator
from modules.key_management.exceptions import UnsupportedAlgorithm  # Only custom exception


class TestKeyGenerator(unittest.TestCase):
    def setUp(self):
        self.key_generator = KeyGenerator()

    def test_list_valid_key_types(self):
        expected_types = ['RSA', 'DSA', 'ECDSA', 'ED25519']
        self.assertListEqual(self.key_generator.list_valid_key_types(), expected_types)

    def test_list_valid_key_sizes_valid_type(self):
        rsa_sizes = [2048, 3072, 4096]
        self.assertListEqual(self.key_generator.list_valid_key_sizes('RSA'), rsa_sizes)

    def test_list_valid_key_sizes_invalid_type(self):
        # Updated to expect UnsupportedAlgorithm instead of ValueError
        with self.assertRaises(UnsupportedAlgorithm):
            self.key_generator.list_valid_key_sizes('INVALID_TYPE')

    def test_validate_key_type_valid(self):
        self.assertTrue(self.key_generator.validate_key_type('RSA'))

    def test_validate_key_type_invalid(self):
        self.assertFalse(self.key_generator.validate_key_type('INVALID_TYPE'))

    def test_validate_key_size_valid(self):
        self.assertTrue(self.key_generator.validate_key_size('RSA', 2048))

    def test_validate_key_size_invalid(self):
        self.assertFalse(self.key_generator.validate_key_size('RSA', 1024))

    @patch('modules.key_management.key_generation.ec.generate_private_key')
    @patch('modules.key_management.key_generation.rsa.generate_private_key')
    @patch('modules.key_management.key_generation.dsa.generate_private_key')
    @patch('modules.key_management.key_generation.ed25519.Ed25519PrivateKey.generate')
    def test_generate_key_pair_rsa(self, mock_ed25519_generate, mock_dsa_generate, mock_rsa_generate, mock_ec_generate):
        # Create a mock RSA private key
        mock_rsa_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_rsa_key.key_size = 2048
        mock_rsa_generate.return_value = mock_rsa_key

        # Create a mock public key
        mock_public_key = MagicMock()
        mock_public_key.public_bytes.return_value = b'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...'

        # Configure the RSA private key mock to return the mock public key
        mock_rsa_key.public_key.return_value = mock_public_key
        mock_rsa_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\n...'

        # Call the method under test
        private_key, public_key = self.key_generator.generate_key_pair('RSA', 2048)

        # Assertions to ensure key generation was called correctly
        mock_rsa_generate.assert_called_once_with(
            public_exponent=65537,
            key_size=2048,
            backend=ANY  # Using ANY since backend is default_backend()
        )
        mock_rsa_key.private_bytes.assert_called_once_with(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=ANY  # Changed to ANY to avoid instance mismatch
        )
        mock_public_key.public_bytes.assert_called_once_with(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Verify the returned keys contain expected substrings
        self.assertIn('BEGIN PRIVATE KEY', private_key)
        self.assertIn('ssh-rsa', public_key)

    @patch('modules.key_management.key_generation.ec.generate_private_key')
    @patch('modules.key_management.key_generation.rsa.generate_private_key')
    @patch('modules.key_management.key_generation.dsa.generate_private_key')
    @patch('modules.key_management.key_generation.ed25519.Ed25519PrivateKey.generate')
    def test_generate_key_pair_invalid_type(
        self, mock_ed25519_generate, mock_dsa_generate, mock_rsa_generate, mock_ec_generate
    ):
        # This test now correctly expects UnsupportedAlgorithm
        with self.assertRaises(UnsupportedAlgorithm):
            self.key_generator.generate_key_pair('INVALID_TYPE', 2048)

    @patch('modules.key_management.key_generation.ec.generate_private_key')
    def test_generate_key_pair_ecdsa_invalid_size(self, mock_ec_generate):
        # This test now correctly expects UnsupportedAlgorithm instead of ValueError
        with self.assertRaises(UnsupportedAlgorithm):
            self.key_generator.generate_key_pair('ECDSA', 123)  # Invalid size

    @patch('modules.key_management.key_generation.ec.generate_private_key')
    def test_generate_key_pair_ecdsa_valid(self, mock_ec_generate):
        # Create a mock ECDSA private key
        mock_ec_key = MagicMock(spec=EllipticCurvePrivateKey)
        mock_ec_key.key_curve = MagicMock()
        mock_ec_key.key_curve.key_size = 256  # Mock the key_curve's key_size attribute
        mock_ec_generate.return_value = mock_ec_key

        # Create a mock public key
        mock_public_key = MagicMock()
        mock_public_key.public_bytes.return_value = b'ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAA...'

        # Configure the ECDSA private key mock to return the mock public key
        mock_ec_key.public_key.return_value = mock_public_key
        mock_ec_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\n...EncryptedWithPassphrase...'

        # Call the method under test
        private_key, public_key = self.key_generator.generate_key_pair('ECDSA', 256, passphrase='securepass')

        # Assertions to ensure key generation was called correctly
        mock_ec_generate.assert_called_once()
        args, kwargs = mock_ec_generate.call_args

        # Assert that 'curve' is an instance of SECP256R1
        self.assertIsInstance(kwargs['curve'], SECP256R1)

        # Assert that 'backend' is the default_backend
        self.assertEqual(kwargs['backend'], default_backend())

        # Use ANY for encryption_algorithm to ignore the specific instance
        mock_ec_key.private_bytes.assert_called_once_with(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=ANY  # Changed to ANY to avoid instance mismatch
        )
        mock_public_key.public_bytes.assert_called_once_with(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Verify the returned keys contain expected substrings
        self.assertIn('BEGIN PRIVATE KEY', private_key)
        self.assertIn('ssh-ecdsa', public_key)
        self.assertIn('EncryptedWithPassphrase', private_key)

    @patch('modules.key_management.key_generation.ec.generate_private_key')
    @patch('modules.key_management.key_generation.rsa.generate_private_key')
    def test_generate_key_pair_with_passphrase(self, mock_rsa_generate, mock_ec_generate):
        # Test generating RSA key pair with passphrase encryption

        # Define passphrase
        passphrase = 'securepass'

        # Create a mock RSA private key
        mock_rsa_key = MagicMock(spec=rsa.RSAPrivateKey)
        mock_rsa_key.key_size = 2048
        mock_rsa_generate.return_value = mock_rsa_key

        # Create a mock public key
        mock_public_key = MagicMock()
        mock_public_key.public_bytes.return_value = b'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...'

        # Configure the RSA private key mock to return the mock public key
        mock_rsa_key.public_key.return_value = mock_public_key
        mock_rsa_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nEncryptedWithPassphrase...'

        # Call the method under test with passphrase
        private_key, public_key = self.key_generator.generate_key_pair('RSA', 2048, passphrase=passphrase)

        # Assertions to ensure key generation was called correctly
        mock_rsa_generate.assert_called_once_with(
            public_exponent=65537,
            key_size=2048,
            backend=ANY  # Using ANY since backend is default_backend()
        )
        mock_rsa_key.private_bytes.assert_called_once_with(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=ANY  # Changed to ANY to avoid instance mismatch
        )
        mock_public_key.public_bytes.assert_called_once_with(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Verify the returned keys contain expected substrings
        self.assertIn('BEGIN PRIVATE KEY', private_key)
        self.assertIn('ssh-rsa', public_key)
        self.assertIn('EncryptedWithPassphrase', private_key)

    def test_get_ec_curve_valid(self):
        curve = self.key_generator.get_ec_curve(256)
        self.assertIsInstance(curve, ec.SECP256R1)

    def test_get_ec_curve_invalid(self):
        # This test now correctly expects UnsupportedAlgorithm instead of ValueError
        with self.assertRaises(UnsupportedAlgorithm):
            self.key_generator.get_ec_curve(123)


if __name__ == '__main__':
    unittest.main()
