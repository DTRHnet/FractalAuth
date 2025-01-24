# tests/test_key_validation.py

import unittest
from unittest.mock import patch, MagicMock
from modules.key_management.key_validation import KeyValidator
from modules.key_management.key_generation import KeyGenerator
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

class TestKeyValidator(unittest.TestCase):
    def setUp(self):
        self.key_generator = KeyGenerator()
        self.key_validator = KeyValidator(self.key_generator)

    def test_validate_key_type_valid(self):
        self.assertTrue(self.key_validator.validate_key_type('RSA'))

    def test_validate_key_type_invalid(self):
        self.assertFalse(self.key_validator.validate_key_type('INVALID_TYPE'))

    def test_validate_key_size_valid(self):
        self.assertTrue(self.key_validator.validate_key_size('RSA', 2048))

    def test_validate_key_size_invalid(self):
        self.assertFalse(self.key_validator.validate_key_size('RSA', 1024))

    @patch('modules.key_management.key_validation.load_pem_private_key')
    def test_validate_private_key_valid_encrypted(self, mock_load_pem_private_key):
        mock_private_key_obj = MagicMock(spec=rsa.RSAPrivateKey)
        mock_private_key_obj.key_size = 2048
        mock_private_key_obj.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nEncrypted...'
        mock_load_pem_private_key.return_value = mock_private_key_obj

        with patch.object(self.key_validator, 'validate_key_type', return_value=True):
            with patch.object(self.key_validator, 'validate_key_size', return_value=True):
                # Simulate that private_bytes raises ValueError when no encryption is provided
                mock_private_key_obj.private_bytes.side_effect = ValueError("Private key is encrypted.")

                result = self.key_validator.validate_private_key('encrypted_private_key_str', passphrase='pass')

                self.assertTrue(result)

    @patch('modules.key_management.key_validation.load_pem_private_key')
    def test_validate_private_key_valid_unencrypted(self, mock_load_pem_private_key):
        mock_private_key_obj = MagicMock(spec=rsa.RSAPrivateKey)
        mock_private_key_obj.key_size = 2048
        mock_private_key_obj.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\nUnencrypted...'
        mock_load_pem_private_key.return_value = mock_private_key_obj

        with patch.object(self.key_validator, 'validate_key_type', return_value=True):
            with patch.object(self.key_validator, 'validate_key_size', return_value=True):
                result = self.key_validator.validate_private_key('unencrypted_private_key_str')

                self.assertTrue(result)

    @patch('modules.key_management.key_validation.load_pem_private_key')
    def test_validate_private_key_invalid_decryption(self, mock_load_pem_private_key):
        mock_load_pem_private_key.side_effect = ValueError("Incorrect passphrase.")

        result = self.key_validator.validate_private_key('invalid_private_key_str', passphrase='wrongpass')

        self.assertFalse(result)

    @patch('modules.key_management.key_validation.load_pem_private_key')
    def test_validate_private_key_unsupported_type(self, mock_load_pem_private_key):
        mock_private_key_obj = MagicMock()
        mock_load_pem_private_key.return_value = mock_private_key_obj

        mock_private_key_obj.__class__ = MagicMock()  # Not an instance of supported key types

        result = self.key_validator.validate_private_key('unsupported_private_key_str')

        self.assertFalse(result)

    @patch('modules.key_management.key_validation.load_ssh_public_key')
    def test_validate_public_key_valid(self, mock_load_ssh_public_key):
        mock_public_key_obj = MagicMock(spec=rsa.RSAPublicKey)
        mock_public_key_obj.key_size = 2048
        mock_load_ssh_public_key.return_value = mock_public_key_obj

        with patch.object(self.key_validator, 'validate_key_type', return_value=True):
            with patch.object(self.key_validator, 'validate_key_size', return_value=True):
                result = self.key_validator.validate_public_key('valid_public_key_str')
                self.assertTrue(result)

    @patch('modules.key_management.key_validation.load_ssh_public_key')
    def test_validate_public_key_invalid_type(self, mock_load_ssh_public_key):
        mock_public_key_obj = MagicMock()
        mock_public_key_obj.__class__ = MagicMock()  # Unsupported key type
        mock_load_ssh_public_key.return_value = mock_public_key_obj

        result = self.key_validator.validate_public_key('invalid_public_key_str')
        self.assertFalse(result)

    @patch('modules.key_management.key_validation.load_ssh_public_key')
    def test_validate_public_key_invalid_key_size(self, mock_load_ssh_public_key):
        mock_public_key_obj = MagicMock(spec=rsa.RSAPublicKey)
        mock_public_key_obj.key_size = 1024  # Assuming 1024 is invalid for RSA in this context
        mock_load_ssh_public_key.return_value = mock_public_key_obj

        with patch.object(self.key_validator, 'validate_key_type', return_value=True):
            with patch.object(self.key_validator, 'validate_key_size', return_value=False):
                result = self.key_validator.validate_public_key('invalid_size_public_key_str')
                self.assertFalse(result)

    @patch('modules.key_management.key_validation.load_pem_private_key')
    def test_validate_private_key_missing_passphrase(self, mock_load_pem_private_key):
        mock_private_key_obj = MagicMock(spec=rsa.RSAPrivateKey)
        mock_private_key_obj.key_size = 2048
        # Simulate that private_bytes raises TypeError when key is encrypted but no passphrase is provided
        mock_private_key_obj.private_bytes.side_effect = TypeError("Private key is encrypted.")
        mock_load_pem_private_key.return_value = mock_private_key_obj

        result = self.key_validator.validate_private_key('encrypted_private_key_str')

        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
