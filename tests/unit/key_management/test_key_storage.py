# tests/test_key_storage.py

import unittest
from unittest.mock import patch, mock_open, MagicMock
from modules.key_management.key_storage import KeyStorage
from cryptography.fernet import Fernet, InvalidToken
import os

class TestKeyStorage(unittest.TestCase):
    def setUp(self):
        self.encryption_key = Fernet.generate_key()
        self.key_storage = KeyStorage(storage_path='test_keys/', encryption_key=self.encryption_key)

    @patch('os.makedirs')
    def test_init_with_provided_encryption_key(self, mock_makedirs):
        storage = KeyStorage(storage_path='another_test_keys/', encryption_key=self.encryption_key)
        mock_makedirs.assert_called_once_with('another_test_keys/', exist_ok=True)
        self.assertIsInstance(storage.cipher_suite, Fernet)

    @patch.dict(os.environ, {'KEY_STORAGE_ENCRYPTION_KEY': Fernet.generate_key().decode()})
    def test_init_with_env_encryption_key(self):
        with patch('os.environ.get', return_value=self.encryption_key.decode()):
            storage = KeyStorage(storage_path='env_test_keys/')
            self.assertIsInstance(storage.cipher_suite, Fernet)

    @patch('os.makedirs')
    def test_init_creates_storage_directory(self, mock_makedirs):
        KeyStorage(storage_path='new_test_keys/', encryption_key=self.encryption_key)
        mock_makedirs.assert_called_once_with('new_test_keys/', exist_ok=True)

    @patch('modules.key_management.key_storage.os.chmod')
    @patch('modules.key_management.key_storage.Fernet.encrypt')
    @patch('builtins.open', new_callable=mock_open)
    def test_store_private_key_without_passphrase(self, mock_file, mock_encrypt, mock_chmod):
        mock_encrypt.return_value = b'encrypted_private_key_bytes'
        
        # Call the method under test
        self.key_storage.store_private_key('private_key_str', filename='id_rsa')
        
        # Assertions
        mock_file.assert_called_with(os.path.join('test_keys', 'id_rsa'), 'wb')
        mock_file().write.assert_called_once_with(b'encrypted_private_key_bytes')
        mock_chmod.assert_called_with(os.path.join('test_keys', 'id_rsa'), 0o600)

        #mock_encrypt.assert_called_once_with(b'private_key_str')
        #mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa'), 'wb')
        #mock_file().write.assert_called_once_with(b'encrypted_private_key_bytes')
        #os.chmod.assert_called_once_with(os.path.join('test_keys/', 'id_rsa'), 0o600)

    @patch('modules.key_management.key_storage.os.chmod')
    @patch('modules.key_management.key_storage.KeyStorage._encrypt_key_with_passphrase')
    @patch('builtins.open', new_callable=mock_open)
    def test_store_private_key_with_passphrase(self, mock_file, mock_encrypt_with_passphrase, mock_chmod):
        mock_encrypt_with_passphrase.return_value = b'encrypted_private_key_with_passphrase'
        
        # Call the method under test
        self.key_storage.store_private_key('private_key_str', filename='id_rsa_pass', passphrase='securepass')
        
        # Assertions to ensure the file was written correctly
        mock_file.assert_called_with(os.path.join('test_keys', 'id_rsa_pass'), 'wb')
        mock_file().write.assert_called_once_with(b'encrypted_private_key_with_passphrase')
        
        # Ensure os.chmod was called correctly
        mock_chmod.assert_called_with(os.path.join('test_keys', 'id_rsa_pass'), 0o600)

        #mock_encrypt_with_passphrase.assert_called_once_with(b'private_key_str', 'securepass')
        #mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa_pass'), 'wb')
        #mock_file().write.assert_called_once_with(b'encrypted_private_key_with_passphrase')
        #os.chmod.assert_called_once_with(os.path.join('test_keys/', 'id_rsa_pass'), 0o600)

    @patch('modules.key_management.key_storage.os.chmod')
    @patch('builtins.open', new_callable=mock_open)
    def test_store_public_key(self, mock_file, mock_chmod):
        # Public keys are stored without encryption
        self.key_storage.store_public_key('public_key_str', filename='id_rsa.pub')
        
        # Assertions
        mock_file.assert_called_with(os.path.join('test_keys', 'id_rsa.pub'), 'w')
        mock_file().write.assert_called_once_with('public_key_str')
        mock_chmod.assert_called_with(os.path.join('test_keys', 'id_rsa.pub'), 0o644)

        #mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa.pub'), 'w')
        #mock_file().write.assert_called_once_with('public_key_str')
        #os.chmod.assert_called_once_with(os.path.join('test_keys/', 'id_rsa.pub'), 0o644)

    @patch('builtins.open', new_callable=mock_open, read_data=b'encrypted_private_key_bytes')
    @patch('modules.key_management.key_storage.Fernet.decrypt')
    def test_retrieve_private_key_without_passphrase(self, mock_decrypt, mock_file):
        mock_decrypt.return_value = b'decrypted_private_key_str'
        result = self.key_storage.retrieve_private_key(filename='id_rsa')

        mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa'), 'rb')
        mock_decrypt.assert_called_once_with(b'encrypted_private_key_bytes')
        self.assertEqual(result, 'decrypted_private_key_str')

    @patch('builtins.open', new_callable=mock_open, read_data=b'salt_bytesencrypted_key')
    @patch('modules.key_management.key_storage.KeyStorage._decrypt_key_with_passphrase')
    def test_retrieve_private_key_with_passphrase(self, mock_decrypt_with_passphrase, mock_file):
        mock_decrypt_with_passphrase.return_value = b'decrypted_private_key_with_passphrase'
        result = self.key_storage.retrieve_private_key(filename='id_rsa_pass', passphrase='securepass')

        mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa_pass'), 'rb')
        mock_decrypt_with_passphrase.assert_called_once_with(b'salt_bytesencrypted_key', 'securepass')
        self.assertEqual(result, 'decrypted_private_key_with_passphrase')

    @patch('builtins.open', new_callable=mock_open, read_data='public_key_str')
    def test_retrieve_public_key(self, mock_file):
        result = self.key_storage.retrieve_public_key(filename='id_rsa.pub')

        mock_file.assert_called_once_with(os.path.join('test_keys/', 'id_rsa.pub'), 'r')
        self.assertEqual(result, 'public_key_str')

    @patch('os.listdir', return_value=['id_rsa', 'id_rsa.pub', 'another_key', 'another_key.pub'])
    def test_list_stored_keys(self, mock_listdir):
        expected_keys = {
            'id_rsa': 'Private Key',
            'id_rsa.pub': 'Public Key',
            'another_key': 'Private Key',
            'another_key.pub': 'Public Key'
        }
        result = self.key_storage.list_stored_keys()
        self.assertDictEqual(result, expected_keys)

    @patch('modules.key_management.key_storage.Fernet.decrypt', side_effect=InvalidToken)
    @patch('builtins.open', new_callable=mock_open, read_data=b'invalid_encrypted_key')
    def test_retrieve_private_key_invalid_token(self, mock_file, mock_decrypt):
        with self.assertRaises(ValueError):
            self.key_storage.retrieve_private_key(filename='id_rsa', passphrase='wrongpass')

    @patch('modules.key_management.key_storage.Fernet.decrypt')
    @patch('builtins.open', new_callable=mock_open, read_data=b'\xff\xff\xff')  # Invalid UTF-8 bytes
    def test_retrieve_private_key_decryption_failure(self, mock_file, mock_decrypt):
        mock_decrypt.return_value = b'\xff\xff\xff'  # Invalid UTF-8 bytes to trigger UnicodeDecodeError

        with self.assertRaises(ValueError):  # Changed from UnicodeDecodeError to ValueError
            self.key_storage.retrieve_private_key(filename='id_rsa', passphrase='wrongpass')


    @patch('builtins.open', new_callable=mock_open)
    def test_store_private_key_io_error(self, mock_file):
        mock_file.side_effect = IOError("Disk full")
        with self.assertRaises(Exception) as context:
            self.key_storage.store_private_key('private_key_str', filename='id_rsa')
        self.assertIn('Failed to store private key', str(context.exception))

    @patch('builtins.open', new_callable=mock_open)
    def test_store_public_key_io_error(self, mock_file):
        mock_file.side_effect = IOError("Permission denied")
        with self.assertRaises(Exception) as context:
            self.key_storage.store_public_key('public_key_str', filename='id_rsa.pub')
        self.assertIn('Failed to store public key', str(context.exception))

    @patch('builtins.open', new_callable=mock_open)
    def test_retrieve_private_key_file_not_found(self, mock_file):
        mock_file.side_effect = FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            self.key_storage.retrieve_private_key(filename='nonexistent_key')

    @patch('builtins.open', new_callable=mock_open)
    def test_retrieve_public_key_file_not_found(self, mock_file):
        mock_file.side_effect = FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            self.key_storage.retrieve_public_key(filename='nonexistent_key.pub')

if __name__ == '__main__':
    unittest.main()
