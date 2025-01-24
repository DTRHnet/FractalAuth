# tests/integration/key_management/test_key_management_integration.py

import unittest
from key_management.key_generation import KeyGenerator
from key_management.key_validation import KeyValidator
from key_management.key_storage import KeyStorage
from cryptography.fernet import Fernet
import os

class TestKeyManagementIntegration(unittest.TestCase):
    def setUp(self):
        # Initialize components with a temporary storage path and encryption key
        self.encryption_key = Fernet.generate_key()
        self.key_generator = KeyGenerator()
        self.key_validator = KeyValidator(self.key_generator)
        self.key_storage = KeyStorage(storage_path='integration_test_keys/', encryption_key=self.encryption_key)

        # Ensure the storage directory is clean
        if not os.path.exists('integration_test_keys/'):
            os.makedirs('integration_test_keys/')

    def tearDown(self):
        # Clean up the storage directory after tests
        for root, dirs, files in os.walk('integration_test_keys/', topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir('integration_test_keys/')

    def test_full_key_management_flow(self):
        # Generate a key pair
        private_key, public_key = self.key_generator.generate_key_pair('RSA', 2048, passphrase='securepass')

        # Store the keys
        self.key_storage.store_private_key(private_key, filename='id_rsa', passphrase='securepass')
        self.key_storage.store_public_key(public_key, filename='id_rsa.pub')

        # List stored keys
        stored_keys = self.key_storage.list_stored_keys()
        self.assertIn('id_rsa', stored_keys)
        self.assertIn('id_rsa.pub', stored_keys)

        # Retrieve and validate the private key
        retrieved_private_key = self.key_storage.retrieve_private_key(filename='id_rsa', passphrase='securepass')
        self.assertEqual(retrieved_private_key, private_key)

        # Validate the retrieved private key
        is_private_key_valid = self.key_validator.validate_private_key(retrieved_private_key, passphrase='securepass')
        self.assertTrue(is_private_key_valid)

        # Retrieve and validate the public key
        retrieved_public_key = self.key_storage.retrieve_public_key(filename='id_rsa.pub')
        self.assertEqual(retrieved_public_key, public_key)

        is_public_key_valid = self.key_validator.validate_public_key(retrieved_public_key)
        self.assertTrue(is_public_key_valid)

if __name__ == '__main__':
    unittest.main()
