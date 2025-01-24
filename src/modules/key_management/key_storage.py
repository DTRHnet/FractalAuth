# src/modules/key_management/key_storage.py

"""
Key Storage Module for FractalAuth

This module provides functionalities to securely store and retrieve SSH keys.
It ensures that private keys are stored with high security measures, including encryption with passphrases,
and that public keys are accessible as needed.
"""

import logging
import os
from typing import Optional, Dict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class KeyStorage:
    def __init__(self, storage_path: str = 'data/keys/', encryption_key: Optional[bytes] = None):
        """
        Initialize the KeyStorage with a specified storage path and encryption key.
        Sets up the logger for the module and ensures the storage directory exists.

        Args:
            storage_path (str): The directory path where keys will be stored.
            encryption_key (Optional[bytes]): The key used for encrypting private keys.
                                              If None, it should be provided via environment variables.
        """
        # Set up logging for the KeyStorage module
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed trace

        # Create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Add formatter to ch
        ch.setFormatter(formatter)

        # Add ch to logger
        if not self.logger.handlers:
            self.logger.addHandler(ch)

        # Set the storage directory for keys
        self.storage_path = storage_path
        try:
            os.makedirs(self.storage_path, exist_ok=True)
            self.logger.info(f"Key storage directory set at: {self.storage_path}")
        except Exception as e:
            self.logger.error(f"Failed to create storage directory '{self.storage_path}': {str(e)}")
            raise

        # Initialize encryption
        if encryption_key:
            self.cipher_suite = Fernet(encryption_key)
            self.logger.debug("Fernet cipher suite initialized with provided encryption key.")
        else:
            env_key = os.environ.get('KEY_STORAGE_ENCRYPTION_KEY')
            if not env_key:
                self.logger.error("KEY_STORAGE_ENCRYPTION_KEY not set in environment variables.")
                raise EnvironmentError("KEY_STORAGE_ENCRYPTION_KEY not set in environment variables.")
            try:
                self.cipher_suite = Fernet(env_key.encode())
                self.logger.debug("Fernet cipher suite initialized with encryption key from environment variables.")
            except Exception as e:
                self.logger.error(f"Failed to initialize cipher suite: {str(e)}")
                raise

    def _derive_key_from_passphrase(self, passphrase: str, salt: bytes) -> bytes:
        """
        Derive a secure encryption key from a passphrase using PBKDF2HMAC.

        Args:
            passphrase (str): The passphrase to derive the key from.
            salt (bytes): A unique salt for key derivation.

        Returns:
            bytes: The derived encryption key.
        """
        self.logger.debug("Deriving encryption key from passphrase.")
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = Fernet(base64.urlsafe_b64encode(kdf.derive(passphrase.encode())))
            self.logger.debug("Encryption key derived successfully from passphrase.")
            return key
        except Exception as e:
            self.logger.error(f"Key derivation failed: {str(e)}")
            raise

    def _encrypt_key_with_passphrase(self, key: bytes, passphrase: str) -> bytes:
        """
        Encrypt the provided key using a passphrase-derived encryption key.

        Args:
            key (bytes): The key to encrypt.
            passphrase (str): The passphrase to derive the encryption key.

        Returns:
            bytes: The encrypted key.
        """
        self.logger.debug("Encrypting key with passphrase-derived encryption key.")
        try:
            # TODO: Implement a secure salt storage mechanism
            salt = os.urandom(16)  # Generate a random salt
            derived_cipher = self._derive_key_from_passphrase(passphrase, salt)
            encrypted_key = derived_cipher.encrypt(key)
            # Prepend the salt to the encrypted key for later decryption
            self.logger.debug("Key encrypted successfully with passphrase.")
            return salt + encrypted_key
        except Exception as e:
            self.logger.error(f"Encryption with passphrase failed: {str(e)}")
            raise

    def _decrypt_key_with_passphrase(self, encrypted_key: bytes, passphrase: str) -> bytes:
        """
        Decrypt the provided key using a passphrase-derived encryption key.

        Args:
            encrypted_key (bytes): The encrypted key to decrypt.
            passphrase (str): The passphrase to derive the decryption key.

        Returns:
            bytes: The decrypted key.
        """
        self.logger.debug("Decrypting key with passphrase-derived encryption key.")
        try:
            # Extract the salt from the beginning of the encrypted key
            salt = encrypted_key[:16]
            actual_encrypted_key = encrypted_key[16:]
            derived_cipher = self._derive_key_from_passphrase(passphrase, salt)
            decrypted_key = derived_cipher.decrypt(actual_encrypted_key)
            self.logger.debug("Key decrypted successfully with passphrase.")
            return decrypted_key
        except InvalidToken:
            self.logger.error("Invalid passphrase or corrupted encrypted key.")
            raise ValueError("Invalid passphrase or corrupted encrypted key.")
        except Exception as e:
            self.logger.error(f"Decryption with passphrase failed: {str(e)}")
            raise

    def _encrypt_key(self, key: bytes) -> bytes:
        """
        Encrypt the provided key using the main encryption cipher suite.

        Args:
            key (bytes): The key to encrypt.

        Returns:
            bytes: The encrypted key.
        """
        self.logger.debug("Encrypting key using main encryption cipher suite.")
        try:
            encrypted_key = self.cipher_suite.encrypt(key)
            self.logger.debug("Key encrypted successfully.")
            return encrypted_key
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            raise

    def _decrypt_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt the provided key using the main encryption cipher suite.

        Args:
            encrypted_key (bytes): The encrypted key to decrypt.

        Returns:
            bytes: The decrypted key.
        """
        self.logger.debug("Decrypting key using main encryption cipher suite.")
        try:
            decrypted_key = self.cipher_suite.decrypt(encrypted_key)
            self.logger.debug("Key decrypted successfully.")
            return decrypted_key
        except InvalidToken:
            self.logger.error("Invalid encryption key or corrupted encrypted key.")
            raise ValueError("Invalid encryption key or corrupted encrypted key.")
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            raise

    def store_private_key(self, private_key: str, filename: str = 'id_rsa', passphrase: Optional[str] = None):
        """
        Securely store the private SSH key, optionally encrypting it with a passphrase.

        Args:
            private_key (str): The private SSH key to store.
            filename (str): The filename for the stored private key.
            passphrase (Optional[str]): An optional passphrase to encrypt the private key.

        Raises:
            Exception: If storage fails due to encryption or I/O errors.
        """
        self.logger.debug(f"Storing private key with filename: {filename}, passphrase_provided: {'Yes' if passphrase else 'No'}")
        try:
            private_key_bytes = private_key.encode('utf-8')

            if passphrase:
                self.logger.debug("Passphrase provided. Encrypting private key with passphrase.")
                encrypted_key = self._encrypt_key_with_passphrase(private_key_bytes, passphrase)
            else:
                self.logger.debug("No passphrase provided. Encrypting private key with main encryption key.")
                encrypted_key = self._encrypt_key(private_key_bytes)

            # Define the full path for the private key file
            private_key_path = os.path.join(self.storage_path, filename)

            # Write the encrypted private key to the file
            with open(private_key_path, 'wb') as f:
                f.write(encrypted_key)
            self.logger.info(f"Private key stored successfully at {private_key_path}")

            # Set file permissions to restrict access (e.g., 600)
            os.chmod(private_key_path, 0o600)
            self.logger.debug(f"Set file permissions to 600 for {private_key_path}")

        except Exception as e:
            self.logger.error(f"Failed to store private key: {str(e)}")
            raise Exception(f"Failed to store private key: {str(e)}")

    def store_public_key(self, public_key: str, filename: str = 'id_rsa.pub'):
        """
        Store the public SSH key without encryption as it is not sensitive.

        Args:
            public_key (str): The public SSH key to store.
            filename (str): The filename for the stored public key.

        Raises:
            Exception: If storage fails due to I/O errors.
        """
        self.logger.debug(f"Storing public key with filename: {filename}")
        try:
            # Define the full path for the public key file
            public_key_path = os.path.join(self.storage_path, filename)

            # Write the public key to the file
            with open(public_key_path, 'w') as f:
                f.write(public_key)
            self.logger.info(f"Public key stored successfully at {public_key_path}")

            # Set file permissions to allow read access (e.g., 644)
            os.chmod(public_key_path, 0o644)
            self.logger.debug(f"Set file permissions to 644 for {public_key_path}")

        except Exception as e:
            self.logger.error(f"Failed to store public key: {str(e)}")
            raise Exception(f"Failed to store public key: {str(e)}")

    def retrieve_private_key(self, filename: str = 'id_rsa', passphrase: Optional[str] = None) -> str:
        """
        Retrieve and decrypt the stored private SSH key.

        Args:
            filename (str): The filename of the stored private key.
            passphrase (Optional[str]): The passphrase used to decrypt the private key, if any.

        Returns:
            str: The decrypted private SSH key.

        Raises:
            FileNotFoundError: If the specified private key file does not exist.
            ValueError: If decryption fails due to incorrect passphrase or corrupted data.
            Exception: If retrieval fails due to other errors.
        """
        self.logger.debug(f"Retrieving private key from filename: {filename}, passphrase_provided: {'Yes' if passphrase else 'No'}")
        try:
            # Define the full path for the private key file
            private_key_path = os.path.join(self.storage_path, filename)

            # Read the encrypted private key from the file
            with open(private_key_path, 'rb') as f:
                encrypted_key = f.read()
            self.logger.debug(f"Encrypted private key read from {private_key_path}")

            if passphrase:
                self.logger.debug("Passphrase provided. Decrypting private key with passphrase.")
                decrypted_key_bytes = self._decrypt_key_with_passphrase(encrypted_key, passphrase)
            else:
                self.logger.debug("No passphrase provided. Decrypting private key with main encryption key.")
                decrypted_key_bytes = self._decrypt_key(encrypted_key)

            # Convert bytes back to string
            decrypted_key = decrypted_key_bytes.decode('utf-8')
            self.logger.info(f"Private key retrieved and decrypted successfully from {private_key_path}")
            return decrypted_key

        except FileNotFoundError:
            self.logger.error(f"Private key file '{filename}' not found in storage.")
            raise FileNotFoundError(f"Private key file '{filename}' not found in storage.")
        except ValueError as ve:
            self.logger.error(f"Decryption failed: {str(ve)}")
            raise ValueError(f"Decryption failed: {str(ve)}")
        except Exception as e:
            self.logger.error(f"Failed to retrieve private key: {str(e)}")
            raise Exception(f"Failed to retrieve private key: {str(e)}")

    def retrieve_public_key(self, filename: str = 'id_rsa.pub') -> str:
        """
        Retrieve the stored public SSH key.

        Args:
            filename (str): The filename of the stored public key.

        Returns:
            str: The public SSH key.

        Raises:
            FileNotFoundError: If the specified public key file does not exist.
            Exception: If retrieval fails due to I/O errors.
        """
        self.logger.debug(f"Retrieving public key from filename: {filename}")
        try:
            # Define the full path for the public key file
            public_key_path = os.path.join(self.storage_path, filename)

            # Read the public key from the file
            with open(public_key_path, 'r') as f:
                public_key = f.read()
            self.logger.info(f"Public key retrieved successfully from {public_key_path}")
            return public_key

        except FileNotFoundError:
            self.logger.error(f"Public key file '{filename}' not found in storage.")
            raise FileNotFoundError(f"Public key file '{filename}' not found in storage.")
        except Exception as e:
            self.logger.error(f"Failed to retrieve public key: {str(e)}")
            raise Exception(f"Failed to retrieve public key: {str(e)}")

    def list_stored_keys(self) -> Dict[str, str]:
        """
        List all stored SSH keys with their filenames.

        Returns:
            Dict[str, str]: A dictionary with filenames as keys and key types as values.

        Raises:
            Exception: If listing fails due to I/O errors.
        """
        self.logger.debug("Listing all stored SSH keys.")
        try:
            keys = {}
            for filename in os.listdir(self.storage_path):
                if filename.endswith('.pub'):
                    key_type = 'Public Key'
                else:
                    key_type = 'Private Key'
                keys[filename] = key_type
            self.logger.info(f"Stored keys: {keys}")
            return keys
        except Exception as e:
            self.logger.error(f"Failed to list stored keys: {str(e)}")
            raise Exception(f"Failed to list stored keys: {str(e)}")
