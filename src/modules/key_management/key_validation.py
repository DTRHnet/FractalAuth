# src/modules/key_management/key_validation.py

"""
Key Validation Module for FractalAuth

This module provides functionalities to validate SSH keys.
It ensures that generated or provided keys conform to the specified types and sizes.
Additionally, it checks for passphrase protection where necessary to enforce security standards.
"""

import logging
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_public_key
)
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey

from .key_generation import KeyGenerator


class KeyValidator:
    def __init__(self, key_generator: KeyGenerator):
        """
        Initialize the KeyValidator with a KeyGenerator instance to access valid key types and sizes.
        Sets up the logger for the module.

        Args:
            key_generator (KeyGenerator): An instance of KeyGenerator to retrieve validation parameters.
        """
        # Set up logging for the KeyValidator module
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

        # Store the key_generator instance for accessing valid_key_types and key sizes
        self.key_generator = key_generator

        self.logger.info("KeyValidator initialized with KeyGenerator dependency.")

    def validate_key_type(self, key_type: str) -> bool:
        """
        Validate whether the provided key type is supported.

        Args:
            key_type (str): The SSH key type to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        self.logger.debug(f"Validating key type: {key_type}")
        is_valid = key_type in self.key_generator.valid_key_types
        self.logger.info(f"Key type '{key_type}' validation result: {'Valid' if is_valid else 'Invalid'}")
        return is_valid

    def validate_key_size(self, key_type: str, key_size: int) -> bool:
        """
        Validate whether the provided key size is valid for the given key type.

        Args:
            key_type (str): The SSH key type.
            key_size (int): The size of the SSH key in bits.

        Returns:
            bool: True if valid, False otherwise.
        """
        self.logger.debug(f"Validating key size: {key_size} for key type: {key_type}")
        try:
            valid_sizes = self.key_generator.list_valid_key_sizes(key_type)
            is_valid = key_size in valid_sizes
            self.logger.info(f"Key size '{key_size}' for type '{key_type}' validation result: {'Valid' if is_valid else 'Invalid'}")
            return is_valid
        except ValueError as ve:
            self.logger.error(f"Validation failed: {ve}")
            return False

    def validate_private_key(self, private_key: str, passphrase: Optional[str] = None) -> bool:
        """
        Validate the provided private SSH key, ensuring it conforms to type, size, and passphrase protection.

        Args:
            private_key (str): The private SSH key to validate.
            passphrase (Optional[str]): The passphrase used to decrypt the private key, if any.

        Returns:
            bool: True if the key is valid and properly protected, False otherwise.

        Raises:
            ValueError: If the private_key format is invalid or does not meet security standards.
        """
        self.logger.debug("Starting validation for private SSH key.")
        try:
            # Attempt to load the private key with or without passphrase
            self.logger.debug("Attempting to load private key.")
            private_key_obj = load_pem_private_key(
                data=private_key.encode('utf-8'),
                password=passphrase.encode('utf-8') if passphrase else None,
                backend=default_backend()
            )
            self.logger.debug("Private key loaded successfully.")

            # Determine key type and size
            if isinstance(private_key_obj, rsa.RSAPrivateKey):
                key_type = 'RSA'
                key_size = private_key_obj.key_size
            elif isinstance(private_key_obj, dsa.DSAPrivateKey):
                key_type = 'DSA'
                key_size = private_key_obj.key_size
            elif isinstance(private_key_obj, ec.EllipticCurvePrivateKey):
                key_type = 'ECDSA'
                key_size = private_key_obj.key_curve.key_size
            elif isinstance(private_key_obj, ed25519.Ed25519PrivateKey):
                key_type = 'ED25519'
                key_size = 256  # Fixed size
            else:
                self.logger.error("Unsupported private key type.")
                raise ValueError("Unsupported key type.")

            self.logger.debug(f"Determined private key type: {key_type}, size: {key_size}")

            # Validate key type and size
            if not self.validate_key_type(key_type):
                self.logger.error(f"Invalid key type: {key_type}")
                raise ValueError(f"Invalid key type: {key_type}.")
            if not self.validate_key_size(key_type, key_size):
                self.logger.error(f"Invalid key size: {key_size} for key type: {key_type}")
                raise ValueError(f"Invalid key size: {key_size} for key type: {key_type}.")

            # Check passphrase protection
            if passphrase:
                self.logger.debug("Passphrase provided. Ensuring private key is encrypted.")
                # If passphrase is provided, key should be encrypted
                # Attempting to serialize the key without encryption should fail
                try:
                    private_key_obj.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    self.logger.error("Private key is not encrypted despite passphrase being provided.")
                    raise ValueError("Private key is not encrypted with a passphrase.")
                except ValueError:
                    # Expected behavior: cannot serialize without encryption when key is encrypted
                    self.logger.debug("Private key is properly encrypted with passphrase.")
            else:
                self.logger.debug("No passphrase provided. Ensuring private key is not encrypted.")
                # If no passphrase, ensure the key is not encrypted
                try:
                    private_key_obj.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    self.logger.debug("Private key is not encrypted as expected.")
                except TypeError:
                    self.logger.error("Private key is encrypted but no passphrase was provided.")
                    raise ValueError("Private key is encrypted but no passphrase was provided.")

            self.logger.info("Private SSH key validation successful.")
            return True

        except (ValueError, UnsupportedAlgorithm, InvalidKey) as e:
            self.logger.error(f"Private key validation failed: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during private key validation: {str(e)}")
            return False

    def validate_public_key(self, public_key: str) -> bool:
        """
        Validate the provided public SSH key, ensuring it conforms to type and size specifications.

        Args:
            public_key (str): The public SSH key to validate.

        Returns:
            bool: True if the key is valid, False otherwise.

        Raises:
            ValueError: If the public_key format is invalid or does not meet security standards.
        """
        self.logger.debug("Starting validation for public SSH key.")
        try:
            # Attempt to load the public key
            self.logger.debug("Attempting to load public key.")
            public_key_obj = load_ssh_public_key(
                data=public_key.encode('utf-8'),
                backend=default_backend()
            )
            self.logger.debug("Public key loaded successfully.")

            # Determine key type and size
            if isinstance(public_key_obj, rsa.RSAPublicKey):
                key_type = 'RSA'
                key_size = public_key_obj.key_size
            elif isinstance(public_key_obj, dsa.DSAPublicKey):
                key_type = 'DSA'
                key_size = public_key_obj.key_size
            elif isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                key_type = 'ECDSA'
                key_size = public_key_obj.key_curve.key_size
            elif isinstance(public_key_obj, ed25519.Ed25519PublicKey):
                key_type = 'ED25519'
                key_size = 256  # Fixed size
            else:
                self.logger.error("Unsupported public key type.")
                raise ValueError("Unsupported key type.")

            self.logger.debug(f"Determined public key type: {key_type}, size: {key_size}")

            # Validate key type and size
            if not self.validate_key_type(key_type):
                self.logger.error(f"Invalid key type: {key_type}")
                raise ValueError(f"Invalid key type: {key_type}.")
            if not self.validate_key_size(key_type, key_size):
                self.logger.error(f"Invalid key size: {key_size} for key type: {key_type}")
                raise ValueError(f"Invalid key size: {key_size} for key type: {key_type}.")

            self.logger.info("Public SSH key validation successful.")
            return True

        except (ValueError, UnsupportedAlgorithm, InvalidKey) as e:
            self.logger.error(f"Public key validation failed: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during public key validation: {str(e)}")
            return False
