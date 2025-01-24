# src/modules/key_management/key_generation.py

"""
Key Generation Module for FractalAuth

This module provides functionalities to generate SSH key pairs securely.
Users can choose from predefined key types and sizes to ensure compatibility and security.
It also supports generating keys with optional passphrase protection to enhance security.
"""

import logging
from typing import Tuple, Optional
from .exceptions import UnsupportedAlgorithm  # Ensure this is your custom exception
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend

class KeyGenerator:
    def __init__(self):
        """
        Initialize the KeyGenerator with predefined valid key types and sizes.
        Sets up the logger for the module.
        """
        # Set up logging for the KeyGenerator module
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed trace

        # Create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Add formatter to ch
        ch.setFormatter(formatter)

        # Add ch to logger if not already added
        if not self.logger.handlers:
            self.logger.addHandler(ch)

        # Define a set of valid SSH key types and their corresponding valid sizes
        self.valid_key_types = {
            'RSA': [2048, 3072, 4096],
            'DSA': [1024, 2048],
            'ECDSA': [256, 384, 521],
            'ED25519': [256]  # ED25519 typically uses a fixed size
        }

        self.logger.info("KeyGenerator initialized with valid key types and sizes.")

    def list_valid_key_types(self) -> list:
        """
        List all valid SSH key types supported by FractalAuth.

        Returns:
            List[str]: A list of valid SSH key types.
        """
        self.logger.debug("Listing all valid SSH key types.")
        # Retrieve the keys from the valid_key_types dictionary
        key_types = list(self.valid_key_types.keys())
        self.logger.info(f"Valid SSH key types: {', '.join(key_types)}")
        return key_types

    def list_valid_key_sizes(self, key_type: str) -> list:
        """
        List all valid SSH key sizes for a given key type.

        Args:
            key_type (str): The type of SSH key (e.g., RSA, DSA).

        Returns:
            List[int]: A list of valid key sizes for the specified key type.

        Raises:
            UnsupportedAlgorithm: If the provided key_type is not supported.
        """
        self.logger.debug(f"Listing valid SSH key sizes for key type: {key_type}")

        # Validate the key_type
        if key_type not in self.valid_key_types:
            self.logger.error(f"Invalid key type requested: {key_type}")
            raise UnsupportedAlgorithm(
                f"Unsupported key type: {key_type}. Supported types are: {', '.join(self.valid_key_types.keys())}"
            )

        # Retrieve the list of valid key sizes for the given key_type
        key_sizes = self.valid_key_types[key_type]
        self.logger.info(f"Valid key sizes for {key_type}: {key_sizes}")
        return key_sizes

    def generate_key_pair(self, key_type: str, key_size: int, passphrase: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate an SSH key pair based on the specified type and size, with optional passphrase protection.

        Args:
            key_type (str): The type of SSH key to generate (e.g., RSA, DSA).
            key_size (int): The size of the SSH key in bits.
            passphrase (Optional[str]): An optional passphrase to protect the private key.

        Returns:
            Tuple[str, str]: A tuple containing the private key and public key as strings.

        Raises:
            UnsupportedAlgorithm: If the key_type or key_size is invalid or unsupported.
            Exception: If key generation fails due to underlying library errors.
        """
        self.logger.debug(
            f"Generating key pair with type: {key_type}, size: {key_size}, passphrase: {'Yes' if passphrase else 'No'}"
        )

        # Validate key_type and key_size using existing methods
        if not self.validate_key_type(key_type):
            self.logger.error(f"Invalid key type provided: {key_type}")
            raise UnsupportedAlgorithm(
                f"Invalid key type: {key_type}. Supported types are: {', '.join(self.valid_key_types.keys())}"
            )

        if not self.validate_key_size(key_type, key_size):
            self.logger.error(f"Invalid key size provided: {key_size} for key type: {key_type}")
            raise UnsupportedAlgorithm(
                f"Invalid key size: {key_size} for key type: {key_type}. Supported sizes are: {self.valid_key_types[key_type]}"
            )

        try:
            # Generate the SSH key pair based on key_type
            if key_type == 'RSA':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=default_backend()
                )
                self.logger.debug("RSA private key generated successfully.")
            elif key_type == 'DSA':
                private_key = dsa.generate_private_key(
                    key_size=key_size,
                    backend=default_backend()
                )
                self.logger.debug("DSA private key generated successfully.")
            elif key_type == 'ECDSA':
                # Map key_size to curve
                curve = self.get_ec_curve(key_size)
                private_key = ec.generate_private_key(
                    curve=curve,
                    backend=default_backend()
                )
                self.logger.debug("ECDSA private key generated successfully.")
            elif key_type == 'ED25519':
                private_key = ed25519.Ed25519PrivateKey.generate()
                self.logger.debug("ED25519 private key generated successfully.")
            else:
                self.logger.error(f"Unsupported key type encountered during generation: {key_type}")
                raise UnsupportedAlgorithm(f"Unsupported key type: {key_type}")

            # Serialize the private key with or without encryption
            if passphrase:
                encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
                self.logger.debug("Passphrase provided. Encrypting private key.")
            else:
                encryption_algorithm = serialization.NoEncryption()
                self.logger.debug("No passphrase provided. Serializing private key without encryption.")

            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            self.logger.debug("Private key serialized successfully.")

            if key_type in ['RSA', 'DSA', 'ECDSA']:
                pem_public = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                )
            elif key_type == 'ED25519':
                pem_public = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                )
  
                self.logger.debug("Public key serialized successfully.")

            self.logger.info(f"SSH key pair generation successful for type: {key_type}, size: {key_size}")
            return pem_private.decode('utf-8'), pem_public.decode('utf-8')

        except UnsupportedAlgorithm as e:
            self.logger.error(f"Key generation failed due to unsupported algorithm: {str(e)}")
            raise e
        except Exception as e:
            self.logger.error(f"Key generation failed: {str(e)}")
            raise Exception(f"Key generation failed: {str(e)}")

    def validate_key_type(self, key_type: str) -> bool:
        """
        Validate whether the provided key type is supported.

        Args:
            key_type (str): The SSH key type to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        is_valid = key_type in self.valid_key_types
        self.logger.debug(f"Validating key type: {key_type} - {'Valid' if is_valid else 'Invalid'}")
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
        try:
            valid_sizes = self.list_valid_key_sizes(key_type)
            is_valid = key_size in valid_sizes
            self.logger.debug(
                f"Validating key size: {key_size} for key type: {key_type} - {'Valid' if is_valid else 'Invalid'}"
            )
            return is_valid
        except UnsupportedAlgorithm:
            self.logger.error(f"Attempted to validate key size for unsupported key type: {key_type}")
            return False

    def get_ec_curve(self, key_size: int):
        """
        Get the elliptic curve corresponding to the key size for ECDSA keys.

        Args:
            key_size (int): The size of the ECDSA key in bits.

        Returns:
            EllipticCurve: The corresponding elliptic curve.

        Raises:
            UnsupportedAlgorithm: If the key_size does not correspond to a supported curve.
        """
        self.logger.debug(f"Mapping key size {key_size} to ECDSA curve.")
        # Map key_size to the appropriate elliptic curve
        if key_size == 256:
            self.logger.debug("Selected curve: SECP256R1")
            return ec.SECP256R1()
        elif key_size == 384:
            self.logger.debug("Selected curve: SECP384R1")
            return ec.SECP384R1()
        elif key_size == 521:
            self.logger.debug("Selected curve: SECP521R1")
            return ec.SECP521R1()
        else:
            self.logger.error(f"Unsupported ECDSA key size: {key_size}")
            raise UnsupportedAlgorithm(
                f"Unsupported ECDSA key size: {key_size}. Supported sizes are: {', '.join(map(str, self.valid_key_types['ECDSA']))}"
            )
