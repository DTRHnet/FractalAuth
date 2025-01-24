# Key Management Module Usage Guide

## 1. Summary

The **Key Management** module is a critical component of the **FractalAuth** authentication framework. It is responsible for the secure generation, validation, and storage of SSH key pairs. The module ensures that SSH keys are created with appropriate standards, validated for integrity and security, and stored in a manner that safeguards against unauthorized access. By adhering to SSH standards and implementing robust encryption mechanisms, the Key Management module plays a pivotal role in maintaining the overall security posture of FractalAuth.

## 2. Module Structure and Functionality

The Key Management module is organized into three primary Python files, each handling distinct aspects of key management:

- [`key_generation.py`](#key_generationpy)
- [`key_validation.py`](#key_validationpy)
- [`key_storage.py`](#key_storagepy)

### 2.1. `key_generation.py`

This file handles the creation of SSH key pairs, allowing users to specify key types and sizes, and optionally protect private keys with passphrases.

#### Functions

- **`__init__()`**
  
  Initializes the `KeyGenerator` class by setting up logging and defining supported SSH key types and their valid sizes.

- **`list_valid_key_types() -> list`**
  
  Returns a list of all supported SSH key types (e.g., RSA, DSA, ECDSA, ED25519).

- **`list_valid_key_sizes(key_type: str) -> list`**
  
  Given a specific `key_type`, returns a list of all valid key sizes. Raises a `ValueError` if the `key_type` is unsupported.

- **`generate_key_pair(key_type: str, key_size: int, passphrase: Optional[str] = None) -> Tuple[str, str]`**
  
  Generates an SSH key pair based on the specified `key_type` and `key_size`. If a `passphrase` is provided, the private key is encrypted accordingly. Returns the serialized private and public keys as strings.

- **`validate_key_type(key_type: str) -> bool`**
  
  Checks if the provided `key_type` is among the supported types.

- **`validate_key_size(key_type: str, key_size: int) -> bool`**
  
  Validates whether the specified `key_size` is valid for the given `key_type`.

- **`get_ec_curve(key_size: int)`**
  
  Maps an ECDSA `key_size` to its corresponding elliptic curve. Raises a `ValueError` if the `key_size` is unsupported.

### 2.2. `key_validation.py`

This file is dedicated to verifying the integrity and conformity of SSH keys, ensuring they meet predefined criteria and security standards.

#### Functions

- **`__init__(key_generator: KeyGenerator)`**
  
  Initializes the `KeyValidator` class with an instance of `KeyGenerator` to access supported key types and sizes. Sets up logging for validation processes.

- **`validate_key_type(key_type: str) -> bool`**
  
  Validates whether the provided `key_type` is supported by checking against the `KeyGenerator`'s configuration.

- **`validate_key_size(key_type: str, key_size: int) -> bool`**
  
  Validates whether the provided `key_size` is appropriate for the specified `key_type`.

- **`validate_private_key(private_key: str, passphrase: Optional[str] = None) -> bool`**
  
  Ensures that the private SSH key is of a supported type and size, and verifies that it is properly encrypted with a passphrase if one is provided.

- **`validate_public_key(public_key: str) -> bool`**
  
  Confirms that the public SSH key is of a supported type and size.

### 2.3. `key_storage.py`

This file manages the secure storage and retrieval of SSH keys, ensuring that private keys are encrypted and stored with appropriate permissions, while public keys are accessible as needed.

#### Functions

- **`__init__(storage_path: str = 'data/keys/', encryption_key: Optional[bytes] = None)`**
  
  Initializes the `KeyStorage` class by setting up logging, ensuring the storage directory exists, and initializing the encryption cipher suite using a provided key or environment variable.

- **`_derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes`**
  
  Derives a secure encryption key from a user-provided passphrase using PBKDF2HMAC with SHA256.

- **`_encrypt_key_with_passphrase(key: bytes, passphrase: str) -> bytes`**
  
  Encrypts a given key using a passphrase-derived encryption key. Prepends a random salt to the encrypted key for future decryption.

- **`_decrypt_key_with_passphrase(encrypted_key: bytes, passphrase: str) -> bytes`**
  
  Decrypts an encrypted key using a passphrase-derived encryption key by extracting the salt and deriving the key accordingly.

- **`_encrypt_key(key: bytes) -> bytes`**
  
  Encrypts a key using the main encryption cipher suite (`Fernet`).

- **`_decrypt_key(encrypted_key: bytes) -> bytes`**
  
  Decrypts an encrypted key using the main encryption cipher suite.

- **`store_private_key(private_key: str, filename: str = 'id_rsa', passphrase: Optional[str] = None)`**
  
  Securely stores the private SSH key by encrypting it with either a passphrase-derived key or the main encryption key. Saves the encrypted key to the specified filename with restrictive permissions.

- **`store_public_key(public_key: str, filename: str = 'id_rsa.pub')`**
  
  Stores the public SSH key without encryption, applying appropriate file permissions to allow read access.

- **`retrieve_private_key(filename: str = 'id_rsa', passphrase: Optional[str] = None) -> str`**
  
  Retrieves and decrypts the stored private SSH key using either a passphrase-derived key or the main encryption key.

- **`retrieve_public_key(filename: str = 'id_rsa.pub') -> str`**
  
  Retrieves the stored public SSH key.

- **`list_stored_keys() -> Dict[str, str]`**
  
  Lists all stored SSH keys, categorizing them as either public or private keys based on their filenames.

## 3. Best Practices for Implementation

To ensure the **Key Management** module operates securely and efficiently within the **FractalAuth** framework, adhere to the following best practices:

### 3.1. Secure Passphrase Handling

- **Use Secure Input Methods:**
  
  When accepting passphrases via command-line interfaces (CLI), utilize secure input methods like Python’s `getpass` to prevent passphrase echoing.

  ```python
  import getpass

  passphrase = getpass.getpass(prompt='Enter passphrase for private key (leave blank for no passphrase): ')
  if not passphrase:
      passphrase = None
  ```

## 3. Best Practices for Implementation

### 3.1. Secure Passphrase Handling

1. **Avoid Storing Passphrases:**
   
   Passphrases should never be stored in logs, files, or any persistent storage. Handle them securely in memory and clear them promptly after use.

### 3.2. Encryption Key Management

1. **Secure Storage of Master Encryption Key:**
   
   The master encryption key used by `KeyStorage` should be managed securely, preferably using environment variables or dedicated secret management services.

2. **Key Rotation:**
   
   Regularly rotate encryption keys to minimize the risk of compromised keys.

### 3.3. File Permissions

1. **Restrictive Permissions for Private Keys:**
   
   Ensure that private key files are stored with restrictive permissions (e.g., `600`) to prevent unauthorized access.

2. **Appropriate Permissions for Public Keys:**
   
   Public key files can have more permissive settings (e.g., `644`) to allow read access while restricting write permissions.

### 3.4. Error Handling

1. **Graceful Error Messages:**
   
   Provide clear and informative error messages without exposing sensitive information. Avoid revealing details about encryption failures or internal processes.

2. **Exception Management:**
   
   Catch and handle exceptions appropriately to maintain application stability and security.

### 3.5. Logging Practices

1. **Comprehensive Logging:**
   
   Implement detailed logging for all key management operations to facilitate monitoring and debugging.

2. **Sensitive Data Exclusion:**
   
   Ensure that sensitive information, such as private keys and passphrases, are never logged.

### 3.6. Compliance and Standards

1. **Adhere to SSH Standards:**
   
   Generate and serialize SSH keys using standard formats (e.g., PEM, OpenSSH) to ensure compatibility with existing SSH tools and services.

2. **Regular Security Audits:**
   
   Conduct periodic security audits to verify that key management practices comply with industry standards and best practices.

## 4. Unit Testing

Comprehensive unit testing is essential to ensure the reliability and security of the Key Management module. Below is a placeholder outline for unit testing:

### 4.1. Testing Framework

1. **Use Popular Testing Libraries:**
   
   Utilize testing frameworks like `unittest`, `pytest`, or `nose` for structuring and executing tests.

### 4.2. Test Cases

1. **Key Generation Tests:**
   - Verify that all supported key types and sizes can be generated successfully.
   - Test key generation with and without passphrase protection.
   - Ensure that invalid key types or sizes raise appropriate exceptions.

2. **Key Validation Tests:**
   - Validate correctly generated keys.
   - Test validation of malformed or corrupted keys.
   - Verify that passphrase protection is correctly enforced.

3. **Key Storage Tests:**
   - Ensure that private keys are stored encrypted when passphrases are provided.
   - Verify that public keys are stored without encryption.
   - Test retrieval of stored keys with correct and incorrect passphrases.
   - Check that file permissions are set correctly upon storage.

4. **Edge Case Tests:**
   - Handle scenarios with missing encryption keys.
   - Test behavior when storage directories are inaccessible.
   - Validate handling of exceptionally large keys.

### 4.3. Mocking and Isolation

1. **Mock File I/O:**
   
   Use mocking libraries like `unittest.mock` to simulate file operations, preventing actual disk writes during testing.

2. **Mock Environment Variables:**
   
   Mock environment variables to test encryption key retrieval without relying on actual environment configurations.

### 4.4. Example Test Structure

```python
import unittest
from unittest.mock import patch, mock_open
from key_management.key_generation import KeyGenerator
from key_management.key_validation import KeyValidator
from key_management.key_storage import KeyStorage
from cryptography.fernet import Fernet

class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.key_generator = KeyGenerator()
        self.key_validator = KeyValidator(self.key_generator)
        self.key_storage = KeyStorage(storage_path='test_keys/', encryption_key=Fernet.generate_key())

    def test_list_valid_key_types(self):
        expected_types = ['RSA', 'DSA', 'ECDSA', 'ED25519']
        self.assertListEqual(self.key_generator.list_valid_key_types(), expected_types)

    def test_generate_rsa_key_pair(self):
        private_key, public_key = self.key_generator.generate_key_pair('RSA', 2048)
        self.assertIn('BEGIN PRIVATE KEY', private_key)
        self.assertIn('ssh-rsa', public_key)

    # Additional test cases...

if __name__ == '__main__':
    unittest.main()
```

Note: The above is a simplified example. Comprehensive tests should cover all functionalities and edge cases.
5. Security Considerations

Ensuring the security of SSH keys is paramount. The following key points highlight critical security aspects of the Key Management module:
5.1. Encryption of Private Keys

    Robust Encryption Algorithms:

    Utilize strong encryption algorithms (e.g., AES-256 via Fernet) to protect private keys both at rest and in transit.

    Passphrase Protection:

    Offer optional passphrase protection for private keys, adding an extra layer of security in case of key exposure.

5.2. Secure Key Storage

    Isolation of Keys:

    Store keys in isolated directories with strict access controls to prevent unauthorized access.

    Regular Audits:

    Periodically audit key storage locations and permissions to ensure compliance with security policies.

5.3. Key Derivation Functions (KDFs)

    Use of KDFs:

    Employ secure Key Derivation Functions (e.g., PBKDF2HMAC with SHA256) to derive encryption keys from passphrases, mitigating the risk of brute-force attacks.

    Salting:

    Implement unique salts for each key derivation to prevent rainbow table attacks and ensure the uniqueness of derived keys.

5.4. Access Control

    Restrictive File Permissions:

    Set file permissions to restrict access to private keys (e.g., 600) and allow appropriate access for public keys (e.g., 644).

    Least Privilege Principle:

    Ensure that only authorized processes and users have access to key management functionalities and key storage locations.

5.5. Secure Handling of Sensitive Data

    Avoid Logging Sensitive Information:

    Ensure that sensitive data, such as private keys and passphrases, are never logged or exposed in error messages.

    In-Memory Security:

    Handle sensitive data securely in memory, ensuring that it is cleared promptly after use to prevent memory scraping attacks.

5.6. Environment Variable Security

    Protecting Encryption Keys:

    Store master encryption keys in secure environment variables or dedicated secret management systems, avoiding hardcoding them in the codebase.

    Access Restrictions:

    Limit access to environment variables containing sensitive information to authorized personnel and processes only.

5.7. Compliance and Standards

    Adherence to SSH Standards:

    Ensure that all SSH keys are generated, serialized, and stored in formats compliant with SSH protocol standards to maintain interoperability and security.

    Regular Security Updates:

    Keep all cryptographic libraries and dependencies up to date to protect against known vulnerabilities.

5.8. Monitoring and Incident Response

    Activity Logging:

    Maintain detailed logs of key management activities to monitor for suspicious behavior and facilitate incident response.

    Alerting Mechanisms:

    Implement alerting systems to notify administrators of unusual key management activities, such as failed decryption attempts or unauthorized access.