# tests/conftest.py

import pytest
from key_management.key_generation import KeyGenerator
from key_management.key_validation import KeyValidator
from key_management.key_storage import KeyStorage
from cryptography.fernet import Fernet

@pytest.fixture(scope='session')
def encryption_key():
    return Fernet.generate_key()

@pytest.fixture
def key_storage(encryption_key):
    return KeyStorage(storage_path='integration_test_keys/', encryption_key=encryption_key)

@pytest.fixture
def key_generator():
    return KeyGenerator()

@pytest.fixture
def key_validator(key_generator):
    return KeyValidator(key_generator)
