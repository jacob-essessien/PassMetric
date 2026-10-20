import os
import sys
import pytest

# Make the backend package importable from /tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..',)))

@pytest.fixture
def sample_key():
    return b'\x01' * 32


@pytest.fixture
def sample_salt():
    return b'\x02' * 32
