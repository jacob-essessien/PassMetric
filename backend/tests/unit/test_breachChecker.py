import os
import pytest
from breachChecker import BreachChecker


@pytest.fixture
def fake_dataset(tmp_path):
    # Creates a small temporary breach dataset for testing
    dataset = tmp_path / "fake_breach.txt"
    dataset.write_text("password\n123456\nqwerty\nletmein\nhello\n")
    return str(dataset)


class TestBreachCheckerInit:

    def test_default_dataset_path(self):
        checker = BreachChecker()
        # Default should point alongside breachChecker.py
        assert checker.dataset_path.endswith('rockyou.txt')

    def test_custom_dataset_path(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        assert checker.dataset_path == fake_dataset

    def test_initial_state_not_loaded(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        assert checker.is_loaded is False
        assert checker.total_passwords == 0


class TestLoadDataset:

    def test_load_valid_dataset(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        result = checker.load_dataset()
        assert result is True
        assert checker.is_loaded is True
        assert checker.total_passwords == 5

    def test_load_missing_dataset_returns_false(self, tmp_path):
        checker = BreachChecker(dataset_path=str(tmp_path / "missing.txt"))
        assert checker.load_dataset() is False
        assert checker.is_loaded is False

    def test_load_is_idempotent(self, fake_dataset):
        # Loading twice should not double-count
        checker = BreachChecker(dataset_path=fake_dataset)
        checker.load_dataset()
        first_total = checker.total_passwords
        checker.load_dataset()
        assert checker.total_passwords == first_total


class TestIsBreached:

    def test_known_breached_password_is_detected(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        checker.load_dataset()
        is_breached, msg = checker.is_breached("password")
        assert is_breached is True
        assert msg is not None
        assert "leaked passwords" in msg

    def test_unknown_password_is_not_breached(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        checker.load_dataset()
        is_breached, msg = checker.is_breached("ThisIsAUniquePass!2099")
        assert is_breached is False
        assert msg is None

    def test_check_when_dataset_not_loaded(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        is_breached, msg = checker.is_breached("password")
        assert is_breached is False
        assert msg is None

    def test_hash_consistency(self, fake_dataset):
        checker = BreachChecker(dataset_path=fake_dataset)
        h1 = checker._hash_password("password")
        h2 = checker._hash_password("password")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest length