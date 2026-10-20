import pytest
from cryptManager import CryptManager


class TestSaltGeneration:

    def test_generate_salt_length(self):
        salt = CryptManager.generate_salt()
        assert len(salt) == CryptManager.SALT_LENGTH

    def test_generate_salt_is_bytes(self):
        salt = CryptManager.generate_salt()
        assert isinstance(salt, bytes)

    def test_generate_salt_is_random(self):
        # Two consecutive salts should not match
        s1 = CryptManager.generate_salt()
        s2 = CryptManager.generate_salt()
        assert s1 != s2


class TestKeyDerivation:

    def test_derive_key_length(self, sample_salt):
        key = CryptManager.derive_key("MyMasterPassword", sample_salt)
        assert len(key) == CryptManager.KEY_LENGTH

    def test_derive_key_is_deterministic(self, sample_salt):
        # Same password + same salt should always produce the same key
        k1 = CryptManager.derive_key("MyMasterPassword", sample_salt)
        k2 = CryptManager.derive_key("MyMasterPassword", sample_salt)
        assert k1 == k2

    def test_different_passwords_produce_different_keys(self, sample_salt):
        k1 = CryptManager.derive_key("password1", sample_salt)
        k2 = CryptManager.derive_key("password2", sample_salt)
        assert k1 != k2

    def test_different_salts_produce_different_keys(self):
        salt1 = b'\x01' * 32
        salt2 = b'\x02' * 32
        k1 = CryptManager.derive_key("samepass", salt1)
        k2 = CryptManager.derive_key("samepass", salt2)
        assert k1 != k2


class TestEncryptDecrypt:

    def test_encrypt_returns_dict_with_nonce_and_ciphertext(self, sample_key):
        result = CryptManager.encrypt_data("hello", sample_key)
        assert 'nonce' in result
        assert 'ciphertext' in result

    def test_encrypt_then_decrypt_round_trip(self, sample_key):
        plaintext = "MySecretVaultPassword123!"
        encrypted = CryptManager.encrypt_data(plaintext, sample_key)
        decrypted = CryptManager.decrypt_data(encrypted, sample_key)
        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext_each_call(self, sample_key):
        # Random nonce should make repeated encryptions differ
        c1 = CryptManager.encrypt_data("same", sample_key)
        c2 = CryptManager.encrypt_data("same", sample_key)
        assert c1['ciphertext'] != c2['ciphertext'] or c1['nonce'] != c2['nonce']

    def test_decrypt_with_wrong_key_fails(self, sample_key):
        encrypted = CryptManager.encrypt_data("secret", sample_key)
        wrong_key = b'\x99' * 32
        with pytest.raises(Exception):
            CryptManager.decrypt_data(encrypted, wrong_key)


class TestVerifyMasterPassword:

    def test_verify_correct_master_password(self, sample_salt):
        key = CryptManager.derive_key("correctPass", sample_salt)
        verification = CryptManager.encrypt_data("passmetric_ok", key)
        assert CryptManager.verify_master_password("correctPass", sample_salt, verification) is True

    def test_verify_incorrect_master_password(self, sample_salt):
        key = CryptManager.derive_key("correctPass", sample_salt)
        verification = CryptManager.encrypt_data("passmetric_ok", key)
        assert CryptManager.verify_master_password("wrongPass", sample_salt, verification) is False