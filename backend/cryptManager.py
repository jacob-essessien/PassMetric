import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

class CryptManager:
    # Argon2id parameters (OWASP recommended values)
    ARGON2_TIME_COST = 2        # Number of iterations
    ARGON2_MEMORY_COST = 65536  # Memory usage in KiB (64 MB)
    ARGON2_PARALLELISM = 1      # Number of parallel threads

    SALT_LENGTH = 32  # 256 bits
    KEY_LENGTH = 32   # 256 bits for AES-256



    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(CryptManager.SALT_LENGTH)
    
    # Derive encryption key from master password using Argon2id
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
                secret=master_password.encode('utf-8'),
                salt=salt,
                time_cost=CryptManager.ARGON2_TIME_COST,
                memory_cost=CryptManager.ARGON2_MEMORY_COST,
                parallelism=CryptManager.ARGON2_PARALLELISM,
                hash_len=CryptManager.KEY_LENGTH,
                type=Type.ID)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> dict:
        nonce = os.urandom(12) # AES-GCM standard nonce size
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    @staticmethod
    def decrypt_data(encrypted_data: dict, key: bytes) -> str:
        nonce = base64.b64decode(encrypted_data['nonce']) 
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        aesgcm = AESGCM(key)

        # Decrypt and verify authentication tag
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    
    @staticmethod
    def verify_master_password(master_password: str, salt: bytes, verification_data: dict) -> bool:
        try:
            key = CryptManager.derive_key(master_password, salt)
            CryptManager.decrypt_data(verification_data, key)
            return True
        except Exception:
            return False
