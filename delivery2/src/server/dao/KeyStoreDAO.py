import os
import secrets
from dotenv import load_dotenv

from .BaseDAO import BaseDAO
from models.database_orm import KeyStore
from sqlalchemy.exc import IntegrityError
from utils.cryptography.AES import AES, AESModes

load_dotenv()
class KeyStoreDAO(BaseDAO):
    
# -------------------------------
    
    def create(self, key: bytes, type: str) -> tuple[KeyStore, bytes, bytes] | KeyStore:
        """Create a new KeyStore entry."""
        try:
            if type in ["symmetric", "private"]:
                key, iv, salt = self.encrypt_key(key)
                
            new_key = KeyStore(key=key, type=type)
            self.session.add(new_key)
            self.session.commit()
            
            return (new_key, iv, salt) if type in ["symmetric", "private"] else new_key
        
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Key '{key}' already registered.")
    
    def get_by_id(self, key_id: int) -> "KeyStore":
        """Retrieve a KeyStore entry by its ID."""
        return self.session.query(KeyStore).get(key_id)
    
# -------------------------------
    
    def encrypt_key(self, key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt the key using AES256 with a derived key from the repository password.
        """
        
        aes = AES(AESModes.CBC)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        salt = secrets.token_bytes(16)
        aes_key = aes.derive_aes_key(repository_password, salt)

        encrypted_key, iv = aes.encrypt_data(key, aes_key)

        return (encrypted_key, iv, salt)

# -------------------------------

    def decrypt_key(self, encrypted_key: bytes, iv: bytes, salt: str) -> bytes:
        """
        Decrypt the key using AES256 with a derived key from the repository password.
        """
        
        aes = AES(AESModes.CBC)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = aes.derive_aes_key(repository_password, salt)
        decrypted_key = aes.decrypt_data(encrypted_key, aes_key, iv)

        return decrypted_key