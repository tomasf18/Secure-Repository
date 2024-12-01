import os
from dotenv import load_dotenv
from .BaseDAO import BaseDAO
from server.models.database_orm import KeyStore
from server.utils.cryptography.AES import AES, AESModes
from sqlalchemy.exc import IntegrityError

load_dotenv()
class KeyStoreDAO(BaseDAO):
    
    def create(self, key: str, type: str) -> tuple[KeyStore, str] | KeyStore:
        """Create a new KeyStore entry."""
        try:
            if type in ["symmetric", "private"]:
                encrypted_key, iv = self.encrypt_key(key)
                key = encrypted_key.decode()
                iv = iv.decode()
                
            new_key = KeyStore(key=key, type=type)
            self.session.add(new_key)
            self.session.commit()
            
            return (new_key, iv) if type in ["symmetric", "private"] else new_key
        
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Key '{key}' already registered.")
    
    def get_by_id(self, key_id: int) -> "KeyStore":
        """Retrieve a KeyStore entry by its ID."""
        return self.session.query(KeyStore).get(key_id)
    
    
    def encrypt_key(self, key: str) -> tuple[bytes, bytes]:
        """
        Encrypt the key using AES256 with a derived key from the repository password.
        """
        
        aes = AES(AESModes.CBC)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = aes.derive_aes_key(repository_password)

        encrypted_key, iv = aes.encrypt_data(key, aes_key)

        return (encrypted_key, iv)


    def decrypt_key(self, encrypted_key: bytes, iv: bytes) -> str:
        """
        Decrypt the key using AES256 with a derived key from the repository password.
        """
        
        aes = AES(AESModes.CBC)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = aes.derive_aes_key(repository_password)
        decrypted_key = aes.decrypt_data(encrypted_key, aes_key, iv)

        return decrypted_key