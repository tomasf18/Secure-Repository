import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESModes:
    CBC = modes.CBC
    # GCM = modes.GCM

# -------------------------------

class AES:
    def __init__(self, mode: AESModes = AESModes.CBC):
        self.mode = mode
      
# -------------------------------
        
    def cbc_encrypt(self, data: str, key: str) -> tuple[bytes, bytes]:
        """ Encrypts data using AES in CBC mode
        
        Args:
            data (str): data to be encrypted
            key (str): key to encrypt data
            
        Returns:
            tuple[bytes, bytes]: (encrypted_data, initialization_vector)
        """
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES256.block_size).padder()
        if (type(data) == str):
            data = data.encode()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        return (encryptor.update(padded_data) + encryptor.finalize(), iv)
        
# -------------------------------
        
    def cbc_decrypt(self, encrypted_data: str, key: str, iv: bytes) -> str:
        """ Decrypts data using AES in CBC mode
        
        Args:
            encrypted_data (str): data to be decrypted
            key (str): key to decrypt data
            iv (bytes): initialization vector

        Returns:
            str: decrypted data
        """
        
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize() 

        unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
# -------------------------------

    def encrypt_data(self, data: str, key: str) -> tuple[bytes, bytes]:
        """ Encrypts data using AES in the selected mode

        Args:
            data (str): Data to be encrypted
            key (str): Key to encrypt data

        Returns:
            tuple[bytes, bytes]: (encrypted_data, initialization_vector) 
        """
        if self.mode == AESModes.CBC:
            return self.cbc_encrypt(data, key)
        # elif self.mode == AESModes.GCM:
        #     return self.gcm_encrypt(data, key)
        else:
            print("Unsupported mode for AES.")
            return None, None

# -------------------------------

    def decrypt_data(self, encrypted_data: str, key: str, iv: bytes = None, nonce: bytes = None) -> str:
        """ Decrypts data using AES in the selected mode
        
        Args:
            encrypted_data (str): Data to be decrypted
            key (str): Key to decrypt data
            iv (bytes): Initialization vector
            nonce (bytes): Nonce
        
        Returns:
            str: Decrypted data
        """
        
        if self.mode == AESModes.CBC:
            return self.cbc_decrypt(encrypted_data, key, iv)
        # elif self.mode == AESModes.GCM:
        #     return self.gcm_decrypt(encrypted_data, key, nonce)
        else:
            print("Unsupported mode for AES.")
            return None

# -------------------------------

    def generate_random_key(self):
        """ Generates a random 32-byte key using a secure source.
        
        Returns:
            bytes: Random key
        """
        
        return secrets.token_bytes(32)
# -------------------------------

    def derive_aes_key(self, password: str) -> bytes:
        """ Derive a secure AES key from the repository password using PBKDF2.

        Args:
            password (str): Password to derive the key from 
            
        Returns:
            bytes: Derived AES key
        """
        
        # Generate a salt (e.g., from a secure source)
        salt = 'salt'.encode()

        # Use PBKDF2 to derive the AES key
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode())