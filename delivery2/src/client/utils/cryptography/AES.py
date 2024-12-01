import os
import secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESModes:
    CBC = modes.CBC
    # GCM = modes.GCM


class AES:
    def __init__(self, mode: AESModes = AESModes.CBC):
        self.mode = mode
        
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
    

    def encrypt_data(self, data: str, key: str) -> tuple[bytes, bytes]:
        if self.mode == AESModes.CBC:
            return self.cbc_encrypt(data, key)
        # elif self.mode == AESModes.GCM:
        #     return self.gcm_encrypt(data, key)
        else:
            print("Unsupported mode for AES.")
            return None, None, None

    def decrypt_data(self, encrypted_data: str, key: str, iv: bytes = None, nonce: bytes = None) -> str:
        if self.mode == AESModes.CBC:
            return self.cbc_decrypt(encrypted_data, key, iv)
        # elif self.mode == AESModes.GCM:
        #     return self.gcm_decrypt(encrypted_data, key, nonce)
        else:
            print("Unsupported mode for AES.")
            return None

    def generate_random_key(self):
        return secrets.token_bytes(32)
