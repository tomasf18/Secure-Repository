import os
import secrets
import base64

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
        
    def cbc_encrypt(self, data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """ Encrypts data using AES in CBC mode
        
        Args:
            data (bytes): data to be encrypted
            key (bytes): key to encrypt data
            
        Returns:
            tuple[bytes, bytes]: (encrypted_data, initialization_vector)
        """
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES256.block_size).padder()

        padded_data = padder.update(data)
        padded_data += padder.finalize()

        return (encryptor.update(padded_data) + encryptor.finalize(), iv)
        
# -------------------------------
        
    def cbc_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """ Decrypts data using AES in CBC mode
        
        Args:
            encrypted_data (bytes): data to be decrypted
            key (bytes): key to decrypt data
            iv (bytes): initialization vector

        Returns:
            bytes: decrypted data
        """
        
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize() 

        unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
# -------------------------------

    def encrypt_data(self, data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """ Encrypts data using AES in the selected mode

        Args:
            data (bytes): Data to be encrypted
            key (bytes): Key to encrypt data

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

    def decrypt_data(self, encrypted_data: bytes, key: bytes, iv: bytes = None, nonce: bytes = None) -> bytes:
        """ Decrypts data using AES in the selected mode
        
        Args:
            encrypted_data (bytes): Data to be decrypted
            key (bytes): Key to decrypt data
            iv (bytes): Initialization vector
            nonce (bytes): Nonce
        
        Returns:
            bytes: Decrypted data
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
    
def convert_str_to_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

file_name = "org1_28e863b2bc93af759f75b3e07ff4cc12b954a40324d3d27c4626c5ce8612dc8b.enc"

aes = AES(AESModes.CBC)

key = "4ShIS85+ebSlzCem/+h0xVmoVPWDfYXvNC1/zaEYMF0="
iv = "vh94hap0zgMltEzEmIrQcA=="

key_bytes = convert_str_to_bytes(key)
iv_bytes = convert_str_to_bytes(iv)

with open(file_name, "rb") as file:
    encrypted_data = file.read()
    
decrypted_data = aes.decrypt_data(encrypted_data, key_bytes, iv_bytes)

print(decrypted_data)