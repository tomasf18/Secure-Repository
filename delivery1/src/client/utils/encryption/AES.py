import os
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class AESModes:
    ECB = modes.ECB
    CBC = modes.CBC
    GCM = modes.GCM


class AES:
    def __init__(self, mode: AESModes = AESModes.CBC):
        self.mode = mode

    def encrypt_data(self, data: str, key: str) -> tuple[bytes, bytes]:
        """
        :param data: data to be encrypted
        :param key: key to encrypt data
        :return (encrypted_data, iv):
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES256.block_size).padder()
        padded_data = padder.update(data.encode())
        padded_data += padder.finalize()

        return (
            encryptor.update(padded_data) + encryptor.finalize(),
            iv
        )

    def decrypt_data(self, encrypted_data: str, iv: bytes, key: str) -> str:
        cipher = Cipher(algorithms.AES256(key), self.mode(iv))

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize() 

        unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def generate_random_key(self):
        return os.urandom(32)