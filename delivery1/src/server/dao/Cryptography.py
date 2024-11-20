import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class Cryptography:
    @staticmethod
    def aes_ecb_encrypt(data_to_encrypt, key=None):
        if key is None:
            key = secrets.token_bytes(32)

        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_to_encrypt) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data, key

    @staticmethod
    def aes_ecb_decrypt(encrypted_data, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    @staticmethod
    def aes_cbc_encrypt(data_to_encrypt, iv=None, key=None):
        if iv is None:
            iv = os.urandom(16)
        if key is None:
            key = secrets.token_bytes(32)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_to_encrypt) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data, key, iv

    @staticmethod
    def aes_cbc_decrypt(encrypted_data, iv, key):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    @staticmethod
    def aes_ofb_encrypt(data_to_encrypt, iv=None, key=None):
        if iv is None:
            iv = os.urandom(16)
        if key is None:
            key = secrets.token_bytes(32)

        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(data_to_encrypt) + encryptor.finalize()

        return encrypted_data, key, iv

    @staticmethod
    def aes_ofb_decrypt(encrypted_data, iv, key):
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data

    @staticmethod
    def encrypt(data_to_encrypt, algorithm='AES', mode='CBC'):
        if algorithm == 'AES':
            if mode == 'ECB':
                return Cryptography.aes_ecb_encrypt(data_to_encrypt)
            elif mode == 'CBC':
                return Cryptography.aes_cbc_encrypt(data_to_encrypt)
            elif mode == 'OFB':
                return Cryptography.aes_ofb_encrypt(data_to_encrypt)
            else:
                raise ValueError("Unsupported mode.")
        else:
            raise ValueError("Unsupported algorithm.")

    @staticmethod
    def decrypt(encrypted_data, algorithm='AES', mode='CBC', key=None, iv=None):
        if algorithm == 'AES':
            if mode == 'ECB':
                return Cryptography.aes_ecb_decrypt(encrypted_data, key)
            elif mode == 'CBC':
                return Cryptography.aes_cbc_decrypt(encrypted_data, iv, key)
            elif mode == 'OFB':
                return Cryptography.aes_ofb_decrypt(encrypted_data, iv, key)
            else:
                raise ValueError("Unsupported mode.")
        else:
            raise ValueError("Unsupported algorithm.")
