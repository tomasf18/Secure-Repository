from abc import ABC, abstractmethod

class Encryption(ABC):
    def encrypt_data(self, data: str, key: str) -> str:
        pass

    def decrypt_data(self, encrypted_data: str, key: str) -> str:
        pass

class AssymmetricEncryption(Encryption):
    @abstractmethod
    def generate_keypair(self):
        pass

class SymmetricEncryption(Encryption):
    @abstractmethod
    def encrypt_data(self, data, key):
        return super().encrypt_data(data, key)