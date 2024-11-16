from .encryption import AssymmetricEncryption
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def AESModes(Enum):
    ECB = modes.ECB
    CBC = modes.CBC
    GCM = modes.GCM

    @property
    def mode(self):
        return self.value()


class AES(AssymmetricEncryption):
    def __init__(self, mode: AESModes):
        self.mode = AESModes.mode

    def generate_keypair(self):
        pass

    def encrypt_data(self, data: str, key: str) -> str:
        pass

    def decrypt_data(self, encrypted_data: str, key: str) -> str:
        pass
