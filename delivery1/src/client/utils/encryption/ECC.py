from .encryption import AssymmetricEncryption

class ECC(AssymmetricEncryption):
    def __init__(self):
        pass

    def generate_keypair(self):
        pass

    def encrypt_data(self, data: str, key: str) -> str:
        pass

    def decrypt_data(self, encrypted_data: str, key: str) -> str:
        pass