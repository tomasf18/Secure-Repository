from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from .encryption import AssymmetricEncryption

class ECC(AssymmetricEncryption):
    def __init__(self, curve=None):
        self.curve = curve or ec.SECP521R1()

    def generate_keypair(self, password: str):
        """Generates a keypair using the given password

        Args:
            password (str): password to generate keypair
        """
        
        # Generate a random private key for the curve instance
        private_key = ec.generate_private_key(self.curve) # This is a 521-bit random integer
    
        # From that private key, we generate the public key
        public_key = private_key.public_key()
        
        # Serialize private key with password protection
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        # The public key is serialized as follows:
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem_private_key, pem_public_key

    def encrypt_data(self, data: str, key: str) -> str:
        pass

    def decrypt_data(self, encrypted_data: str, key: str) -> str:
        pass