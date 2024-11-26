from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECC:
    def __init__(self, curve=ec.SECP521R1()):
        self.curve = curve

    def generate_keypair(self, password: str = None) -> tuple[str, str]:
        """ Generates an ECC keypair using the specified curve and password
        
        Args:
            password (str): password to protect the private key (if None, no password is used)

        Returns:
            tuple[str, str]: tuple containing the private and public keys in PEM format (serialized)
        """
        
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        password = password.encode() if password else None
        
        # Serialize private key with password protection
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )

        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem_private_key, pem_public_key
    
    def load_private_key(self, serialized_private_key: str, password: str = None) -> ec.EllipticCurvePrivateKey:
        """ Loads a private key from a serialized string
        
        Args:
            serialized_private_key (str): serialized private key
            password (str): password to decrypt the private key (if encrypted)
            
        Returns:
            ec.EllipticCurvePrivateKey: private key object
        """
        
        password = password.encode() if password else None
        private_key = serialization.load_pem_private_key(
            serialized_private_key,
            password=password if password else None
        )
        
        return private_key
    
    def load_public_key(self, serialized_public_key: str) -> ec.EllipticCurvePublicKey:
        """ Loads a public key from a serialized string
        
        Args:
            serialized_public_key (str): serialized public key
            
        Returns:
            ec.EllipticCurvePublicKey: public key object
        """
        
        public_key = serialization.load_pem_public_key(serialized_public_key)
        return public_key
         