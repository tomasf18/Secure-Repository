from utils.file_operations import read_file

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

algorithm = hashes.SHA256()

class ECC:
    def __init__(self, curve=ec.SECP521R1()):
        self.curve = curve
        
# ------------------------------- ECC & ECDH methods ------------------------------- #

    def generate_keypair(self, password: str = None) -> tuple[bytes, bytes]:
        """ Generates an ECC keypair using the specified curve and password
        
        Args:
            password (str): password to protect the private key (if None, no password is used)

        Returns:
            tuple[str, str]: tuple containing the private and public keys in PEM format (serialized)
        """
        
        self.private_key = ec.generate_private_key(self.curve)
        public_key = self.private_key.public_key()
        password = password.encode() if password else None
        
        # Serialize private key with password protection
        pem_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )

        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem_private_key, pem_public_key
        
# -------------------------------
        
    def generate_shared_secret(self, peer_public_key: bytes):
        """ Generates a shared secret using the provided peer public key
        
        Args:
            peer_public_key (bytes): public key of the peer to generate the shared secret with
            
        Returns:
            bytes: shared secret 
            
        """
        
        if self.private_key is None:
            raise Exception("No private key has been generated yet!")
        
        peer_public_key_ecc = serialization.load_pem_public_key(peer_public_key)

        self.shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key_ecc)
        
        self.derived_key = HKDF(
            algorithm=algorithm,
            length=64, # So then I can use 32 bytes for the encryption key and 32 bytes for the MAC (integrity) key
            salt=None,
            info=b''
        ).derive(self.shared_key)

        return self.derived_key
    
# ------------------------------- Static methods ------------------------------- #
    
    @staticmethod
    def load_private_key(serialized_private_key: str, password: str = None) -> ec.EllipticCurvePrivateKey:
        """ Loads a private key from a serialized string
        
        Args:
            serialized_private_key (str): serialized private key
            password (str): password to decrypt the private key (if encrypted)
            
        Returns:
            ec.EllipticCurvePrivateKey: private key object
        """
        
        # Private key is a string, so we need to convert it to bytes
        serialized_private_key = serialized_private_key.encode()
        password = password.encode() if password else None
        private_key = serialization.load_pem_private_key(
            serialized_private_key,
            password=password if password else None
        )
        
        return private_key
    
# -------------------------------
    
    @staticmethod
    def load_public_key(serialized_public_key: str) -> ec.EllipticCurvePublicKey:
        """ Loads a public key from a serialized string
        
        Args:
            serialized_public_key (str): serialized public key
            
        Returns:
            ec.EllipticCurvePublicKey: public key object
        """
        
        # Public key is a string, so we need to convert it to bytes
        public_key = serialization.load_pem_public_key(serialized_public_key.encode())
        return public_key
    
# -------------------------------
    
    @staticmethod
    def read_public_key(key_file: str) -> ec.EllipticCurvePublicKey:
        """ Reads a public key from a file

        Args:
            key_file (str): path to the file containing the public key

        Returns:
            ec.EllipticCurvePublicKey: public key object
        """
        
        serialized_public_key = read_file(key_file)
        return ECC.load_public_key(serialized_public_key)

# -------------------------------

    @staticmethod
    def read_private_key(key_file: str, password: str) -> ec.EllipticCurvePrivateKey:
        """ Reads a private key from a file
        
        Args:
            key_file (str): path to the file containing the private key
            password (str): password to decrypt the private key
            
        Returns:
            ec.EllipticCurvePrivateKey: private key object
        """
        
        serialized_private_key = read_file(key_file)
        return ECC.load_private_key(serialized_private_key, password)
    
         