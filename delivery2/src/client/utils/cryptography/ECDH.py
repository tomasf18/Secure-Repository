from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


# Generate a private key for use in the exchange.
class ECDH:
    def generate_keys(self) -> bytes:
        """ Generates a private key and returns the public key

        Returns:
            bytes: public key in PEM format
        """
        
        self.private_key = ec.generate_private_key(
            ec.SECP521R1()
        )
        
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_key
        

    def generate_shared_secret(self, peer_public_key: bytes):
        """ Returns derived key """
        if self.private_key is None:
            raise Exception("No private key has been generated yet!")
        
        public_key = serialization.load_pem_public_key(peer_public_key)

        self.shared_key = self.private_key.exchange(
            ec.ECDH(), 
            public_key
        )
        
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b''
        ).derive(self.shared_key)

        return self.derived_key