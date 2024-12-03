import base64
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

# -------------------------------

hashing_algorithm = hashes.SHA256()

# -------------------------------

def sign(data: dict, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Signs a document using the provided private key and returns the signature.
    Elliptic Curve Digital Signature Algorithm (ECDSA) is used with SHA256 as the hashing algorithm.
    
    Args:
        data (str): Data to be signed
        private_key (ec.EllipticCurvePrivateKey): Private key to sign the data
        
    Returns:
        bytes: Signature of the data 
    
    """
    
    data_str = str(data)

    signature = private_key.sign(
        data_str.encode(),
        ec.ECDSA(hashing_algorithm)
    )
    return signature

# -------------------------------

def verify_signature(response: dict[str, str], public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verifies the signature of a document using the provided public key.
    
    Args:
        response (dict): Response from the server containing the data and signature
        public_key (ec.EllipticCurvePublicKey): Public key to verify the signature
        
    Returns:
        bool: True if the signature is valid, False otherwise 
    
    """
    
    data_str = str(response["data"])
    signature = base64.b64decode(response["signature"])

    try:
        public_key.verify(signature, data_str.encode(), ec.ECDSA(hashing_algorithm))
        logging.info("Document signature is valid")
        return True
    except InvalidSignature:
        logging.error("Document signature is not valid")
        return False