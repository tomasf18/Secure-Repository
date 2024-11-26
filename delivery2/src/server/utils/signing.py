import base64
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from utils.encryption.ECC import ECC
from utils.encryption.AES import AES

def sign_document(
        data: str, 
        private_key: ec.EllipticCurvePrivateKey
    ) -> bytes:

    return private_key.sign(
        data.encode(),
        ec.ECDSA(hashes.SHA256())
    )

def verify_doc_sign(data: dict[str, str], pub_key: bytes) -> bool:
    msg = data["data"]

    digest = base64.b64decode(data["digest"])

    public_key = serialization.load_pem_public_key(pub_key)

    try:
        public_key.verify(
            digest, 
            str(msg).encode(), 
            ec.ECDSA(hashes.SHA256())
        )
        logging.debug("Document signature is valid")
        return True
    except:
        logging.debug("Document signature is not valid")
        return False