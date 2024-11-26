import base64
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from utils.cryptography.ECC import ECC
from utils.cryptography.AES import AES

def sign_document(
        data: str, 
        private_key: ec.EllipticCurvePrivateKey, 
    ) -> bytes:

    return private_key.sign(
        data.encode(),
        ec.ECDSA(hashes.SHA256())
    )

def verify_doc_sign(response: dict[str, str], public_key: ec.EllipticCurvePublicKey) -> bool:
    msg = response["data"]
    digest = base64.b64decode(response["digest"])

    try:
        public_key.verify(
            digest, 
            str(msg).encode(), 
            ec.ECDSA(hashes.SHA256())
        )
        logging.info("Document signature is valid")
        return True
    except:
        logging.error("Document signature is not valid")
        return False