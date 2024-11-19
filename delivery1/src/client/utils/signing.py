from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from utils.encryption.ECC import ECC
from utils.encryption.AES import AES

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
    digest = response["digest"]

    return public_key.verify(
        digest, 
        msg, 
        ec.ECDSA(hashes.SHA256())
    )