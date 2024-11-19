import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from utils.encryption.ECC import ECC
from utils.encryption.AES import AES

def sign_document(
        data: str, 
        private_key: str = None,
        password: str = None,
    ) -> bytes:
    key = serialization.load_pem_private_key(private_key.encode(), password=password.encode())

    return key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

def verify_doc_sign(data: dict[str, str], pub_key: str) -> bool:
    msg = data["data"]
    digest = base64.b64decode(data["digest"])

    print("got digest: ", digest)

    public_key = serialization.load_pem_public_key(pub_key.encode())

    try:
        public_key.verify(
            digest, 
            msg, 
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False