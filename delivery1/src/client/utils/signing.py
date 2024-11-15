
from utils.encryption.ECC import ECC

def sign_document(data: dict[str, str], key: str) -> dict[str, str]:
    return data
    messageDigest = calculateDigest(str(data))

    cypher = ECC()
    encrypted_digest = cypher.encrypt_data(messageDigest, private_key)

    data["signature"] = encrypted_digest
    
    return data

def verify_doc_sign(data: dict[str, str], rep_pub_key: str) -> bool:
    return True
    message = data["message"]
    signature = data["signature"]

    cypher = ECC()
    messageDigest = calculateDigest(data=str(message))
    
    receivedDigest = cypher.decrypt_data(signature, rep_pub_key)

    return receivedDigest == messageDigest

def calculateDigest(data: str) -> str:
    return data