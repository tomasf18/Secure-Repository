import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


from utils.encryption.ECDH import ECDH
from utils.encryption.AES import AES
from utils.files import read_private_key
from utils.digest import calculate_digest, verifyDigest
from utils.signing import sign_document, verify_doc_sign

def exchange_keys(client_session_key: bytes) -> tuple[bytes, bytes]:
    """
    :param client_key: Client known public key in order to verify signature
    :return (sessionKey, public_key): session key and public key in order for client to derive session key
    """
    ### HANDSHAKE ###
    KeyDerivation: ECDH = ECDH()

    ## Generate random private key
    public_key: bytes = KeyDerivation.generate_keys()

    ## Generate shared secred
    sessionKey: bytes = KeyDerivation.generate_shared_secret(client_session_key)

    return sessionKey, public_key


def encrypt_payload(data: dict | str, messageKey: bytes, MACKey: bytes) -> dict[str, dict]:
    """
    :param data: Payload to be sent
    :param messageKey: first part of session key, used to encrypt data
    :param MACKey: second part of session key, used to encrypt mac

    :return body: body to be sent, made of {
        data: {message, iv},
        digest: {mac, iv}
    }
    """
    ## Encrypt data
    encryptor = AES()
    encryptedData, dataIv = encryptor.encrypt_data(str(data), messageKey)

    message = {
        "message": encryptedData,
        "iv" : dataIv,
    }

    digest = calculate_digest(encryptedData)
    mac, macIv = encryptor.encrypt_data(digest, MACKey)

    body = {
        "data": message,
        "digest": {
            "mac": mac,
            "iv": macIv,
        }
    }
    return body
    
def decrypt_payload(response, messageKey: bytes, MACKey: bytes):
    """
    :param data: Payload received
    :param messageKey: first part of session key, used to encrypt data
    :param MACKey: second part of session key, used to encrypt mac
    :return receivedMessage: decrypted message sent
    """
    encryptor = AES()
    receivedData = response["data"]
    receivedMac = response["digest"]

    ## Decrypt Digest
    receivedDigest = encryptor.decrypt_data(
        base64.b64decode(receivedMac["mac"]),
        base64.b64decode(receivedMac["iv"]),
        MACKey
    )

    ## Verify digest of received data
    if ( not verifyDigest(receivedData, receivedDigest) ):
        return None
    
    ## Decrypt data
    receivedMessage = encryptor.decrypt_data(
        encrypted_data = base64.b64decode(receivedData["message"]),
        iv = base64.b64decode(receivedData["iv"]),
        key = messageKey
    )

    return receivedMessage

def verify_message_order(data: dict, counter: int, nonce: bytes) -> bool:
    received_nonce = base64.b64decode(data["nonce"])
    received_counter = data["counter"]

    return all([
        received_nonce == nonce,
        received_counter > counter
    ])