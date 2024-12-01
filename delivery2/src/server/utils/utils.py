import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


from utils.cryptography.ECDH import ECDH
from utils.cryptography.AES import AES
from utils.cryptography.ECC import ECC
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
    if isinstance(data, dict):
        data = json.dumps(data)

    ## Encrypt data
    encryptor = AES()
    encryptedData, dataIv = encryptor.encrypt_data(data, messageKey)

    message = {
        "message": base64.b64encode(encryptedData).decode(),
        "iv" : base64.b64encode(dataIv).decode(),
    }

    digest = calculate_digest(encryptedData)
    mac, macIv = encryptor.encrypt_data(digest, MACKey)

    body = {
        "data": message,
        "digest": {
            "mac": base64.b64encode(mac).decode(),
            "iv": base64.b64encode(macIv).decode(),
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

    encryptedMessage = base64.b64decode(receivedData["message"])
    ## Verify digest of received data
    if ( not verifyDigest(encryptedMessage, receivedDigest) ):
        return None
    
    ## Decrypt data
    receivedMessage = encryptor.decrypt_data(
        encrypted_data = base64.b64decode(receivedData["message"]),
        iv = base64.b64decode(receivedData["iv"]),
        key = messageKey
    )

    return json.loads(receivedMessage.decode('utf-8'))

def verify_message_order(data: dict, counter: int, nonce: bytes) -> bool:
    received_nonce = data["nonce"]
    received_counter = data["counter"]


    print(f"nonce: {received_nonce}, counter: {received_counter}, nonce: {nonce}, counter: {counter}")
    return all([
        received_nonce == nonce,
        received_counter > counter
    ])