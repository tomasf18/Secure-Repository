from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


from utils.encryption.ECDH import ECDH
from utils.encryption.AES import AES
from utils.files import read_private_key
from utils.digest import calculateDigest, verifyDigest
from utils.signing import sign_document, verify_doc_sign

def exchangeKeys(client_session_key: bytes) -> tuple[bytes, bytes]:
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


def encryptPayload(data: dict | str, messageKey: bytes, MACKey: bytes) -> dict[str, dict]:
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
    encryptedData, dataIv = encryptor.encrypt_data(data, messageKey)

    message = {
        "message": encryptedData,
        "iv" : dataIv,
    }

    digest = calculateDigest(encryptedData)
    mac, macIv = encryptor.encrypt_data(digest, MACKey)

    body = {
        "data": message,
        "digest": {
            "mac": mac,
            "iv": macIv,
        }
    }
    return body
    
def decryptPayload(response, messageKey: bytes, MACKey: bytes):
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
        receivedMac["mac"],
        receivedMac["iv"],
        MACKey
    )

    ## Verify digest of received data
    if ( not verifyDigest(receivedData, receivedDigest) ):
        return None
    
    ## Decrypt data
    receivedMessage = encryptor.decrypt_data(
        encrypted_data=receivedData["message"],
        iv = receivedData["iv"],
        key = messageKey
    )

    return receivedMessage