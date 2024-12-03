import json
import base64

from utils.cryptography.ECC import ECC
from utils.cryptography.AES import AES
from utils.cryptography.integrity import calculate_digest, verify_digest

# -------------------------------

def exchange_keys(client_session_public_key: bytes) -> tuple[bytes, bytes]:
    """Exchange keys with the client
    Generates the shared secret (session key) from the client's public key

    Args:
        client_session_public_key (bytes): _description_

    Returns:
        tuple[bytes, bytes]: _description_
    """
    
    ### HANDSHAKE ###
    ecdh = ECC()

    # Generate random Private Key and obtain Public Key
    _, session_server_public_key = ecdh.generate_keypair()

    # Generate shared secred
    session_key: bytes = ecdh.generate_shared_secret(client_session_public_key)
    
    return session_key, session_server_public_key

# -------------------------------

def encrypt_payload(data: dict | str, encryption_key: bytes, integrity_key: bytes) -> dict[str, dict]:
    """Encrypts the payload to be sent to the client
    
    Args:
        data (dict | str): Data to be sent
        encryption_key (bytes): first part of session key, used to encrypt data
        integrity_key (bytes): second part of session key, used to encrypt mac
        
    Returns:
        dict[str, dict]: Encrypted payload
    """
    
    if isinstance(data, dict):
        data = json.dumps(data)

    ## Encrypt data
    encryptor = AES()
    encryptedData, dataIv = encryptor.encrypt_data(data, encryption_key)

    message = {
        "message": base64.b64encode(encryptedData).decode(),
        "iv" : base64.b64encode(dataIv).decode(),
    }

    digest = calculate_digest(encryptedData)
    mac, macIv = encryptor.encrypt_data(digest, integrity_key)

    body = {
        "data": message,
        "signature": {
            "mac": base64.b64encode(mac).decode(),
            "iv": base64.b64encode(macIv).decode(),
        }
    }
    return body
    
# -------------------------------
    
def decrypt_payload(response, encryption_key: bytes, integrity_key: bytes):
    """ Decrypts the payload received from the client
    
    Args:
        response: Response from the client
        encryption_key: first part of session key, used to encrypt data
        integrity_key: second part of session key, used to encrypt mac
    
    Returns:
        dict: Decrypted payload
    """
    
    encryptor = AES()
    receivedData = response["data"]
    receivedMac = response["signature"]

    ## Decrypt Digest
    receivedDigest = encryptor.decrypt_data(
        base64.b64decode(receivedMac["mac"]),
        base64.b64decode(receivedMac["iv"]),
        integrity_key
    )

    encryptedMessage = base64.b64decode(receivedData["message"])
    ## Verify digest of received data
    if ( not verify_digest(encryptedMessage, receivedDigest) ):
        return None
    
    ## Decrypt data
    receivedMessage = encryptor.decrypt_data(
        encrypted_data = base64.b64decode(receivedData["message"]),
        iv = base64.b64decode(receivedData["iv"]),
        key = encryption_key
    )

    return json.loads(receivedMessage.decode('utf-8'))

# -------------------------------

def verify_message_order(data: dict, counter: int, nonce: bytes) -> bool:
    """Verify the order of the messages received from the client to prevent replay attacks
    
    Args:
        data (dict): Data received from the client
        counter (int): Counter of the last message received
        nonce (bytes): Nonce of the last message received
        
    Returns:
        bool: True if the message is valid, False otherwise
    """
    
    received_nonce = data["nonce"]
    received_counter = data["counter"]

    print(f"nonce: {received_nonce}, counter: {received_counter}, nonce: {nonce}, counter: {counter}")
    return all([
        received_nonce == nonce,
        received_counter > counter
    ])