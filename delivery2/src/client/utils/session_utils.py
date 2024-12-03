import sys
import json
import base64
import logging
import requests

from cryptography.hazmat.primitives.asymmetric import ec

from utils.cryptography.AES import AES
from utils.cryptography.ECC import ECC
from utils.constants.return_code import ReturnCode
from utils.cryptography.auth import sign, verify_signature
from utils.cryptography.integrity import calculate_digest, verify_digest

# -------------------------------

def exchange_keys(private_key: ec.EllipticCurvePrivateKey, data: dict, rep_address: str, rep_pub_key):
    """Exchange keys with the repository
    Sends the signed data (which includes the public key of the subject) to the server (endpoint rep_addr/sessions) and receives the public key of the server.
    
    Args:
        private_key (ec.EllipticCurvePrivateKey): Subject's private key associated with the public key registered by this subject in that organization
        data (dict): Data to be sent to the repository
        
    Returns:
        session_key: bytes: Derived key from the ECDH exchange (shared secret / session key)
        response_data: dict: Data received from the repository
    """
        
    ### HANDSHAKE ###
    ecdh = ECC()

    # Generate random Private Key and obtain Public Key
    _, session_public_key = ecdh.generate_keypair()
    session_public_key_str = base64.b64encode(session_public_key).decode('utf-8')

    # Create packet made of public key and data
    data = {
        "public_key" : session_public_key_str,
        **data
    }

    # Generate Signature 
    signature = sign(
        data = data,
        private_key = private_key
    )
        
    signature_str = base64.b64encode(signature).decode('utf-8')
        
    # Build Session creation packet
    body = {
        "data": data,
        "signature": signature_str
    }

    # Send to the server 
    response = requests.request("post", rep_address + "/sessions", json=body)
        
    if response.status_code not in [201]:
        logging.error(f"Error: Invalid repository response: {response}")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    logging.debug(f"Response from repository: {response}")

    # Verify if signature is valid from repository
    response = response.json()
    if (not verify_signature(response, rep_pub_key)):
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    # If it is valid, finish calculations
    response_data = response["data"]
    server_session_public_key = base64.b64decode(response_data["public_key"])
    session_key: bytes = ecdh.generate_shared_secret(server_session_public_key)

    return session_key, response_data
    
# -------------------------------

def encrypt_payload(data, message_key, mac_key):
    ## Encrypt data
    if isinstance(data, dict):
        data = json.dumps(data)

    encryptor = AES()
    encryptedData, dataIv = encryptor.encrypt_data(data, message_key)

    message = {
        "message": base64.b64encode(encryptedData).decode(),
        "iv" : base64.b64encode(dataIv).decode(),
    }

    digest = calculate_digest(encryptedData)
    mac, macIv = encryptor.encrypt_data(digest, mac_key)

    body = {
        "data": message,
        "signature": {
            "mac": base64.b64encode(mac).decode(),
            "iv": base64.b64encode(macIv).decode(),
        }
    }
    return body

# -------------------------------
    
def decrypt_payload(response, message_key, mac_key):
    encryptor = AES()
    receivedData = response["data"]
    receivedMac = response["signature"]
    
    ## Decrypt Digest
    receivedDigest = encryptor.decrypt_data(
        base64.b64decode(receivedMac["mac"]),
        base64.b64decode(receivedMac["iv"]),
        mac_key
    )
    
    encryptedMessage = base64.b64decode(receivedData["message"])
    ## Verify digest of received data
    if ( not verify_digest(encryptedMessage, receivedDigest) ):
        return None
    
    ## Decrypt data
    received_message = encryptor.decrypt_data(
        encrypted_data = base64.b64decode(receivedData["message"]),
        iv = base64.b64decode(receivedData["iv"]),
        key = message_key
    )
    return json.loads(received_message.decode())