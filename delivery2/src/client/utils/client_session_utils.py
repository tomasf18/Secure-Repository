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
from utils.utils import convert_bytes_to_str, convert_str_to_bytes
from utils.cryptography.integrity import calculate_digest, verify_digest

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()

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

def encrypt_payload(data: dict | str, encryption_key: bytes, integrity_key: bytes) -> dict[str, dict]:
    """Encrypts the payload to be sent to the server
    
    Args:
        data (dict | str): Data to be sent
        encryption_key (bytes): first part of session key, used to encrypt data
        integrity_key (bytes): second part of session key, used to encrypt mac
        
    Returns:
        dict[str, dict]: Encrypted payload
    """
    
    # Encrypt data
    if isinstance(data, dict):
        data = json.dumps(data)

    encryptor = AES()
    encrypted_data, data_iv = encryptor.encrypt_data(data.encode(), encryption_key)

    data = {
        "message": base64.b64encode(encrypted_data).decode(),    # Data to be sent to the server
        "iv" : base64.b64encode(data_iv).decode(),               # IV used to encrypt the data
    }

    data_to_digest = (data["message"] + data["iv"]).encode()
    digest = calculate_digest(data_to_digest, integrity_key)

    body = {
        "data": data,
        "signature": convert_bytes_to_str(digest)
    }
    
    logger.debug(f"Encrypted payload: {body} with encryption key: {encryption_key} and integrity key: {integrity_key}")
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
    received_data = response["data"]
    received_mac = convert_str_to_bytes(response["signature"])
    
    message_str = received_data["message"]
    data_to_digest = (message_str + received_data["iv"]).encode()
    
    # Verify digest of received data and check integrity
    if ( not verify_digest(data_to_digest, received_mac, integrity_key) ):
        print("Digest verification failed")
        return None
    
    encrypted_message = convert_str_to_bytes(message_str)
    # Decrypt data
    received_message = encryptor.decrypt_data(
        encrypted_data=encrypted_message,
        key=encryption_key,
        iv=convert_str_to_bytes(received_data["iv"])
    )
    return json.loads(received_message.decode('utf-8'))