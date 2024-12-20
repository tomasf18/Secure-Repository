import sys
import json
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


def anonymous_request(rep_pub_key, method, rep_address, endpoint, data=None) -> tuple[requests.Response, dict]:
    encryption_key, client_ephemeral_public_key = exchange_anonymous_keys(rep_address, endpoint, method, rep_pub_key)
    
    if not data:
        data = {}
    
    data = encrypt_anonymous(data, encryption_key, client_ephemeral_public_key)
    
    logging.info("\nENCRYPTED_DATA: ", data, "\n\n\n")
    logging.info(f"Sending ({method}) to \'{endpoint}\' with data= \"{data}\"")
    
    response = requests.request(method, rep_address + endpoint, json=data)
    logging.info(f"response= {response}")
    response_json = response.json()

    if "error" in response_json:
        return response, response_json

    encrypted_data = convert_str_to_bytes(response_json.get("data"))
    iv = convert_str_to_bytes(response_json.get("iv"))
    
    logging.info("\n\n\nENCRYPTED_DATA: ", encrypted_data, "")
    logging.info("\nENCRYPTION_KEY: ", encryption_key)
    logging.info("\nIV:\n", iv, "\n\n\n")


    return response, json.loads(decrypt_anonymous(encrypted_data, encryption_key, iv).decode())

# -------------------------------

def exchange_anonymous_keys(rep_address: str, endpoint: str, method: str, rep_pub_key: bytes):
    """Exchange keys with the repository
    Sends the ephemeral public key of the subject to the server (endpoint rep_addr/sessions) and receives the ephemeral public key from the server.
    
    Args:
        rep_address (str): Repository address
        rep_pub_key (bytes): Public key of the repository
        
    Returns:
        encryption_key: bytes: Derived key from the ECDH exchange (shared secret / session key)
        response_data: dict: Data received from the repository
    """
    
    ecdh = ECC()
    _, client_ephemeral_public_key = ecdh.generate_keypair()
    client_ephemeral_public_key_str = convert_bytes_to_str(client_ephemeral_public_key)

    # Create packet made of public key
    data = {
        "public_key" : client_ephemeral_public_key_str
    }

    # Send to the server 
    response = requests.request(method, rep_address + endpoint, json=data)
    
    logging.debug("RESPONSE: ", response.json())
    
    if response.status_code not in [200]:
        logging.error(f"Error: Invalid repository response: {response}")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    # Verify if signature is valid from repository
    response = response.json()
    if (not verify_signature(response, rep_pub_key)):
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    # If it is valid, finish calculations
    response_data = response["data"]
    server_ephemeral_public_key = convert_str_to_bytes(response_data["public_key"])
    encryption_key: bytes = ecdh.generate_shared_secret(server_ephemeral_public_key)[:32] # 32 bytes for encryption key

    return encryption_key, client_ephemeral_public_key

# -------------------------------

def encrypt_anonymous(data: dict | str, encryption_key: bytes, client_ephemeral_public_key: bytes):
    
    if isinstance(data, dict):
        data = json.dumps(data)
    
    encryptor = AES()
    encrypted_data, data_iv = encryptor.encrypt_data(data.encode(), encryption_key)
    
    data = {
        "client_ephemeral_public_key": convert_bytes_to_str(client_ephemeral_public_key),
        "message": convert_bytes_to_str(encrypted_data),            # Data to be sent to the server 
        "iv" : convert_bytes_to_str(data_iv),                       # IV used to encrypt the data
    }
    
    return data

# -------------------------------

def decrypt_anonymous(data: bytes, encryption_key: bytes, iv: bytes):

    decryptor = AES()
    decrypted_data = decryptor.decrypt_data(data, encryption_key, iv)

    return decrypted_data

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
    session_public_key_str = convert_bytes_to_str(session_public_key)

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
        
    signature_str = convert_bytes_to_str(signature)
        
    # Build Session creation packet
    body = {
        "data": data,
        "signature": signature_str
    }

    endpoint = "/sessions"
    # Send to the server 
    response, received_message = anonymous_request(rep_pub_key, "post", rep_address, endpoint, body)
    
    if response.status_code not in [201]:
        logging.error(f"Error: Invalid repository response: {response}")
        print("Error: ", received_message.get("error"))
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    # Verify if signature is valid from repository
    if (not verify_signature(received_message, rep_pub_key)):
        print("Error: Error verifying server authenticity")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    # If it is valid, finish calculations
    response_data = received_message["data"]
    server_session_public_key = convert_str_to_bytes(response_data["public_key"])
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
        "message": convert_bytes_to_str(encrypted_data),            # Data to be sent to the server 
        "iv" : convert_bytes_to_str(data_iv),                       # IV used to encrypt the data
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
        logging.debug("Digest verification failed")
        return None
    
    encrypted_message = convert_str_to_bytes(message_str)
    # Decrypt data
    received_message = encryptor.decrypt_data(
        encrypted_data=encrypted_message,
        key=encryption_key,
        iv=convert_str_to_bytes(received_data["iv"])
    )
    return json.loads(received_message.decode('utf-8'))

# -------------------------------

# def encrypt_anonymous(data: dict | str, rep_pub_key: bytes):
#     """Encrypts data using the public key of the repository
    
#     Args:
#         data (dict | str): Data to be encrypted
#         rep_pub_key (bytes): Public key of the repository
        
#     Returns:
#         dict: Encrypted data
#     """
    
#     if isinstance(data, dict):
#         data = json.dumps(data)
    
#     encryptor = AES()
#     symmetryc_key = encryptor.generate_random_key
#     encrypted_data, data_iv = encryptor.encrypt_data(str(data).encode(), symmetryc_key)
    
#     # Now, encrypt the symmetric key with the public key of the repository (ECC public key)
#     aes_key_from_pub_key = encryptor.derive_aes_key(rep_pub_key)
    
#     # Prepare the final data to be returned
#     data = {
#         "encrypted_data": base64.b64encode(encrypted_data).decode(),
#         "iv": base64.b64encode(data_iv).decode(),
#         "encrypted_key": base64.b64encode(encrypted_symmetric_key).decode()
#     }
#     return data