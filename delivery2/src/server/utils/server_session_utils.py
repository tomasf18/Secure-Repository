import json
import base64
import logging

from utils.cryptography.ECC import ECC
from utils.cryptography.AES import AES
from utils.cryptography.integrity import calculate_digest, verify_digest

from dao.SessionDAO import SessionDAO

from models.database_orm import Session


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
    encrypted_data, data_iv = encryptor.encrypt_data(data.encode(), encryption_key)

    message = {
        "message": base64.b64encode(encrypted_data).decode(),    # Data to be sent to the client
        "iv" : base64.b64encode(data_iv).decode(),               # IV used to encrypt the data
    }

    digest = calculate_digest(encrypted_data)
    mac, macIv = encryptor.encrypt_data(digest, integrity_key)

    body = {
        "data": message,
        "signature": {
            "mac": base64.b64encode(mac).decode(),              # MAC of the data
            "iv": base64.b64encode(macIv).decode(),             # IV used to encrypt the MAC
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
    received_data = response["data"]
    received_mac = response["signature"]
    
    # Decrypt Digest
    received_digest = encryptor.decrypt_data(
        encrypted_data=base64.b64decode(received_mac["mac"].encode()),
        key=integrity_key,
        iv=base64.b64decode(received_mac["iv"].encode())
    )
    
    encrypted_message = base64.b64decode(received_data["message"].encode())
    
    # Verify digest of received data and check integrity
    if ( not verify_digest(encrypted_message, received_digest) ):
        print("Digest verification failed")
        return None
    
    # Decrypt data
    received_message = encryptor.decrypt_data(
        encrypted_data=encrypted_message,
        key=encryption_key,
        iv=base64.b64decode(received_data["iv"].encode())
    )
    return json.loads(received_message.decode('utf-8'))

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

    print(f"Received counter: {received_counter}, Received nonce: {received_nonce}\
        \nExpected counter: >{counter}, Expected nonce: {nonce}")
    
    return all([
        received_nonce == nonce,
        received_counter > counter
    ])
    
# -------------------------------

def load_session(data: dict, session_dao: SessionDAO, organization_name: str) -> tuple[dict, Session, bytes]:
    """Load the session from the received data and make the necessary verifications: 
        - organization
        - message order 
        - message integrity 
        - message uniqueness
        
    Args:
        data (dict): Data received from the client
        session_dao (SessionDAO): DAO to access the session
        organization_name (str): Name of the organization
    
    Returns:
        tuple[dict, Session, bytes]: Decrypted data, Session, Session key
    """
    
    # Get session
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    if session is None:
        print(f"SERVER: Session with id {session_id} not found")
        raise ValueError(
                json.dumps(f"Session with id {session_id} not found"), HTTP_Code.NOT_FOUND
            )

    session_key = session_dao.get_decrypted_key(session_id)
    
    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        print("SERVER: Error decrypting data")
        raise ValueError(
            encrypt_payload({
                    "error": f"Invalid session key"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    if (decrypted_data.get("counter") is None) or (decrypted_data.get("nonce") is None):
        print("No counter or nonce provided")    
        raise ValueError(
            encrypt_payload({
                    "error": f"No counter or nonce provided!"
                }, session_key[:32], session_key[32:]
            ), 403
        )
        
    if not verify_message_order(decrypted_data, counter=session.counter, nonce=session.nonce):
        print("SERVER: Invalid message order")
        raise ValueError(
            encrypt_payload({
                    "error": f"Invalid message order"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    if organization_name != session.organization_name:
        print("SERVER: Cannot access organization")
        raise ValueError(
            encrypt_payload({
                    "error": f"Cannot access organization {organization_name}"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    return decrypted_data, session, session_key