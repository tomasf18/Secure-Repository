import os
import json
import base64
import logging
import datetime
from dotenv import load_dotenv

from utils.cryptography.ECC import ECC
from utils.cryptography.AES import AES
from utils.cryptography.integrity import calculate_digest, verify_digest

from utils.constants.http_code import HTTP_Code

from sqlalchemy.orm import Session as SQLAlchemySession

from dao.SessionDAO import SessionDAO
from dao.OrganizationDAO import OrganizationDAO

from models.status import Status
from models.database_orm import Session

load_dotenv()

SESSION_LIFETIME = eval(os.getenv("SESSION_LIFETIME"))

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
        "signature": base64.b64encode(digest).decode('utf-8') # convert_bytes_to_str(digest)
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
    received_mac = base64.b64decode(response["signature"].encode('utf-8')) # convert_str_to_bytes(response["signature"])
    
    message_str = received_data["message"]
    data_to_digest = (message_str + received_data["iv"]).encode()
    
    # Verify digest of received data and check integrity
    if ( not verify_digest(data_to_digest, received_mac, integrity_key) ):
        logging.debug("Digest verification failed")
        return None
    
    encrypted_message = base64.b64decode(message_str.encode('utf-8')) # convert_str_to_bytes(received_data["message"])
    # Decrypt data
    received_message = encryptor.decrypt_data(
        encrypted_data=encrypted_message,
        key=encryption_key,
        iv=base64.b64decode(received_data["iv"].encode('utf-8')) # convert_str_to_bytes(received_data["iv"])
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
    return all([
        received_nonce == nonce,
        received_counter > counter
    ])
    
# -------------------------------

def load_session(data: dict, db_session: SQLAlchemySession, organization_name: str) -> tuple[dict, Session, bytes]:
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
    
    session_dao = SessionDAO(db_session)
    
    # Get session
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    
    if session is None:
        raise ValueError(
                 f"Session with id {session_id} not found", HTTP_Code.NOT_FOUND, None
            )
        
    if subject_invalid(session, db_session):
        raise ValueError(
                f"Subject {session.subject_username} is suspended", HTTP_Code.FORBIDDEN, None
            )
       
    if session_expired(session):
        raise ValueError(
                f"Session with id {session_id} expired", HTTP_Code.FORBIDDEN, None
            ) 

    session_dao.update_last_interaction(session.id)
    
    session_key = session_dao.get_decrypted_key(session_id)
    
    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        raise ValueError(
            f"Invalid session key",
            HTTP_Code.FORBIDDEN,
            session_key
        )

    if (decrypted_data.get("counter") is None) or (decrypted_data.get("nonce") is None):
        raise ValueError(
            f"No counter or nonce provided!",
            HTTP_Code.FORBIDDEN, 
            session_key
        )
        
    if not verify_message_order(decrypted_data, counter=session.counter, nonce=session.nonce):
        raise ValueError(
            f"Invalid message order",
            HTTP_Code.FORBIDDEN,
            session_key
        )

    if organization_name != session.organization_name:
        raise ValueError(
            f"Cannot access organization {organization_name}",
            HTTP_Code.FORBIDDEN, 
            session_key
        )

    return decrypted_data, session, session_key

# -------------------------------

def session_expired(session: Session) -> bool:
    session_last_interaction = session.last_interaction
    current_time = datetime.datetime.now()
    return (current_time - session_last_interaction).total_seconds() > SESSION_LIFETIME

def subject_invalid(session: Session, db_session: SQLAlchemySession) -> bool:
    organization_dao = OrganizationDAO(db_session)
    org_subj_assoc = organization_dao.get_org_subj_association(session.organization_name, session.subject_username)
    return org_subj_assoc.status == Status.SUSPENDED.value