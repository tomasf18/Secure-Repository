import os
import json
import base64
from .cryptography.AES import AES
from .cryptography.ECC import ECC
from .cryptography.auth import sign
from models.database_orm import Session
from .constants.http_code import HTTP_Code
from .server_session_utils import encrypt_payload
from dao.RepositoryDAO import RepositoryDAO


def convert_bytes_to_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def convert_str_to_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

def check_permissions(user_id: int) -> bool:
    pass

def return_data(key: str, data: str, code: HTTP_Code, session_key: bytes = None):
    if session_key:
        return encrypt_payload({key: data}, session_key[:32], session_key[32:]), code
    return json.dumps({key: data}), code

ephemeral_keys = {}

def get_ephemeral_server_public_key(data, db_session):
    client_ephemeral_pub_key = convert_str_to_bytes(data["public_key"])
    result, encryption_key, code = generate_anonymous_signed_shared_secret(client_ephemeral_pub_key, db_session)
    ephemeral_keys[data["public_key"]] = encryption_key
    return result, code

def get_decrypted_request(data, encryption_key):
    ephemeral_keys.pop(data["client_ephemeral_public_key"])
    encrypted_message = convert_str_to_bytes(data["message"])
    iv = convert_str_to_bytes(data["iv"])
    decrypted_data = decrypt_anonymous_content(encrypted_message, encryption_key, iv).decode()
    print("\n\n\n\n\n DECRYPTED DATA: \n\n", decrypted_data, "\n\n\n\n")
    print("\n ENCRYPTION KEY: ", encryption_key)
    
    return json.loads(decrypted_data), encryption_key

def generate_anonymous_signed_shared_secret(client_ephemeral_pub_key: bytes, db_session: Session):
    repository_dao = RepositoryDAO(db_session)
    encryption_key, ephemeral_server_public_key = exchange_keys(client_ephemeral_pub_key)
    data = {
        "public_key": convert_bytes_to_str(ephemeral_server_public_key)
    } 
    
    # Get repository private key using the respective password to decrypt it
    rep_priv_key_password: str = os.getenv('REP_PRIV_KEY_PASSWORD')
    rep_priv_key = ECC.load_private_key(repository_dao.get_private_key(), rep_priv_key_password)
    
    # Sign response
    signature = sign(
        data = data,
        private_key = rep_priv_key,
    )

    # Finish response packet
    result = json.dumps({
        "data": data,
        "signature": convert_bytes_to_str(signature)
    })
    
    # Return response to the client
    print(f"\n\nResult: {result}\n\n")
    return result, encryption_key[:32], HTTP_Code.OK


def exchange_keys(client_session_public_key: bytes) -> tuple[bytes, bytes]:
    ecdh = ECC()
    _, session_server_public_key = ecdh.generate_keypair()
    session_key: bytes = ecdh.generate_shared_secret(client_session_public_key)
    
    return session_key, session_server_public_key

# -------------------------------

def decrypt_anonymous_content(data: bytes, key: bytes, iv: bytes):
    decryptor = AES()
    return decryptor.decrypt_data(data, key, iv)

def encrypt_anonymous_content(data: bytes, key: bytes):
    encryptor = AES()
    return encryptor.encrypt_data(data, key)

# -------------------------------

def get_shared_secret(ephemeral_key):
    return ephemeral_keys[ephemeral_key]
