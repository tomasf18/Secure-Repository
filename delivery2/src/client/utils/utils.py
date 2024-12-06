import os
import base64
from dotenv import load_dotenv

load_dotenv()

def get_private_key_file(credentials_file: str):
    client_priv_key_path = os.getenv("CLIENT_PRIV_KEY_PATH")
    private_key_path = client_priv_key_path + f"{credentials_file}.pem"
    return private_key_path

def get_public_key_file(credentials_file: str):
    client_pub_key_path = os.getenv("CLIENT_PUB_KEY_PATH")
    public_key_path = client_pub_key_path + f"{credentials_file}.pub"
    return public_key_path

def get_session_file(session_file: str):
    session_file_path = os.getenv("CLIENT_SESSION_FILE_PATH") + session_file + ".json"
    return session_file_path

def get_client_file(file: str):
    client_file_path = os.getenv("CLIENT_FILES_PATH") + file
    return client_file_path

def get_metadata_path(metadata_file_name: str) -> str:
    return os.getenv("CLIENT_METADATAS_PATH") + metadata_file_name + "_metadata.json"

def get_encrypted_file_path(encrypted_file_name: str) -> str:
    return os.getenv("CLIENT_ENCRYPTED_FILES_PATH") + encrypted_file_name + ".enc"

def get_decrypted_file_path(decrypted_file_name: str) -> str:
    return os.getenv("CLIENT_DECRYPTED_FILES_PATH") + decrypted_file_name + ".dec"

def convert_bytes_to_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def convert_str_to_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))