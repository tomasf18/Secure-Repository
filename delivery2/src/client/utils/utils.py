import os
import base64
from dotenv import load_dotenv

load_dotenv()

def get_private_key_file(credentials_file):
    client_priv_key_path = os.getenv("CLIENT_PRIV_KEY_PATH")
    private_key_path = client_priv_key_path + f"{credentials_file}.pem"
    return private_key_path

def get_public_key_file(credentials_file):
    client_pub_key_path = os.getenv("CLIENT_PUB_KEY_PATH")
    public_key_path = client_pub_key_path + f"{credentials_file}.pub"
    return public_key_path

def get_session_file(session_file):
    session_file_path = os.getenv("CLIENT_SESSION_FILE_PATH") + session_file + ".json"
    return session_file_path

def convert_bytes_to_str(data: bytes):
    return base64.b64encode(data).decode('utf-8')

def convert_str_to_bytes(data: str):
    return base64.b64decode(data.encode('utf-8'))