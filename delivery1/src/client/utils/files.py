import logging
import sys
from cryptography.hazmat.primitives import serialization
import os
import json

from constants.return_code import ReturnCode

def read_file(key_file: str) -> str | None:
    if not os.path.exists(key_file):
        logging.error(f"File {key_file} does not exist")
        # sys.exit(ReturnCode.INPUT_ERROR)
    
    with open(key_file, "r") as f:
        content = f.read();
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content

def read_public_key(key_file: str):
    content = read_file(key_file)
    return serialization.load_pem_public_key(content.encode())

def read_private_key(key_file: str, password: str):
    content = read_file(key_file)
    return serialization.load_pem_private_key(content.encode(), password.encode())