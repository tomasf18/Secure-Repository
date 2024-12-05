import os
import sys
import json
import logging

from utils.constants.return_code import ReturnCode

# -------------------------------

def read_file(file: str) -> str | None:
    if not os.path.exists(file):
        logging.error(f"File {file} does not exist")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    with open(file, "r") as f:
        content = f.read();
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content
        
# -------------------------------
        
def write_file(file_path: str, content: str):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(content)
    

