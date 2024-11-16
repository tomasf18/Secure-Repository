import os

def read_file(key_file: str) -> str | None:
    if not os.path.exists(key_file):
        return
    
    with open(key_file, "r") as f:
        return f.read();