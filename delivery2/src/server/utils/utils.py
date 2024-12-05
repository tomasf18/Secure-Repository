import base64

def convert_bytes_to_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def convert_str_to_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))