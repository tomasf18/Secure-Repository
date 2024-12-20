import os
import json

from utils.utils import convert_bytes_to_str, return_data
from utils.constants.http_code import HTTP_Code

def download_file(file_handle):
    '''Handles GET requests to /files/<file_handle>'''
    
    # Extract organization name and digest from the file_handle
    try:
        org_name, digest = file_handle.split("_")
    except ValueError:
        return return_data(
            key="error",
            data="File not found.",
            code = HTTP_Code.NOT_FOUND
        )
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_org_dir = os.path.join(project_root, "data", org_name)
    
    # Search in organization's directory for the file using the file_handle
    file_path = os.path.join(data_org_dir, file_handle) + ".enc"
    if not os.path.exists(file_path):
        return return_data(
            key = "error",
            data = "File not found.",
            code = HTTP_Code.NOT_FOUND
        )
    
    # Return the encrypted file contents
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
        
    return return_data(
        key="data",
        data=convert_bytes_to_str(encrypted_data),
        code=HTTP_Code.OK
    )