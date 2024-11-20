import json
import os
import base64

def download_file(file_handle):
    '''Handles GET requests to /files/<file_handle>'''
    
    # extract organization name and digest from the file_handle
    org_name, digest = file_handle.split("_")
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_org_dir = os.path.join(project_root, "data", org_name)
    
    # search in organization's directory for the file using the file_handle
    file_path = os.path.join(data_org_dir, file_handle)
    if not os.path.exists(file_path):
        return json.dumps({"error": "File not found."}), 404
    
    # return the encrypted file contents
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    return json.dumps({"data": base64.b64encode(encrypted_data).decode('utf-8')}), 200