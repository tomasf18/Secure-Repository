from services.file_service import *
from flask import Blueprint, request, g

from utils.utils import get_ephemeral_server_public_key, get_shared_secret, convert_bytes_to_str, encrypt_anonymous_content

file_blueprint = Blueprint("files", __name__)

# -------------------------------

@file_blueprint.route("/files/<file_handle>", methods=["GET"])
def files(file_handle):    
    db_session = g.db_session
    data = request.json
    if data and "public_key" in data:
        return get_ephemeral_server_public_key(data, db_session)
    
    encryption_key = get_shared_secret(data["client_ephemeral_public_key"]) # Might not be necessary to always send the client ephemeral pub_key, because whenever I add it to the ephemeral_keys dict, on the same command I remove it    

    if file_handle != "None":
        return_data, code = download_file(file_handle)        
    else:
        return_data = json.dumps({"error": "File not found."})
        print(f"File {file_handle} not found.")
        code = HTTP_Code.NOT_FOUND
        
    encrypted_return_data, iv_encrypted_return_data = encrypt_anonymous_content(return_data.encode(), encryption_key)
    return json.dumps({"data": convert_bytes_to_str(encrypted_return_data), 
                       "iv": convert_bytes_to_str(iv_encrypted_return_data)
                       }), code