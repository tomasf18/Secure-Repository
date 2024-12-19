from flask import Blueprint, request, g
from services.session_service import *
from utils.utils import get_ephemeral_server_public_key, get_shared_secret, get_decrypted_request, encrypt_anonymous_content, convert_bytes_to_str

session_blueprint = Blueprint("sessions", __name__)

# -------------------------------

# The session key is encrypted before calling the database function
@session_blueprint.route('/sessions', methods=['POST'])
def sessions():
    db_session = g.db_session
    data = request.json
    print(f"SERVER: Received data: {data}. Creating session")
    
    if "public_key" in data:
        return get_ephemeral_server_public_key(data, db_session)
    
    encryption_key = get_shared_secret(data["client_ephemeral_public_key"]) # Might not be necessary to always send the client ephemeral pub_key, because whenever I add it to the ephemeral_keys dict, on the same command I remove it
    decrypted_data, encryption_key = get_decrypted_request(data, encryption_key)
    return_data, code = create_session(decrypted_data, db_session)
    encrypted_return_data, iv_encrypted_return_data = encrypt_anonymous_content(return_data.encode(), encryption_key)
        
    print("\n\n\nENCRYPTED_DATA: ", encrypted_return_data)
    print("\nIV:\n", iv_encrypted_return_data, "\n\n\n")
    return json.dumps({"data": convert_bytes_to_str(encrypted_return_data), 
                       "iv": convert_bytes_to_str(iv_encrypted_return_data)
                       }), code

@session_blueprint.route('/organizations/<organization_name>/sessions/<session_id>/roles/<role>', methods=['PUT', 'DELETE'])
def session_roles_role(organization_name, session_id, role):
    db_session = g.db_session
    data = request.json
    if request.method == 'PUT':
        print(f"SERVER: Received data: {data}. Adding role {role} to session {session_id} in organization {organization_name}")
        return session_assume_role(organization_name, session_id, role, data, db_session)
    elif request.method == 'DELETE':
        print(f"SERVER: Received data: {data}. Dropping role {role} from session {session_id} in organization {organization_name}")
        return session_drop_role(organization_name, session_id, role, data, db_session)
    
@session_blueprint.route('/organizations/<organization_name>/sessions/<session_id>/roles', methods=['GET'])
def session_roles(organization_name, session_id):
    db_session = g.db_session
    data = request.json
    print(f"SERVER: Received data: {data}. Getting roles from session {session_id} in organization {organization_name}")
    return list_session_roles(organization_name, session_id, data, db_session)