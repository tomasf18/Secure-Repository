from flask import Blueprint, request, g
from services.session_service import *

session_blueprint = Blueprint("sessions", __name__)

# -------------------------------

# The session key is encrypted before calling the database function
@session_blueprint.route('/sessions', methods=['POST'])
def sessions():
    db_session = g.db_session
    data = request.json
    print(f"SERVER: Received data: {data}. Creating session")
    return create_session(data, db_session)

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