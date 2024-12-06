import logging
from flask import Blueprint, request, g
from services.organization_service import *

organization_blueprint = Blueprint("organizations", __name__)



# -------------------------------

@organization_blueprint.route("/organizations", methods=["GET", "POST"])
def organizations():
    db_session = g.db_session
    if request.method == 'GET':
        print("SERVER: Getting organizations")
        return list_organizations(db_session)
    if request.method == 'POST':
        data = request.json
        print(f"SERVER: Received data: {data}. Creating organization")
        return create_organization(data, db_session)

# -------------------------------

@organization_blueprint.route('/organizations/<organization_name>/subjects', methods=['GET', 'POST'])
def organization_subjects(organization_name):
    db_session = g.db_session
    data = request.json
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting subjects from organization {organization_name}")
        role = request.args.get('role')
        return list_organization_subjects(organization_name, role, data, db_session)
    elif request.method == 'POST':
        data = request.json
        print(f"SERVER: Received data: {data}. Adding subject to organization {organization_name}")
        return add_organization_subject(organization_name, data, db_session)

# -------------------------------

@organization_blueprint.route('/organizations/<organization_name>/subjects/<username>', methods=['GET', 'PUT', 'DELETE'])
def organization_subject(organization_name, username):
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting subject {username} from organization {organization_name}")
        return get_organization_subject(organization_name, username, data, db_session)
    elif request.method == 'PUT':
        data = request.json
        print(f"SERVER: Received data: {data}. Activating subject {username} from organization {organization_name}")
        return activate_organization_subject(organization_name, username, data, db_session)
    elif request.method == 'DELETE':
        data = request.json
        print(f"SERVER: Received data: {data}. Suspending subject {username} from organization {organization_name}")
        return suspend_organization_subject(organization_name, username, data, db_session)
    
# -------------------------------
    
@organization_blueprint.route('/organizations/<organization_name>/documents', methods=['GET', 'POST'])
def organization_documents(organization_name):
    
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting documents from organization {organization_name}")
        username = request.args.get('subject')
        date_filter = request.args.get('date_filter')
        date = request.args.get('date')
        return list_organization_documents(organization_name, data, username, date_filter, date, db_session)
    elif request.method == 'POST':
        data = request.json
        print(f"SERVER: Received data: {data}. Creating document in organization {organization_name}")
        return create_organization_document(organization_name, data, db_session)
    
# -------------------------------
    
@organization_blueprint.route('/organizations/<organization_name>/documents/<document_name>', methods=['GET', 'DELETE'])
def organization_document(organization_name, document_name):
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting document {document_name} from organization {organization_name}")
        return get_organization_document_metadata(organization_name, document_name, data, db_session)
    elif request.method == 'DELETE':
        data = request.json
        print(f"SERVER: Received data: {data}. Deleting document {document_name} from organization {organization_name}")
        return delete_organization_document(organization_name, document_name, data, db_session)
    
# -------------------------------
    
# @organization_blueprint.route('/organizations/<organization_name>/documents/<document_name>/file', methods=['GET'])
# def organization_document_file(organization_name, document_name):
#     db_session = g.db_session
#     data = request.json
#     print(f"SERVER: Received data: {data}. Getting file from document {document_name} from organization {organization_name}")
#     return get_organization_document_file(organization_name, document_name, data, db_session)


# ==================================== Second Delivery ==================================== #

@organization_blueprint.route('/organizations/<organization_name>/roles', methods=['GET', 'POST'])
def organization_roles(organization_name):
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        # print(f"SERVER: Received data: {data}. Getting documents from organization {organization_name}")
        # username = request.args.get('subject')
        # date_filter = request.args.get('date_filter')
        # date = request.args.get('date')
        # return list_organization_documents(organization_name, data, username, date_filter, date, db_session)
    elif request.method == 'POST':
        data = request.json
        print(f"SERVER: Received data: {data}. Creating role in organization {organization_name}")
        return create_organization_role(organization_name, data, db_session)
    
# -------------------------------

@organization_blueprint.route('/organizations/<organization_name>/subjects/<username>/roles', methods=['GET'])
def organization_subject_roles(organization_name, username):
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting roles from subject {username} in organization {organization_name}")
        return list_subject_roles(organization_name, username, data, db_session)
    
# -------------------------------

@organization_blueprint.route('/organizations/<organization_name>/roles/<role>', methods=['PUT', 'DELETE'])
def organization_role(organization_name, role):
    db_session = g.db_session
    if request.method == 'PUT':
        data = request.json
        print(f"SERVER: Received data: {data}. Reactivating role {role} in organization {organization_name}")
        return reactivate_role_subjects(organization_name, role, data, db_session)
    elif request.method == 'DELETE':
        data = request.json
        print(f"SERVER: Received data: {data}. Suspending role {role} in organization {organization_name}")
        return suspend_role_subjects(organization_name, role, data, db_session)
    
# -------------------------------

@organization_blueprint.route('/organizations/<organization_name>/roles/<role>/subject-permissions', methods=['GET', 'PUT', 'DELETE'])
def organization_role_permissions(organization_name, role):
    db_session = g.db_session
    if request.method == 'GET':
        data = request.json
        print(f"SERVER: Received data: {data}. Getting permissions from role {role} in organization {organization_name}")
        return get_role_permissions(organization_name, role, data, db_session)
    elif request.method == 'PUT':
        data = request.json
        print(f"SERVER: Received data: {data}. Adding permission or subject to role {role} in organization {organization_name}")
        return add_subject_or_permission_to_role(organization_name, role, data, db_session)
    elif request.method == 'DELETE':
        data = request.json
        print(f"SERVER: Received data: {data}. Removing permission or subject from role {role} in organization {organization_name}")
        return remove_subject_or_permission_from_role(organization_name, role, data, db_session)