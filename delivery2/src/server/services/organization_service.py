import json
import base64

from dao.SessionDAO import SessionDAO
from dao.DocumentDAO import DocumentDAO
from dao.OrganizationDAO import OrganizationDAO
from dao.RoleDAO import RoleDAO

from models.status import Status
from models.database_orm import Organization, Subject, Document

from utils.server_session_utils import load_session
from utils.server_session_utils import encrypt_payload

from utils.utils import convert_bytes_to_str, convert_str_to_bytes

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError




# -------------------------------

def create_organization(data, db_session: Session):
    '''Handles POST requests to /organizations'''
    
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    org_name: str = data.get('organization')
    username: str = data.get('username')
    name: str = data.get('name')
    email: str = data.get('email')
    public_key: bytes = convert_str_to_bytes(data.get('public_key'))
    # This is how the client sends the public key (must be converted to string to be sent by the internet):
    # base64.b64encode(<what i want t obtain>).decode('utf-8')
    # The reverse is: base64.b64decode(<what i want to decode>.encode())

    try:
        organization_dao.create(org_name, username, name, email, public_key)
    except IntegrityError:
        return json.dumps(f"Organization with name '{org_name}' already exists."), 400
    
    return json.dumps(f'Organization {org_name} created successfully'), 201

# -------------------------------

def list_organizations(db_session: Session):
    '''Handles GET requests to /organizations'''
    
    organization_dao = OrganizationDAO(db_session)
    organizations: list["Organization"] = organization_dao.get_all()
    serializable_organizations = []
    for org in organizations:
        serializable_organizations.append({
            "name": org.name
        })
    return json.dumps(serializable_organizations), 200

# -------------------------------

def list_organization_subjects(organization_name, role, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    role_dao = RoleDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    try:
        subjects: list["Subject"] = None
        if role:
            role_object = role_dao.get_by_name(role)
            subjects = role_object.subjects
        else:
            subjects = organization_dao.get_subjects(organization_name)
            
        serializable_subjects = []
        for subject in subjects:
            status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
            serializable_subjects.append({
                "username": subject.username,
                "status": status
            })
    except Exception as e:
        print(f"SERVER: Error getting subjects from organization {organization_name}. Error: {e}")
        return encrypt_payload({
                "error": f"Organization '{organization_name}' doesn't exist."
            }, session_key[:32], session_key[32:]
        ), 404
    
    # Construct result
    result = {
        "data": serializable_subjects
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200

# -------------------------------

def get_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    status = organization_dao.get_org_subj_association(org_name=organization_name, username=username).status

    # Create result
    result = {
        "data": {
            "username": subject.username,
            "status": status
        }
    }
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])

    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200

# -------------------------------

def add_organization_subject(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/subjects'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    username = decrypted_data.get('username')
    name = decrypted_data.get('name')
    email = decrypted_data.get('email')
    public_key = base64.b64decode(decrypted_data.get('public_key'))
    
    try:
        organization_dao.add_subject_to_organization(organization_name, username, name, email, public_key)
    except IntegrityError:
        return encrypt_payload({
                "error": f"Subject with username '{username}' already exists."
            }, session_key[:32], session_key[32:]
        ), 400

    # Construct result
    result = {
        "data": f'Subject {username} added to organization {organization_name} successfully'
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200

# -------------------------------

def suspend_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    try:
        organization_dao.update_org_subj_association_status(organization_name, username, Status.SUSPENDED.value)
    except Exception as e:
        return encrypt_payload({
                "error": f"Subject '{username}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), 403
    
    # Construct result
    result = {
        "data": f"Subject '{username}' in the organization '{organization_name}' has been suspended."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200
    
# -------------------------------
    
def activate_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    try:
        organization_dao.update_org_subj_association_status(organization_name, username, Status.ACTIVE.value)
    except Exception as e:
        return encrypt_payload({
                "error": f"Subject '{username}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), 403
    
    # Construct result
    result = {
        "data": f"Subject '{username}' in the organization '{organization_name}' has been activated."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return json.dumps(encrypted_result), 200
    
# -------------------------------
    
def create_organization_document(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/documents'''
    
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    document_name = decrypted_data.get('document_name')
    encrypted_file_content = convert_str_to_bytes(decrypted_data.get('file'))
    alg = decrypted_data.get('alg')
    key = convert_str_to_bytes(decrypted_data.get('key'))
    iv = convert_str_to_bytes(decrypted_data.get('iv'))
    
    document_dao.create_document(document_name, session.id, encrypted_file_content, alg, key, iv)

    # Construct result
    result = {
        "data": f"Document '{document_name}' uploaded in the organization '{organization_name}' successfully."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 201

# -------------------------------

def list_organization_documents(organization_name, data, username, date_filter, date, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents'''
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    documents: list["Document"] = document_dao.get(session.id, username, date_filter, date)
    if not documents:
        return encrypt_payload({
                "error": "No documents found."
            }, session_key[:32], session_key[32:]
        ), 404

    i = 0
    serializable_documents = []
    for doc in documents:
        i += 1
        serializable_documents.append({
            "document" + str(i): doc.__repr__(),
        })

    # Construct result
    result = {
        "data": serializable_documents
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 201

# =================================== Auxiliar Function =================================== #

def get_serializable_document(document: "Document", document_dao: DocumentDAO):
    
    decrypted_key: bytes = document_dao.get_decrypted_metadata_key(document.id)
    
    return {
        "document_handle": document.document_handle,
        "document_name": document.name,
        "create_date": document.create_date.strftime("%Y-%m-%d %H:%M:%S"),
        "creator": document.creator.__repr__(),
        "file_handle": document.file_handle,
        "acl": document.acl.__repr__(),
        "deleter": document.deleter.__repr__(),
        "organization": document.org_name,
        "encryption_data": {
            "algorithm": document.restricted_metadata.alg,
            "mode": document.restricted_metadata.mode,
            "key": convert_bytes_to_str(decrypted_key),
            "iv": convert_bytes_to_str(document.restricted_metadata.iv),
        }
    }

# ========================================================================================= #

def get_organization_document_metadata(organization_name, document_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents/<document_name>'''
    
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    try:
        document: "Document" = document_dao.get_metadata(session.id, document_name)
    except Exception as e:
        return encrypt_payload({
                "error": f"Document '{document_name}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), 404
    
    serializable_document = get_serializable_document(document, document_dao)

    # Construct result
    result = {
        "data": serializable_document
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    print("\n\n\n RESULT: ", result, "\n\n\n")
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 201


# def get_organization_document_file(organization_name, document_name, data, db_session: Session):
#     '''Handles GET requests to /organizations/<organization_name>/documents/<document_name>/file'''
    
#     document_dao = DocumentDAO(db_session)
#     session_dao = SessionDAO(db_session)

#     # Get session
#     try:
#         decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
#     except ValueError as e:
#         message, code = e.args
#         return message, code
    
#     document: "Document" = document_dao.get_metadata(session.id, document_name)
#     if not document.file_handle:
#         return encrypt_payload({
#                 "error": f"ERROR 404 - Document '{document_name}' does not have an associated file handle in Organization: '{organization_name}'."
#             }, session_key[:32], session_key[32:]
#         ), 404
    
#     serializable_document = get_serializable_document(document)

#     # Construct result
#     result = {
#         "data": serializable_document
#     }

#     # Update session
#     session_dao.update_counter(session.id, decrypted_data["counter"])
    
#     # Encrypt result
#     encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
#     return encrypted_result, 201

# -------------------------------

def delete_organization_document(organization_name, document_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/documents/<document_name>'''
    
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    try:
        ceasing_file_handle = document_dao.delete(session.id, document_name)
    except ValueError as e:
        return encrypt_payload({
                "error": e.args[0]
            }, session_key[:32], session_key[32:]
        ), 400
    
    # Construct result
    result = {
        "data": f"Document '{document_name}' with file_handle '{ceasing_file_handle}' deleted from organization '{organization_name}' successfully."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200


# ==================================== Second Delivery ==================================== #

def create_organization_role(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/documents'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    # Get organization, acl_id and new_role
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id
    new_role = decrypted_data.get('new_role')

    # Create role
    role = role_dao.create(new_role, acl_id)

    # Construct result
    result = {
        "data": f"Role '{role.__repr__()}' created in the organization '{organization_name}' successfully."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 201

# -------------------------------

def list_subject_roles(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>/roles'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # Get subject
    subject = organization_dao.get_subject_by_username(organization_name, username)

    # Get roles
    roles = role_dao.get_by_username_and_acl_id(username, acl_id)

    # Construct result
    result = {
        "data": [role.__repr__() for role in roles]
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200



# ========================================================================================= #

