import json
import base64
from dotenv import load_dotenv

from dao.RoleDAO import RoleDAO
from dao.SubjectDAO import SubjectDAO
from dao.SessionDAO import SessionDAO
from dao.DocumentDAO import DocumentDAO
from dao.PermissionDAO import PermissionDAO
from dao.OrganizationDAO import OrganizationDAO
from dao.DocumentRolePermissionDAO import DocumentRolePermissionDAO

from models.status import Status
from models.database_orm import Organization, Subject, Document, Permission, DocumentRolePermission

from utils.server_session_utils import load_session
from utils.server_session_utils import encrypt_payload

from utils.constants.http_code import HTTP_Code
from utils.utils import convert_bytes_to_str, convert_str_to_bytes

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError


load_dotenv()

# -------------------------------

def create_organization(data: dict, db_session: Session):
    '''Handles POST requests to /organizations'''
    
    organization_dao = OrganizationDAO(db_session)
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
        return json.dumps(f"Organization with name '{org_name}' already exists."), HTTP_Code.BAD_REQUEST
    
    return json.dumps(f'Organization {org_name} created successfully'), HTTP_Code.CREATED

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
    return json.dumps(serializable_organizations), HTTP_Code.OK

# -------------------------------

def list_organization_subjects(organization_name, role, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    role_dao = RoleDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    try:
        subjects: list["Subject"] = None
        if role:
            organization = organization_dao.get_by_name(organization_name)
            role_object = role_dao.get_by_name_and_acl_id(role, organization.acl.id)
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
        ), HTTP_Code.NOT_FOUND
    
    # Construct result
    result = {
        "data": serializable_subjects
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), HTTP_Code.OK

# -------------------------------

def get_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    try:
        subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    except Exception as e:
        return encrypt_payload({
                "error": f"Subject '{username}' doesn't exist in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.NOT_FOUND
        
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

    return json.dumps(encrypted_result), HTTP_Code.OK

# -------------------------------

def add_organization_subject(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/subjects'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    
    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_NEW"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
        
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
        ), HTTP_Code.BAD_REQUEST

    # Construct result
    result = {
        "data": f'Subject {username} added to organization {organization_name} successfully'
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), HTTP_Code.OK

# -------------------------------

def suspend_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''

    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_DOWN"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    if organization_dao.subject_has_role(organization_name, username, "Manager"):
        return encrypt_payload({
                "error": f"Subject '{username}' is a Manager and cannot be suspended."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
        
    try:
        organization_dao.update_org_subj_association_status(organization_name, username, Status.SUSPENDED.value)
    except Exception as e:
        return encrypt_payload({
                "error": f"Subject '{username}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    # Construct result
    result = {
        "data": f"Subject '{username}' in the organization '{organization_name}' has been suspended."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), HTTP_Code.OK
    
# -------------------------------
    
def activate_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_UP"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    if organization_dao.subject_has_role(organization_name, username, "Manager"):
        return encrypt_payload({
                "error": f"Subject '{username}' is a Manager, therefore it is always active."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    try:
        organization_dao.update_org_subj_association_status(organization_name, username, Status.ACTIVE.value)
    except Exception as e:
        return encrypt_payload({
                "error": f"Subject '{username}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    # Construct result
    result = {
        "data": f"Subject '{username}' in the organization '{organization_name}' has been activated."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return json.dumps(encrypted_result), HTTP_Code.OK
    
# -------------------------------
    
def create_organization_document(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/documents'''
    
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    role_dao = RoleDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["DOC_NEW"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    document_name = decrypted_data.get('document_name')
    encrypted_file_content = convert_str_to_bytes(decrypted_data.get('file'))
    alg = decrypted_data.get('alg')
    key = convert_str_to_bytes(decrypted_data.get('key'))
    iv = convert_str_to_bytes(decrypted_data.get('iv'))
    
    new_document = document_dao.create_document(document_name, session.id, encrypted_file_content, alg, key, iv)

    # Construct result
    result = {
        "data": f"Document '{document_name}' uploaded in the organization '{organization_name}' successfully."
    }
    
    # Get Manager role
    organization = organization_dao.get_by_name(organization_name)
    role_to_add_doc_permissions = session.session_roles[0]

    # Give all the document permissions to the Manager role
    document_role_permission_dao.add_all_doc_permissions_to_role(new_document.acl.id, role_to_add_doc_permissions.id)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.CREATED

# -------------------------------

def list_organization_documents(organization_name, data, username, date_filter, date, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents'''
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    documents: list["Document"] = document_dao.get(session.id, username, date_filter, date)
    if not documents:
        return encrypt_payload({
                "error": "No documents found."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.NOT_FOUND

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
    
    return encrypted_result, HTTP_Code.CREATED

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
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    try:
        document: "Document" = document_dao.get_metadata(session.id, document_name)
        missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_READ"])
        if missing_permissions != []:
            return encrypt_payload({
                    "error": f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}"
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.FORBIDDEN
    except Exception as e:
        return encrypt_payload({
                "error": f"Document '{document_name}' doesn't exists in the organization '{organization_name}'."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.NOT_FOUND
    
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
    
    return encrypted_result, HTTP_Code.CREATED

# -------------------------------

def delete_organization_document(organization_name, document_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/documents/<document_name>'''
    
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
        
    try:
        document: "Document" = document_dao.get_metadata(session.id, document_name)
        missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_DELETE"])
        if missing_permissions != []:
            return encrypt_payload({
                    "error": f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}"
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.FORBIDDEN
        ceasing_file_handle = document_dao.delete(session.id, document_name)
    except ValueError as e:
        return encrypt_payload({
                "error": e.args[0]
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.BAD_REQUEST
    
    # Construct result
    result = {
        "data": f"Document '{document_name}' with file_handle '{ceasing_file_handle}' deleted from organization '{organization_name}' successfully."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK


# ==================================== Second Delivery ==================================== #

def create_organization_role(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/roles'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_NEW"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
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
    
    return encrypted_result, HTTP_Code.CREATED

# -------------------------------

def list_subject_roles(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>/roles'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # # Get subject
    # subject = organization_dao.get_subject_by_username(organization_name, username)

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
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def suspend_role(organization_name, role_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/roles/<role>'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_DOWN"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    if role_name == "Manager":
        return encrypt_payload({
                "error": f"Role '{role_name}' cannot be suspended."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
        
    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    role = role_dao.update_role_status(role_name, acl_id, Status.SUSPENDED.value)
    
    # From all sessions where this role is being used, remove it
    session_dao.remove_role_from_all_sessions(role)
    
    # Construct result
    result = {
        "data": f"Role '{role.name}' in the organization '{organization_name}' has been suspended."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def reactivate_role(organization_name, role_name, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/roles/<role>'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_UP"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN
    
    if role_name == "Manager":
        return encrypt_payload({
                "error": f"Role '{role_name}' is always active."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    role = role_dao.update_role_status(role_name, acl_id, Status.ACTIVE.value)
    
    # Construct result
    result = {
        "data": f"Role '{role.name}' in the organization '{organization_name}' has been reactivated."
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def get_role_permissions(organization_name, role_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/roles/<role>/subject-permissions'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # Get role
    role = role_dao.get_by_name_and_acl_id(role_name, acl_id)

    # Get role permissions
    permissions = role.permissions
    
    # Construct result
    result = {
        "data": [permission.__repr__() for permission in permissions]
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def add_subject_or_permission_to_role(organization_name, role_name, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/roles/<role>/subject-permissions'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    subject_dao = SubjectDAO(db_session)
    permission_dao = PermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_MOD"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # Get role
    role = role_dao.get_by_name_and_acl_id(role_name, acl_id)

    # Add subject or permission to role
    object = decrypted_data.get('object')
    
    subject: Subject = None
    permission: Permission = None

    try:
        subject = subject_dao.get_by_username(object)
    except ValueError:
        try:
            permission = permission_dao.get_by_name(object)
        except ValueError:
            return encrypt_payload({
                    "error": f"Subject '{object}' or Permission '{object}' doesn't exist."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.BAD_REQUEST
    
    result = None
    
    if subject:
        if role.name == "Manager":
            org_subj_assoc = organization_dao.get_org_subj_association(organization_name, subject.username)
            if org_subj_assoc.status == Status.SUSPENDED.value:
                return encrypt_payload({
                        "error": f"Subject '{subject.username}' is suspended and cannot be added to role '{role_name}'."
                    }, session_key[:32], session_key[32:]
                ), HTTP_Code.FORBIDDEN
            
        role.subjects.append(subject)
        result = {
            "data": f"Subject '{subject.username}' added to role '{role_name}' in organization '{organization_name}' successfully."
        }
        
    if permission:
        if role.name == "Manager":
            return encrypt_payload({
                    "error": f"Role '{role_name}' cannot have its permissions modified."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.FORBIDDEN
        role.permissions.append(permission)
        result = {
            "data": f"Permission '{permission.name}' added to role '{role_name}' in organization '{organization_name}' successfully."
        }
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def remove_subject_or_permission_from_role(organization_name, role_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/roles/<role>/subject-permissions'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    subject_dao = SubjectDAO(db_session)
    permission_dao = PermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_MOD"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # Get role
    role = role_dao.get_by_name_and_acl_id(role_name, acl_id)

    # Remove subject or permission from role
    object = decrypted_data.get('object')
    
    subject: Subject = None
    permission: Permission = None

    try:
        subject = subject_dao.get_by_username(object)
    except ValueError:
        try:
            permission = permission_dao.get_by_name(object)
        except ValueError:
            return encrypt_payload({
                    "error": f"Subject '{object}' or Permission '{object}' doesn't exist."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.NOT_FOUND
    
    result = None
    
    if subject:
        try:
            if role.name == "Manager":
                managers = role_dao.get_role_subjects("Manager", acl_id)
                if subject in managers and len(managers) == 1:
                    return encrypt_payload({
                            "error": f"Role '{role_name}' must have at least one active subject."
                        }, session_key[:32], session_key[32:]
                    ), HTTP_Code.FORBIDDEN

            role.subjects.remove(subject)
            session_dao.drop_subject_sessions_role(subject.username, role.name)
            result = {
                "data": f"Subject '{subject.username}' removed from role '{role_name}' in organization '{organization_name}' successfully."
            }
        except ValueError:
            return encrypt_payload({
                    "error": f"Subject '{subject.username}' is not associated with role '{role_name}' in organization '{organization_name}'."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.BAD_REQUEST
        
    if permission:
        try:
            if role.name == "Manager":
                return encrypt_payload({
                        "error": f"Role '{role_name}' cannot have its permissions modified."
                    }, session_key[:32], session_key[32:]
                ), HTTP_Code.FORBIDDEN
                
            role.permissions.remove(permission)
            result = {
                "data": f"Permission '{permission.name}' removed from role '{role_name}' in organization '{organization_name}' successfully."
            }
        except ValueError:
            return encrypt_payload({
                    "error": f"Permission '{permission.name}' is not associated with role '{role_name}' in organization '{organization_name}'."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.BAD_REQUEST
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def add_role_permission_to_document(organization_name, document_name, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/documents/<document_name>/roles/<role>/permissions'''
    
    document_dao = DocumentDAO(db_session)
    role_dao = RoleDAO(db_session)
    permission_dao = PermissionDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    # Get document
    document = document_dao.get_metadata(session.id, document_name)
    
    missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_ACL"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    # Get role
    role_name = decrypted_data.get('role')
    role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)
    
    # if role.name == "Manager":
    #     return encrypt_payload({
    #             "error": f"Role '{role_name}' cannot have its permissions modified."
    #         }, session_key[:32], session_key[32:]
    #     ), HTTP_Code.FORBIDDEN

    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return encrypt_payload({
                "error": f"Permission '{permission_name}' is not a valid document permission."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.BAD_REQUEST
    
    permission = permission_dao.get_by_name(permission_name)

    # Add role permission to document
    document_role_permission_dao.create(document.acl.id, role.id, permission.name)
    
    # Construct result
    result = {
        "data": f"Permission '{permission.name}' added to role '{role.name}' in document '{document.name}' in organization '{document.org_name}' successfully."
    }
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def remove_role_permission_from_document(organization_name, document_name, data, db_session):
    '''Handles DELETE requests to /organizations/<organization_name>/documents/<document_name>/roles/<role>/permissions'''
    
    document_dao = DocumentDAO(db_session)
    role_dao = RoleDAO(db_session)
    permission_dao = PermissionDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    # Get document
    document = document_dao.get_metadata(session.id, document_name)

    missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_ACL"])
    if missing_permissions != []:
        return encrypt_payload({
                "error": f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}"
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.FORBIDDEN

    # Get role
    role_name = decrypted_data.get('role')
    role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)
    
    # if role.name == "Manager":
    #     return encrypt_payload({
    #             "error": f"Role '{role_name}' cannot have its permissions modified."
    #         }, session_key[:32], session_key[32:]
    #     ), HTTP_Code.FORBIDDEN

    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return encrypt_payload({
                "error": f"Permission '{permission_name}' is not a valid document permission."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.BAD_REQUEST
    
    permission = permission_dao.get_by_name(permission_name)
    
    if permission.name == "DOC_ACL":
        roles_with_doc_acl = document_role_permission_dao.get_roles_by_document_acl_id_and_permission_name(document.acl.id, permission.name)
        if len(roles_with_doc_acl) == 1:
            return encrypt_payload({
                    "error": f"Role '{role.name}' is the only role with permission '{permission.name}' in document '{document.name}' in organization '{document.org_name}'."
                }, session_key[:32], session_key[32:]
            ), HTTP_Code.BAD_REQUEST
    
    # Remove role permission from document
    document_role_permission: DocumentRolePermission = document_role_permission_dao.get_by_document_acl_id_and_role_id_and_permission_name(document.acl.id, role.id, permission.name)
    if not document_role_permission:
        return encrypt_payload({
                "error": f"Permission '{permission.name}' is not associated with role '{role.name}' in document '{document.name}' in organization '{document.org_name}'."
            }, session_key[:32], session_key[32:]
        ), HTTP_Code.BAD_REQUEST
    
    document_role_permission_dao.delete_by_id(document_role_permission.id)
    
    # Construct result
    result = {
        "data": f"Permission '{permission.name}' removed from role '{role.name}' in document '{document.name}' in organization '{document.org_name}' successfully."
    }
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    
    return encrypted_result, HTTP_Code.OK

# -------------------------------

def list_roles_per_permission(organization_name, permission, data, db_session):
    '''Handles GET requests to /organizations/<organization_name>/permissions/<permission>/roles'''
    
    role_dao = RoleDAO(db_session)
    permission_dao = PermissionDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    document_permission = permission in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_name = organization.name
    org_acl_id = organization.acl.id

    # Get permission
    permission = permission_dao.get_by_name(permission)
    document_roles_permission = []
    serializable_document_roles = []
    
    if document_permission: # Get, for each document, the roles that have the given permission
        document_roles_permission = document_role_permission_dao.get_document_roles_by_permission_and_org(permission.name, org_name)
        for doc_name, roles in document_roles_permission.items():
            if roles != []:
                serializable_document_roles.append({
                    "document_name": doc_name,
                    "roles": roles
                })
    else:
        document_roles_permission = role_dao.get_by_acl_id_and_permission(org_acl_id, permission.name)
        serializable_document_roles = [role.__repr__() for role in document_roles_permission]
    
    # Construct result
    result = {
        "document_permission": document_permission,
        "data": serializable_document_roles,
    }
    

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, HTTP_Code.OK

# ========================================================================================= #

