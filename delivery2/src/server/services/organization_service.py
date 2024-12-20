import hashlib
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
from utils.cryptography.AES import AES, AESModes

from utils.constants.http_code import HTTP_Code
from utils.utils import convert_bytes_to_str, convert_str_to_bytes, return_data

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
    except ValueError:
        return return_data("error", f"Organization '{org_name}' already exists.", HTTP_Code.BAD_REQUEST)
    
    return return_data("data", f"Organization '{org_name}' created successfully.", HTTP_Code.CREATED)

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
    return return_data("data", serializable_organizations, HTTP_Code.OK)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

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
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    return return_data("data", serializable_subjects, HTTP_Code.OK, session_key)

# -------------------------------

def get_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    try:
        subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    except Exception as e:
        return return_data("error", f"Subject '{username}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)
        
    status = organization_dao.get_org_subj_association(org_name=organization_name, username=username).status

    # Create result
    result = {
        "username": subject.username,
        "status": status
    }
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])

    return return_data("data", result, HTTP_Code.OK, session_key)

# -------------------------------

def add_organization_subject(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/subjects'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    
    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_NEW"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
        
    username = decrypted_data.get('username')
    name = decrypted_data.get('name')
    email = decrypted_data.get('email')
    public_key = base64.b64decode(decrypted_data.get('public_key'))
    
    try:
        organization_dao.add_subject_to_organization(organization_name, username, name, email, public_key)
    except IntegrityError:
        return return_data("error", f"Subject with username '{username}' already exists.", HTTP_Code.BAD_REQUEST, session_key)
    except Exception as e:
        print("Some error occurred adding subject to organization")
        print(e)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    return return_data("data", f'Subject {username} added to organization {organization_name} successfully', HTTP_Code.OK, session_key)

# -------------------------------

def suspend_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''

    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_DOWN"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
    
    try:
        if organization_dao.subject_has_role(organization_name, username, "Manager"):
            return return_data("error", f"Subject '{username}' is a Manager and cannot be suspended.", HTTP_Code.FORBIDDEN, session_key)
    except Exception as e:
        return return_data("error", f"Subject '{username}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)
        
    organization_dao.update_org_subj_association_status(organization_name, username, Status.SUSPENDED.value)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Subject '{username}' in the organization '{organization_name}' has been suspended.", HTTP_Code.OK, session_key)
    
# -------------------------------
    
def activate_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["SUBJECT_UP"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    try:    
        if organization_dao.subject_has_role(organization_name, username, "Manager"):
            return return_data("error", f"Subject '{username}' is a Manager, therefore it is always active.", HTTP_Code.FORBIDDEN, session_key)
    except Exception as e:
        return return_data("error", f"Subject '{username}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)
    
    organization_dao.update_org_subj_association_status(organization_name, username, Status.ACTIVE.value)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Subject '{username}' in the organization '{organization_name}' has been activated.", HTTP_Code.OK, session_key)
    
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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["DOC_NEW"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
    
    document_name = decrypted_data.get('document_name')
    file_handle = decrypted_data.get('file_handle')

    encrypted_file_content = convert_str_to_bytes(decrypted_data.get('file'))
    alg, mode = decrypted_data.get('alg').split("-")
    key = convert_str_to_bytes(decrypted_data.get('key'))
    iv = convert_str_to_bytes(decrypted_data.get('iv'))

    # Decrypt file
    if alg == "AES256":
        if mode == "CBC":
            decryptor = AES(AESModes.CBC)
    
    decrypted_file = decryptor.decrypt_data(encrypted_data=encrypted_file_content, key=key, iv=iv)
    
    # Verify if file_handle == digest(decrypted_file)
    digest = hashlib.sha256(decrypted_file).hexdigest()
    if file_handle != digest:
        return return_data(
            key="error",
            data=f"Received file does not match sent file!",
            code=HTTP_Code.BAD_REQUEST,
            session_key=session_key    
        )

    new_document = document_dao.create_document(document_name, session.id, digest, encrypted_file_content, alg, mode, key, iv)
    
    # Get Manager role
    organization = organization_dao.get_by_name(organization_name)
    role_to_add_doc_permissions = session.session_roles[0]

    # Give all the document permissions to the Manager role
    document_role_permission_dao.add_all_doc_permissions_to_role(new_document.acl.id, role_to_add_doc_permissions.id)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Document '{document_name}' uploaded in the organization '{organization_name}' successfully.", HTTP_Code.CREATED, session_key)

# -------------------------------

def list_organization_documents(organization_name, data, username, date_filter, date, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents'''
    document_dao = DocumentDAO(db_session)
    session_dao = SessionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    documents: list["Document"] = document_dao.get(session.id, username, date_filter, date)
    if not documents:
        return return_data("error", "No documents found.", HTTP_Code.NOT_FOUND, session_key)

    i = 0
    serializable_documents = []
    for doc in documents:
        i += 1
        serializable_documents.append({
            "document" + str(i): doc.__repr__(),
        })

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", serializable_documents, HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    try:
        document: "Document" = document_dao.get_metadata(session.id, document_name)
        missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_READ"])
        if missing_permissions != []:
            return return_data("error", f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
    except Exception as e:
        return return_data("error", f"Document '{document_name}' doesn't exists in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)
    
    serializable_document = get_serializable_document(document, document_dao)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", serializable_document, HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
        
    try:
        document: "Document" = document_dao.get_metadata(session.id, document_name)
        missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_DELETE"])
        if missing_permissions != []:
            return return_data("error", f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
        ceasing_file_handle = document_dao.delete(session.id, document_name)
    except ValueError as e:
        return return_data("error", e.args[0], HTTP_Code.NOT_FOUND, session_key)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Document '{document_name}' with file_handle '{ceasing_file_handle}' deleted from organization '{organization_name}' successfully.", HTTP_Code.OK, session_key)


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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_NEW"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
    
    # Get organization, acl_id and new_role
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id
    new_role = decrypted_data.get('new_role')

    try:
        # Create role
        role = role_dao.create(new_role, acl_id)
    except Exception as e:
        return return_data("error", f"Role '{new_role}' already exists in the organization '{organization_name}'.", HTTP_Code.BAD_REQUEST, session_key)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Role '{role.__repr__()}' created in the organization '{organization_name}' successfully.", HTTP_Code.CREATED, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    # # Get subject
    # subject = organization_dao.get_subject_by_username(organization_name, username)

    try:
        # Get roles
        roles = role_dao.get_by_username_and_acl_id(username, acl_id)
    except Exception as e:
        return return_data("error", f"Roles for username '{username}' not found in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", [role.__repr__() for role in roles], HTTP_Code.OK, session_key) 

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_DOWN"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    if role_name == "Manager":
        return return_data("error", f"Role '{role_name}' cannot be suspended.", HTTP_Code.FORBIDDEN, session_key)
        
    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    role = role_dao.update_role_status(role_name, acl_id, Status.SUSPENDED.value)
    
    # From all sessions where this role is being used, remove it
    session_dao.remove_role_from_all_sessions(role)

    # Update session TODO check pls
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Role '{role.name}' in the organization '{organization_name}' has been suspended.", HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_UP"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)
    
    if role_name == "Manager":
        return return_data("error", f"Role '{role_name}' is always active.", HTTP_Code.FORBIDDEN, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    role = role_dao.update_role_status(role_name, acl_id, Status.ACTIVE.value)

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Role '{role.name}' in the organization '{organization_name}' has been reactivated.", HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    try:
        # Get role
        role = role_dao.get_by_name_and_acl_id(role_name, acl_id)
    except Exception as e:
        return return_data("error", f"Role '{role_name}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", [permission.__repr__() for permission in role.permissions], HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_MOD"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    try:
        # Get role
        role = role_dao.get_by_name_and_acl_id(role_name, acl_id)
    except Exception as e:
        return return_data("error", f"Role '{role_name}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)

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
            return return_data("error", f"Subject '{object}' or Permission '{object}' doesn't exist.", HTTP_Code.NOT_FOUND, session_key)
    
    result = None
    
    if subject:
        if role.name == "Manager":
            org_subj_assoc = organization_dao.get_org_subj_association(organization_name, subject.username)
            if org_subj_assoc.status == Status.SUSPENDED.value:
                return return_data("error", f"Subject '{subject.username}' is suspended and cannot be added to role '{role_name}'.", HTTP_Code.FORBIDDEN, session_key)
            
        role.subjects.append(subject)
        result = f"Subject '{subject.username}' added to role '{role_name}' in organization '{organization_name}' successfully."
        
    if permission:
        if role.name == "Manager":
            return return_data("error", f"Role '{role_name}' cannot have its permissions modified.", HTTP_Code.FORBIDDEN, session_key)
        role.permissions.append(permission)
        result = f"Permission '{permission.name}' added to role '{role_name}' in organization '{organization_name}' successfully."
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", result, HTTP_Code.OK, session_key) 

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    missing_permissions = session_dao.missing_org_permitions(session.id, ["ROLE_MOD"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    acl_id = organization.acl.id

    try:
        # Get role
        role = role_dao.get_by_name_and_acl_id(role_name, acl_id)
    except Exception as e:
        return return_data("error", f"Role '{role_name}' doesn't exist in the organization '{organization_name}'.", HTTP_Code.NOT_FOUND, session_key)

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
            return return_data("error", f"Subject '{object}' or Permission '{object}' doesn't exist.", HTTP_Code.NOT_FOUND, session_key)
    
    result = None
    
    if subject:
        try:
            if role.name == "Manager":
                managers = role_dao.get_role_subjects("Manager", acl_id)
                if subject in managers and len(managers) == 1:
                    return return_data("error", f"Role '{role_name}' must have at least one active subject.", HTTP_Code.FORBIDDEN, session_key)

            role.subjects.remove(subject)
            session_dao.drop_subject_sessions_role(subject.username, role.name)
            result = f"Subject '{subject.username}' removed from role '{role_name}' in organization '{organization_name}' successfully."
        except ValueError:
            return return_data("error", f"Subject '{subject.username}' is not associated with role '{role_name}' in organization '{organization_name}'.", HTTP_Code.BAD_REQUEST, session_key)
        
    if permission:
        try:
            if role.name == "Manager":
                return return_data("error", f"Role '{role_name}' cannot have its permissions modified.", HTTP_Code.FORBIDDEN, session_key)
                
            role.permissions.remove(permission)
            result = f"Permission '{permission.name}' removed from role '{role_name}' in organization '{organization_name}' successfully."
        except ValueError:
            return return_data("error", f"Permission '{permission.name}' is not associated with role '{role_name}' in organization '{organization_name}'.", HTTP_Code.BAD_REQUEST, session_key)
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", result, HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    try:
        # Get document
        document = document_dao.get_metadata(session.id, document_name)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)
    
    missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_ACL"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    # Get role
    role_name = decrypted_data.get('role')
    try:
        role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)
    


    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return return_data("error", f"Permission '{permission_name}' is not a valid document permission.", HTTP_Code.BAD_REQUEST, session_key)
    
    try:
        permission = permission_dao.get_by_name(permission_name)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)
    
    try:    
        # Add role permission to document
        document_role_permission_dao.create(document.acl.id, role.id, permission.name)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.BAD_REQUEST, session_key)
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Permission '{permission.name}' added to role '{role.name}' in document '{document.name}' in organization '{document.org_name}' successfully.", HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    try:
        # Get document
        document = document_dao.get_metadata(session.id, document_name)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)

    missing_permissions = document_role_permission_dao.missing_doc_permissions(session.session_roles, document.acl.id, ["DOC_ACL"])
    if missing_permissions != []:
        return return_data("error", f"Access denied. Missing permissions for document {document.name}: {', '.join(permission.name for permission in missing_permissions)}", HTTP_Code.FORBIDDEN, session_key)

    # Get role
    role_name = decrypted_data.get('role')
    try:
        role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)
    except Exception as e:
        return return_data("error", str(e), HTTP_Code.NOT_FOUND, session_key)
    


    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return return_data("error", f"Permission '{permission_name}' is not a valid document permission.", HTTP_Code.BAD_REQUEST, session_key)
    
    permission = permission_dao.get_by_name(permission_name)

    if permission.name == "DOC_ACL":
        roles_with_doc_acl = document_role_permission_dao.get_roles_by_document_acl_id_and_permission_name(document.acl.id, permission.name)
        if len(roles_with_doc_acl) == 1:
            return return_data(
                key="error",
                data=f"Role '{role.name}' is the only role with permission '{permission.name}' in document '{document.name}' in organization '{document.org_name}'.",
                code=HTTP_Code.BAD_REQUEST,
                session_key=session_key
            )

    # Remove role permission from document
    document_role_permission: DocumentRolePermission = document_role_permission_dao.get_by_document_acl_id_and_role_id_and_permission_name(document.acl.id, role.id, permission.name)
    if not document_role_permission:
        return return_data("error", f"Permission '{permission.name}' is not associated with role '{role.name}' in document '{document.name}' in organization '{document.org_name}'.", HTTP_Code.BAD_REQUEST, session_key)
    
    document_role_permission_dao.delete_by_id(document_role_permission.id)
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    return return_data("data", f"Permission '{permission.name}' removed from role '{role.name}' in document '{document.name}' in organization '{document.org_name}' successfully.", HTTP_Code.OK, session_key)

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
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)

    document_permission = permission in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_name = organization.name
    org_acl_id = organization.acl.id

    try:
        # Get permission
        permission = permission_dao.get_by_name(permission)
    except Exception as e:
        return return_data("error", f"Permission '{permission}' doesn't exist.", HTTP_Code.NOT_FOUND, session_key)
    
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
    return return_data("data", result, HTTP_Code.OK, session_key) 

# ========================================================================================= #

