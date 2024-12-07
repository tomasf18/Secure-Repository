import json
import base64

from dao.SessionDAO import SessionDAO
from dao.DocumentDAO import DocumentDAO
from dao.OrganizationDAO import OrganizationDAO
from dao.RoleDAO import RoleDAO
from dao.SubjectDAO import SubjectDAO
from dao.PermissionDAO import PermissionDAO
from dao.DocumentRolePermissionDAO import DocumentRolePermissionDAO

from models.status import Status
from models.database_orm import Organization, Subject, Document, Permission, DocumentRolePermission

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

# -------------------------------

def suspend_role_subjects(organization_name, role_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/roles/<role>'''
    
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

    # Suspend role subjects
    subjects_to_be_suspended = role_dao.get_role_subjects(role_name, acl_id)
    
    for subject in subjects_to_be_suspended:
        organization_dao.update_org_subj_association_status(organization_name, subject.username, Status.SUSPENDED.value)

    serializable_suspended_subjects = []
    for subject in subjects_to_be_suspended:
        status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
        serializable_suspended_subjects.append({
            "username": subject.username,
            "status": status
        })
    
    # Construct result
    result = {
        "data": serializable_suspended_subjects
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200

# -------------------------------

def reactivate_role_subjects(organization_name, role_name, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/roles/<role>'''
    
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

    # Reactivate role subjects
    subjects_to_be_reactivated = role_dao.get_role_subjects(role_name, acl_id)
    
    for subject in subjects_to_be_reactivated:
        organization_dao.update_org_subj_association_status(organization_name, subject.username, Status.ACTIVE.value)

    serializable_reactivated_subjects = []
    for subject in subjects_to_be_reactivated:
        status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
        serializable_reactivated_subjects.append({
            "username": subject.username,
            "status": status
        })
    
    # Construct result
    result = {
        "data": serializable_reactivated_subjects
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200

# -------------------------------

def get_role_permissions(organization_name, role_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/roles/<role>/subject-permissions'''
    
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
    
    return encrypted_result, 200

# -------------------------------
    # data = {
    #     "session_id": session_id,
    #     "counter": session_file_content["counter"] + 1,
    #     "nonce": session_file_content["nonce"],
    #     "object": object, -> Object: username or permission ID/name (e.g. DOC_READ, DOC_WRITE, ...)
    # }

def add_subject_or_permission_to_role(organization_name, role_name, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/roles/<role>/subject-permissions'''
    
    role_dao = RoleDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    subject_dao = SubjectDAO(db_session)
    permission_dao = PermissionDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

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
            ), 400
    
    result = None
    
    if subject:
        role.subjects.append(subject)
        result = {
            "data": f"Subject '{subject.username}' added to role '{role_name}' in organization '{organization_name}' successfully."
        }
        
    if permission:
        role.permissions.append(permission)
        result = {
            "data": f"Permission '{permission.name}' added to role '{role_name}' in organization '{organization_name}' successfully."
        }
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200

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
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

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
            ), 400
    
    result = None
    
    if subject:
        try:
            role.subjects.remove(subject)
            result = {
                "data": f"Subject '{subject.username}' removed from role '{role_name}' in organization '{organization_name}' successfully."
            }
        except ValueError:
            return encrypt_payload({
                    "error": f"Subject '{subject.username}' is not associated with role '{role_name}' in organization '{organization_name}'."
                }, session_key[:32], session_key[32:]
            ), 400
        
    if permission:
        try:
            role.permissions.remove(permission)
            result = {
                "data": f"Permission '{permission.name}' removed from role '{role_name}' in organization '{organization_name}' successfully."
            }
        except ValueError:
            return encrypt_payload({
                    "error": f"Permission '{permission.name}' is not associated with role '{role_name}' in organization '{organization_name}'."
                }, session_key[:32], session_key[32:]
            ), 400
        
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    return encrypted_result, 200

# -------------------------------
# class DocumentRolePermissionDAO(BaseDAO):
#     """DAO for managing DocumentRolePermission entities."""
    
#     def __init__(self, session):
#         super().__init__(session)
        
#     def create(self, document_acl_id: int, role_id: int, permission_name: str) -> DocumentRolePermission:
#         """ Create a new DocumentRolePermission entry. """
#         try:
#             new_document_role_permission = DocumentRolePermission(
#                 document_acl_id=document_acl_id,
#                 role_id=role_id,
#                 permission_name=permission_name
#             )
#             self.session.add(new_document_role_permission)
#             self.session.commit()
#             return new_document_role_permission
#         except IntegrityError:
#             self.session.rollback()
#             raise ValueError(f"DocumentRolePermission associated with document_acl_id '{document_acl_id}', role_id '{role_id}', permission_name '{permission_name}' already exists.")
        
#     def get_by_document_acl_id(self, document_acl_id):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id).all()
    
#     def get_by_role_id(self, role_id):
#         return self.session.query(self.model).filter(self.model.role_id == role_id).all()
    
#     def get_by_permission_name(self, permission_name):
#         return self.session.query(self.model).filter(self.model.permission_name == permission_name).all()
    
#     def get_by_document_acl_id_and_role_id(self, document_acl_id, role_id):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.role_id == role_id).all()
    
#     def get_by_document_acl_id_and_permission_name(self, document_acl_id, permission_name):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.permission_name == permission_name).all()
    
#     def get_by_role_id_and_permission_name(self, role_id, permission_name):
#         return self.session.query(self.model).filter(self.model.role_id == role_id, self.model.permission_name == permission_name).all()
    
#     def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.role_id == role_id, self.model.permission_name == permission_name).all()
    
#     def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.role_id == role_id, self.model.permission_name == permission_name).all()
    
#     def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.role_id == role_id, self.model.permission_name == permission_name).all()
    
#     def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name):
#         return self.session.query(self.model).filter(self.model.document_acl_id == document_acl_id, self.model.role_id == role_id, self.model.permission_name == permission_name).all()
    
# class DocumentRolePermission(Base):
#     __tablename__ = "document_role_permission"
    
#     id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
#     document_acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'), nullable=False)
#     role_id: Mapped[int] = mapped_column(ForeignKey('role.id'), nullable=False)
#     permission_name: Mapped[str] = mapped_column(ForeignKey('permission.name'), nullable=False)
    
#     # Relationships
#     role: Mapped["Role"] = relationship()
#     permission: Mapped["Permission"] = relationship()
#     document_acl: Mapped["DocumentACL"] = relationship(back_populates="permissions")
    
#     __table_args__ = (
#         UniqueConstraint("document_acl_id", "role_id", "permission_name", name="uq_doc_acl_role_permission"),
#     )
    
#     def __repr__(self):
#         return f"<DocumentRolePermission(document_acl_id={self.document_acl_id}, role_id={self.role_id}, permission_name={self.permission_name})>"


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
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    # Get document
    document = document_dao.get_metadata(session.id, document_name)

    # Get role
    role_name = decrypted_data.get('role')
    role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)

    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return encrypt_payload({
                "error": f"Permission '{permission_name}' is not a valid document permission."
            }, session_key[:32], session_key[32:]
        ), 400
    
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
    
    return encrypted_result, 200

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
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    # Get organization
    organization = organization_dao.get_by_name(organization_name)
    org_acl_id = organization.acl.id

    # Get document
    document = document_dao.get_metadata(session.id, document_name)

    # Get role
    role_name = decrypted_data.get('role')
    role = role_dao.get_by_name_and_acl_id(role_name, org_acl_id)

    # Get permission
    permission_name = decrypted_data.get('permission')
    if permission_name not in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
        return encrypt_payload({
                "error": f"Permission '{permission_name}' is not a valid document permission."
            }, session_key[:32], session_key[32:]
        ), 400
    
    permission = permission_dao.get_by_name(permission_name)

    # Remove role permission from document
    document_role_permission: DocumentRolePermission = document_role_permission_dao.get_by_document_acl_id_and_role_id_and_permission_name(document.acl.id, role.id, permission.name)
    if not document_role_permission:
        return encrypt_payload({
                "error": f"Permission '{permission.name}' is not associated with role '{role.name}' in document '{document.name}' in organization '{document.org_name}'."
            }, session_key[:32], session_key[32:]
        ), 400
    
    document_role_permission_dao.delete_by_id(document_role_permission.id)
    
    # Construct result
    result = {
        "data": f"Permission '{permission.name}' removed from role '{role.name}' in document '{document.name}' in organization '{document.org_name}' successfully."
    }
    
    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    # Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    
    
    return encrypted_result, 200

# -------------------------------


# This function lists the roles of the organization with which I have currently a session that have a given permission. 
# Use the names previously referred for the permission rights.
# As roles can be used in documents’ ACLs to associate subjects to permissions, this command should also list the roles 
# per document that have the given permission. Note: permissions for documents are different from the other organization permissions.
# Doc permissions: DOC_ACL, DOC_READ, DOC_DELETE
# All permissions: "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
# doc permissions: "DOC_ACL", "DOC_READ", "DOC_DELETE"
# other organization permissions: "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"

def list_roles_per_permission(organization_name, permission, data, db_session):
    '''Handles GET requests to /organizations/<organization_name>/permissions/<permission>/roles'''
    
    role_dao = RoleDAO(db_session)
    permission_dao = PermissionDAO(db_session)
    document_role_permission_dao = DocumentRolePermissionDAO(db_session)
    session_dao = SessionDAO(db_session)
    organization_dao = OrganizationDAO(db_session)

    # Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, organization_name)
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
    
    return encrypted_result, 200

# ========================================================================================= #

