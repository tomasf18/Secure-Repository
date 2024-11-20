import base64
import secrets
from dao.OrganizationDAO import OrganizationDAO, SessionDAO
from dao.DocumentDAO import DocumentDAO
# from dao.SessionDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from utils.utils import decrypt_payload, encrypt_payload, verify_message_order
from utils.loadSession import load_session
from dao.DocumentDAO import DocumentDAO
from models.orm import Organization, Subject, Document
from models.status import Status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import json
import base64

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

def create_organization(data, db_session: Session):
    '''Handles POST requests to /organizations'''
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    org_name = data.get('organization')
    username = data.get('username')
    name = data.get('name')
    email = data.get('email')
    public_key: bytes = base64.b64decode(data.get('public_key'))

    try:
        organization_dao.create(org_name, username, name, email, public_key)
    except IntegrityError:
        return json.dumps(f"Organization with name '{org_name}' already exists."), 400
    
    
    return json.dumps(f'Organization {org_name} created successfully'), 201

def add_organization_subject(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    ## Get session
    try:
        from utils.loadSession import load_session
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
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

    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": f'Subject {username} added to organization {organization_name} successfully'
    }

    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200


def list_organization_subjects(organization_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    ## Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    try:
        subjects: list["Subject"] = organization_dao.get_subjects(organization_name)
        serializable_subjects = []
        for subject in subjects:
            status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
            serializable_subjects.append({
                "username": subject.username,
                "status": status
            })
    except Exception as e:
        ## TODO: Fix error message
        return encrypt_payload({
                    "error": str(e)
                }, session_key[:32], session_key[32:]
            ), 400
    
    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": serializable_subjects
    }

    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200


def get_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    ## Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code

    subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    status = organization_dao.get_org_subj_association(org_name=organization_name, username=username).status

    ## Create result
    result = {
        "nonce": secrets.token_hex(16),
        "data": {
            "username": subject.username,
            "status": status
        }
    }
    
    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])

    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200
    
def activate_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
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
    
    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": f"Subject '{username}' in the organization '{organization_name}' has been activated."
    }

    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    return json.dumps(encrypted_result), 200
    

def suspend_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
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
    
    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": f"Subject '{username}' in the organization '{organization_name}' has been suspended."
    }

    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200

def create_organization_document(organization_name, data, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/documents'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session)
    key_store_dao = KeyStoreDAO(db_session)

    ## Get session
    try:
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code


    document_name = decrypted_data.get('document_name')
    encrypted_data = base64.b64decode(decrypted_data.get('file'))
    alg = decrypted_data.get('alg')
    key = base64.b64decode(decrypted_data.get('key'))
    iv = base64.b64decode(decrypted_data.get('iv'))
    
    organization_dao.create_document(document_name, session.id, encrypted_data, alg, key.decode(), iv.decode())

    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": f"Document '{document_name}' uploaded in the organization '{organization_name}' successfully."
    }

    ## Update session
    session_dao.update_nonce(session.id, result["nonce"])
    session_dao.update_counter(session.id, decrypted_data["counter"])
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])
    return encrypted_result, 201

def list_organization_documents(organization_name, data, username, date_filter, date, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents'''
    document_dao = DocumentDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    documents: list["Document"] = document_dao.get(session_id, username, date_filter, date)
    if not documents:
        return json.dumps({"error": "No documents found."}), 404
    serializable_documents = []
    for doc in documents:
        serializable_documents.append({
            "document_name": doc.name,
        })
    return json.dumps(serializable_documents), 200

# =================================== Auxiliar Function =================================== #

def get_serializable_document(document: "Document"):
    return {
        "document_name": document.name,
        "create_date": document.create_date.strftime("%Y-%m-%d %H:%M:%S"),
        "file_handle": document.file_handle,
        "creator_username": document.creator_username,
        "deleter_username": document.deleter_username,
        "organization": document.org_name,
        "encryption_data": {
            "algorithm": document.restricted_metadata.alg,
            "mode": document.restricted_metadata.mode,
            "key": base64.b64encode(document.restricted_metadata.key).decode(),
            "iv": base64.b64encode(document.restricted_metadata.iv).decode()
        }
    }

# ========================================================================================= #

def get_organization_document_metadata(organization_name, document_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents/<document_name>'''
    document_dao = DocumentDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    document: "Document" = document_dao.get_metadata(session_id, document_name)
    serializable_document = get_serializable_document(document)
    return json.dumps(serializable_document), 200

def get_organization_document_file(organization_name, document_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/documents/<document_name>/file'''
    document_dao = DocumentDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    document: "Document" = document_dao.get_metadata(session_id, document_name)
    if not document.file_handle:
        return json.dumps({"error": f"Document '{document_name}' does not have an associated file handle in Organization: '{organization_name}'."}), 404
    serializable_document = get_serializable_document(document)
    return json.dumps(serializable_document), 200

def delete_organization_document(organization_name, document_name, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/documents/<document_name>'''
    document_dao = DocumentDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    ceasing_file_handle = document_dao.delete(session_id, document_name)
    return json.dumps(f"Document '{document_name}' with file_handle '{ceasing_file_handle}' deleted from organization '{organization_name}' successfully."), 200