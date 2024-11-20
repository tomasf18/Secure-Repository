import base64
import secrets
from dao.OrganizationDAO import OrganizationDAO
from dao.SessionDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from utils.utils import decrypt_payload, encrypt_payload, verify_message_order
from models.orm import Organization
from models.orm import Subject
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
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    if session is None:
        return json.dumps(f"Session with id {session_id} not found"), 404
    
    ## Decrypt data
    session_key_id = session.key_id
    session_key = base64.b64decode(key_store_dao.get_by_id(session_key_id).key)

    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])

    if decrypted_data is None:
        return encrypt_payload({
                    "error": f"Invalid session key"
                }, session_key[:32], session_key[32:]
            ), 403

    if (not verify_message_order(decrypted_data, counter=session.counter, nonce=session.nonce)):
        return encrypt_payload({
                    "error": f"Invalid message order"
                }, session_key[:32], session_key[32:]
            ), 403
    
    if organization_name != session.organization_name:
        return encrypt_payload({
                    "error": f"Cannot access organization {organization_name}"
                }, session_key[:32], session_key[32:]
            ), 403
    
    organization_name = session.organization_name

    username = decrypted_data.get('username')
    name = decrypted_data.get('name')
    email = decrypted_data.get('email')
    public_key = base64.b64decode(decrypted_data.get('public_key'))
    
    try:
        organization_dao.add_subject_to_organization(organization_name, username, name, email, public_key)
    except IntegrityError:
        return json.dumps(f"Subject with username '{username}' already exists."), 400
    

    ## Construct result
    result = {
        "nonce": secrets.token_hex(16),
        "data": f'Subject {username} added to organization {organization_name} successfully'
    }

    ## Update session
    session_dao.update_nonce(session_id, result["nonce"])
    session_dao.update_counter(session_id, decrypted_data["counter"])
    
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
        from utils.loadSession import load_session
        decrypted_data, session, session_key = load_session(data, session_dao, key_store_dao, organization_name)
    except ValueError as e:
        message, code = e.args
        return message, code


    subjects: list["Subject"] = organization_dao.get_subjects(organization_name)
    serializable_subjects = []
    for subject in subjects:
        status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
        serializable_subjects.append({
            "username": subject.username,
            "status": status
        })
    
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
        from utils.loadSession import load_session
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
        from utils.loadSession import load_session
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
        from utils.loadSession import load_session
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
    data = data.get("data")
    session_id = data.get('session_id')
    document_name = data.get('document_name')
    encrypted_data = base64.b64decode(data.get('file'))
    alg = data.get('alg')
    key = base64.b64decode(data.get('key'))
    iv = base64.b64decode(data.get('iv'))
    organization_dao.create_document(document_name, session_id, encrypted_data, alg, key, iv)
    return json.dumps(f"Document '{document_name}' uploaded in the organization '{organization_name}' successfully."), 201