import base64
import secrets
from dao.OrganizationDAO import OrganizationDAO
from server.dao import SessionDAO
from server.utils.utils import decrypt_payload, encrypt_payload, verify_message_order
from models.orm import Organization
from models.orm import Subject
from models.status import Status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import json

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

<<<<<<< Updated upstream
def list_organization_subjects(organization_name, db_session: Session):
=======
def add_organization_subject(data, organization_name, db_session: Session):
    '''Handles POST requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session);

    ## Get session
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    if session is None:
        return json.dumps(f"Session with id {session_id} not found"), 404
    
    ## Decrypt data
    session_key = base64.b64decode(session.key)
    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        return json.dumps(f"Invalid session key"), 403

    if (not verify_message_order(decrypted_data)):
        return json.dumps(f"Invalid message order"), 403
    
    organization_name = session.organization_name

    data = data.get("data")
    username = data.get('username')
    name = data.get('name')
    email = data.get('email')
    public_key = data.get('public_key')
    
    try:
        organization_dao.add_subject_to_organization(organization_name, username, name, email, public_key)
    except IntegrityError:
        return json.dumps(f"Subject with username '{username}' already exists."), 400
    

    ## Construct result
    result = {
        "nonce": base64.b64encode(secrets.token_hex(16)).decode("utf-8"),
        "data": f'Subject {username} added to organization {organization_name} successfully'
    }

    ## Update session
    session_dao.update_nonce(session_id, result["nonce"]) # TODO implement
    session_dao.update_counter(session_id, decrypted_data["counter"]+1) # TODO implement
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 201

def list_organization_subjects(organization_name, data, db_session: Session):
>>>>>>> Stashed changes
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    session_dao = SessionDAO(db_session);

    ## Get session
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    if session is None:
        return json.dumps(f"Session with id {session_id} not found"), 404
    
    ## Decrypt data
    session_key = base64.b64decode(session.key)
    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        return json.dumps(f"Invalid session key"), 403

    if (not verify_message_order(decrypted_data)):
        return json.dumps(f"Invalid message order"), 403
    
    organization_name = session.organization_name

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
        "nonce": base64.b64encode(secrets.token_hex(16)).decode("utf-8"),
        "data": serializable_subjects
    }

    ## Update session
    session_dao.update_nonce(session_id, result["nonce"]) # TODO implement
    session_dao.update_counter(session_id, decrypted_data["counter"]+1) # TODO implement
    
    ## Encrypt result
    encrypted_result = encrypt_payload(result, session_key[:32], session_key[32:])

    return json.dumps(encrypted_result), 200


def get_organization_subject(data, organization_name, username, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    status = organization_dao.get_org_subj_association(org_name=organization_name, username=username).status
    return json.dumps({
        "username": subject.username,
        "status": status
    }), 200
    
def activate_organization_subject(organization_name, username, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    organization_dao.update_org_subj_association_status(organization_name, username, Status.ACTIVE.value)
    return json.dumps(f"Subject '{username}' in the organization '{organization_name}' has been activated."), 200

def suspend_organization_subject(organization_name, username, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    organization_dao.update_org_subj_association_status(organization_name, username, Status.SUSPENDED.value)
    return json.dumps(f"Subject '{username}' in the organization '{organization_name}' has been suspended."), 200