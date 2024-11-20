import base64
from dao.OrganizationDAO import OrganizationDAO
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
    data = data.get("data")
    session_id = data.get('session_id')
    username = data.get('username')
    name = data.get('name')
    email = data.get('email')
    public_key = data.get('public_key')
    
    try:
        organization_dao.add_subject_to_organization(organization_name, username, name, email, public_key)
    except IntegrityError:
        return json.dumps(f"Subject with username '{username}' already exists."), 400
    
    return json.dumps(f'Subject {username} added to organization {organization_name} successfully'), 201

def list_organization_subjects(organization_name, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    subjects: list["Subject"] = organization_dao.get_subjects(organization_name)
    serializable_subjects = []
    for subject in subjects:
        status = organization_dao.get_org_subj_association(org_name=organization_name, username=subject.username).status
        serializable_subjects.append({
            "username": subject.username,
            "status": status
        })
    return json.dumps(serializable_subjects), 200

def get_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    status = organization_dao.get_org_subj_association(org_name=organization_name, username=username).status
    return json.dumps({
        "username": subject.username,
        "status": status
    }), 200
    
def activate_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles PUT requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    organization_dao.update_org_subj_association_status(organization_name, username, Status.ACTIVE.value)
    return json.dumps(f"Subject '{username}' in the organization '{organization_name}' has been activated."), 200

def suspend_organization_subject(organization_name, username, data, db_session: Session):
    '''Handles DELETE requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    data = data.get("data")
    session_id = data.get('session_id')
    organization_dao.update_org_subj_association_status(organization_name, username, Status.SUSPENDED.value)
    return json.dumps(f"Subject '{username}' in the organization '{organization_name}' has been suspended."), 200

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