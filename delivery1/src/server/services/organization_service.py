from dao.OrganizationDAO import OrganizationDAO
from models.orm import Organization
from models.orm import Subject
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
    public_key_file = data.get('public_key')
    
    try:
        organization_dao.create(org_name, username, name, email, public_key_file)
    except IntegrityError:
        return json.dumps(f"Organization with name '{org_name}' already exists."), 400
    
    
    return json.dumps(f'Organization {org_name} created successfully'), 201

def list_organization_subjects(organization_name, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects'''
    organization_dao = OrganizationDAO(db_session)
    subjects: list["Subject"] = organization_dao.get_subjects(organization_name)
    serializable_subjects = []
    for subject in subjects:
        serializable_subjects.append({
            "username": subject.username
        })
    return json.dumps(serializable_subjects), 200

def get_organization_subject(organization_name, username, db_session: Session):
    '''Handles GET requests to /organizations/<organization_name>/subjects/<subject_name>'''
    organization_dao = OrganizationDAO(db_session)
    subject: "Subject" = organization_dao.get_subject_by_username(organization_name, username)
    return json.dumps({
        "username": subject.username
    }), 200