from dao.SessionDAO import SessionDAO
from models.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession
import json
import secrets

def create_session(data, db_session: SQLAlchemySession):
    '''Handles POST requests to /sessions'''
    session_dao = SessionDAO(db_session)
    org_name = data.get('organization')
    username = data.get('username')
    
    try:
        session = session_dao.create(username, org_name, secrets.token_hex(64))
    except IntegrityError:
        return json.dumps(f"Session for user '{username}' already exists."), 400
    
    result = json.dumps({
        "session_id": session.id,
        "username": session.subject_username,
        "organization": session.organization_name,
        "roles": [role.name for role in session.session_roles]
    })
    
    return result, 201