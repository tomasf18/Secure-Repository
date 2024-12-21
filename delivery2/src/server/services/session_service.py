import os
import json
import base64
import secrets

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession

from dao.RoleDAO import RoleDAO
from dao.SessionDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from dao.RepositoryDAO import RepositoryDAO
from dao.OrganizationDAO import OrganizationDAO

from utils.server_session_utils import exchange_keys
from utils.cryptography.auth import sign, verify_signature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from utils.server_session_utils import load_session, session_expired

from utils.constants.http_code import HTTP_Code
from utils.utils import return_data

from models.status import Status

# -------------------------------

def create_session(data, db_session: SQLAlchemySession):
    """Handles the exchange of keys and the creation of the session between the client and the repository.

    Args:
        data (_type_): Data received from the client
        db_session (SQLAlchemySession): Database session

    Returns:
        response: Response to be sent to the client
    """
    
    # Init DAO's
    session_dao = SessionDAO(db_session)
    repository_dao = RepositoryDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    keystore_dao = KeyStoreDAO(db_session)
    
    # Get repository private key using the respective password to decrypt it
    rep_priv_key_password: str = os.getenv('REP_PRIV_KEY_PASSWORD')
    rep_priv_key: ec.EllipticCurvePrivateKey = serialization.load_pem_private_key(
        data=repository_dao.get_private_key(), 
        password=rep_priv_key_password.encode()
    )

    # Read client data from request and load it
    msg_data = data.get("data")
    client_session_pub_key = msg_data.get("public_key")
    org_name = msg_data.get('organization')
    username = msg_data.get('username')

    # Verify if there is no active session for the user in the organization
    last_session_user_org = session_dao.get_last_session_of_user_in_org(username, org_name)
    if last_session_user_org is not None:
        if not session_expired(last_session_user_org):
            return json.dumps({"error": f"Session for user '{username}' in organization '{org_name}' already exists."}), HTTP_Code.BAD_REQUEST

    try:
        client = organization_dao.get_org_subj_association(
            org_name=org_name,
            username=username
        )
        if client.status == Status.SUSPENDED.value:
            return json.dumps({"error": f"User '{username}' is suspended."}), HTTP_Code.FORBIDDEN
    except ValueError as e:
        message = e.args[0]
        return return_data("error", message, HTTP_Code.NOT_FOUND) 

    if (client is None):
        return return_data("error", f"User not found!", HTTP_Code.NOT_FOUND)
    
    # Get client public key
    client_pub_key = keystore_dao.get_by_id(client.pub_key_id).key

    # Verify Signature
    if (not verify_signature(data=data, pub_key=client_pub_key)):
        return return_data("error", f"Invalid signature!", HTTP_Code.BAD_REQUEST)

    # Derive session key
    session_key: bytes
    session_server_public_key: bytes
    session_key, session_server_public_key = exchange_keys(client_session_public_key=base64.b64decode(client_session_pub_key))

    ## Create session
    nonce = secrets.token_hex(16) 
    try:
        session = session_dao.create(
            username, 
            org_name, 
            session_key,
            counter = 0,    # for replay attack prevention
            nonce = nonce,  # for unique session identification
        )
    except IntegrityError:
        return return_data("error", f"Session for user '{username}' already exists.", HTTP_Code.BAD_REQUEST)

    # Create response
    result = {
        "session_id": session.id,
        "username": session.subject_username,
        "organization": session.organization_name,
        "roles": [role.name for role in session.session_roles],
        "public_key": base64.b64encode(session_server_public_key).decode('utf-8'), # So that the client can generate the shared secret (key for the session symmetric encryption)
        "nonce": nonce,
    }

    # Sign response
    signature = sign(
        data = str(result),
        private_key = rep_priv_key,
    )

    # Finish response packet
    result = json.dumps({
        "data": result,
        "signature": base64.b64encode(signature).decode('utf-8')
    })
    
    # Return response to the client
    return result, HTTP_Code.CREATED

# -------------------------------

def session_assume_role(organization_name, session_id, role, data, db_session):
    ''' Handles the addition of a role to a session. 
    
    Args:
        role (str): The role to be added to the session
        data (_type_): Data received from the client
        db_session (SQLAlchemySession): Database session
        
    Returns:
        response: Response to be sent to the client
    '''
    
    session_dao = SessionDAO(db_session)
    role_dao = RoleDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key)
    
    # Verify if the subject is bound to the role in the organization
    session_subject = session.subject
    organization = session.organization
    
    try:
        subjects_with_role = role_dao.get_role_subjects(role, organization.acl.id)
    except Exception as e:
        message = e.args[0]
        return return_data("error", message, HTTP_Code.NOT_FOUND, session_key)
        
    if session_subject not in subjects_with_role:
        return return_data(
            key="error",
            data=f"Subject '{session_subject.username}' is not bound to role '{role}' in organization '{organization_name}'",
            code=HTTP_Code.FORBIDDEN,
            session_key=session_key
        )
        
    role = role_dao.get_by_name_and_acl_id(role, organization.acl.id)
    
    if role.status == Status.SUSPENDED.value:
        return return_data(
            key="error",
            data=f"Role '{role.name}' is suspended, therefore can not be assumed.",
            code=HTTP_Code.FORBIDDEN,
            session_key=session_key
        )
    
    try:
        role_added = session_dao.add_session_role(session.id, role.name)
    except ValueError as e:
        message = e.args[0]
        return return_data(
            key="error",
            data=message,
            code=HTTP_Code.FORBIDDEN,
            session_key=session_key
        )
    
    # Construct result
    result = {
        "roles": [role.name for role in session.session_roles],
        "data": f"Role '{role_added.__repr__()}' added to the session with user '{session.subject_username}' in organization '{session.organization_name}'"
    }  

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])

    return return_data("data", result, HTTP_Code.OK, session_key)

# -------------------------------

def session_drop_role(organization_name, session_id, role, data, db_session):
    ''' Handles the addition of a role to a session. 
    
    Args:
        role (str): The role to be added to the session
        data (_type_): Data received from the client
        db_session (SQLAlchemySession): Database session
        
    Returns:
        response: Response to be sent to the client
    '''
    
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data("error", message, code, session_key=session_key)
    
    try:
        role_removed = session_dao.drop_session_role(session.id, role)
        # Nao ha exception a ser chamada
    except ValueError as e:
        message = e.args[0]
        return return_data(
            key = "error",
            data = message,
            code = HTTP_Code.FORBIDDEN,
            session_key = session_key
        )

    # Construct result
    result = {
        "roles": [role.name for role in session.session_roles],
        "data": f"Role '{role_removed.__repr__()}' removed from the session with user '{session.subject_username}' in organization '{session.organization_name}'"
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])
        
    return return_data("data", result, HTTP_Code.OK, session_key)

# -------------------------------

def list_session_roles(organization_name, session_id, data, db_session):
    ''' Handles the listing of roles from a session. «
    
    Args:
        data (_type_): Data received from the client
        db_session (SQLAlchemySession): Database session
        
    Returns:
        response: Response to be sent to the client
    '''
    
    session_dao = SessionDAO(db_session)

    try:
        decrypted_data, session, session_key = load_session(data, db_session, organization_name)
    except ValueError as e:
        message, code, session_key = e.args
        return return_data(
            key = "error",
            data = message,
            code = code,
            session_key=session_key
        )
    
    # Construct result
    roles =  {
        "roles": [role.name for role in session.session_roles]
    }

    # Update session
    session_dao.update_counter(session.id, decrypted_data["counter"])

    return return_data(
        key="data",
        data=roles,
        code=HTTP_Code.OK,
        session_key=session_key
    )