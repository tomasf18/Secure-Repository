import os
import json
import base64
import secrets

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession

from dao.SessionDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from dao.RepositoryDAO import RepositoryDAO
from dao.OrganizationDAO import OrganizationDAO

from utils.server_session_utils import exchange_keys
from utils.cryptography.auth import sign, verify_signature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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

    try:
        client = organization_dao.get_org_subj_association(
            org_name=org_name,
            username=username
        )
    except ValueError as e:
        message = e.args[0]
        return json.dumps({"error:": message}), 404

    if (client is None):
        return json.dumps(f"User not found!"), 404
    
    # Get client public key
    client_pub_key = keystore_dao.get_by_id(client.pub_key_id).key

    # Verify Signature
    if (not verify_signature(data=data, pub_key=client_pub_key)):
        return json.dumps(f"Invalid signature!"), 400

    # Derive session key
    session_key: bytes
    session_server_public_key: bytes
    session_key, session_server_public_key = exchange_keys(client_session_public_key=base64.b64decode(client_session_pub_key))

    print(f"\n\nSERVER: SHARED SECRET: {session_key}\n\n")
    
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
        return json.dumps(f"Session for user '{username}' already exists."), 400

    ## Create response
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
    print(f"\n\nResult: {result}\n\n")
    return result, 201