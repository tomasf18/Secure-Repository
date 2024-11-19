import base64
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession
import json
import secrets
import os
from dao.RepositoryDAO import RepositoryDAO
from dao.OrganizationDAO import OrganizationDAO 
from dao.SessionDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from models.orm import Session
from utils.keyExchange import exchangeKeys
from utils.signing import verify_doc_sign, sign_document
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def create_session(data, db_session: SQLAlchemySession):
    '''Handles POST requests to /sessions'''
    ## Init DAO's
    session_dao = SessionDAO(db_session)
    repository_dao = RepositoryDAO(db_session)
    organization_dao = OrganizationDAO(db_session)
    keystore_dao = KeyStoreDAO(db_session)
    
    ## Get repository private key
    rep_priv_key_password: str = os.getenv('REP_PRIV_KEY_PASSWORD')
    rep_priv_key: ec.EllipticCurvePrivateKey = serialization.load_pem_private_key(
        data=repository_dao.get_private_key().encode(), 
        password=rep_priv_key_password.encode()
    )

    ## Read client data from request and load it
    msgData = data.get("data")
    client_session_pub_key = msgData.get("public_key")
    org_name = msgData.get('organization')
    username = msgData.get('username')
    client = organization_dao.get_org_subj_association(
        org_name=org_name,
        username=username
    )

    if (client is None):
        # No user found
        return json.dumps(f"No user found!"), 404
    
    ## Get client public key
    client_pub_key = keystore_dao.get_by_id(client.pub_key_id).key

    ## Verify Signature
    if (not verify_doc_sign(data = data, pub_key = client_pub_key)):
        # Send bad credentials
        return json.dumps(f"Invalid signature!"), 400


    ## Derive session key
    sessionKey: bytes
    public_key: bytes
    sessionKey, public_key = exchangeKeys(
        client_session_key=base64.b64decode(client_session_pub_key),
    )


    ## Create session
    # TODO: Encrypt sessionKey 
    encryptedSessionKey = sessionKey
    try:
        session = session_dao.create(username, org_name, encryptedSessionKey)
    except IntegrityError:
        return json.dumps(f"Session for user '{username}' already exists."), 400


    ## Create response
    result = {
        "session_id": session.id,
        "username": session.subject_username,
        "organization": session.organization_name,
        "roles": [role.name for role in session.session_roles],
        "public_key": base64.b64encode(public_key).decode('utf-8'),   
    }
    ## Sign response
    signature = sign_document(
        data = str(result),
        private_key = rep_priv_key,
    )


    ## Finish response packet
    result = json.dumps({
        "data": result,
        "digest": base64.b64encode(signature).decode('utf-8')
    })

    
    return result, 201