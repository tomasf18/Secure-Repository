from dao.SessionDAO import SessionDAO
from models.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession
import json
import secrets
from utils.keyExchange import exchangeKeys
from utils.signing import verify_doc_sign, sign_document

def create_session(data, db_session: SQLAlchemySession):
    '''Handles POST requests to /sessions'''
    session_dao = SessionDAO(db_session)
    rep_priv_key = None # TODO ir buscar a chave privada
    rep_priv_key_password = None # TODO ir buscar a password da chave privaada

    if (not verify_doc_sign(data = data, pub_key = client_pub_key)):
        # Send bad credentials
        return json.dumps(f"Invalid signature!"), 403

    data = data.get("data")
    client_session_key = data.get("public_key")
    org_name = data.get('organization')
    username = data.get('username')

    client_pub_key = None # TODO: ir buscar à db a pub key do user

    sessionKey, publicKey = exchangeKeys(
            key = rep_priv_key,
            password = rep_priv_key_password,
            client_session_key=client_session_key
    )

    # TODO: Encrypt sessionKey 
    encryptedSessionKey = sessionKey
    try:
        session = session_dao.create(username, org_name, encryptedSessionKey)
    except IntegrityError:
        return json.dumps(f"Session for user '{username}' already exists."), 400

    result = {
        "session_id": session.id,
        "username": session.subject_username,
        "organization": session.organization_name,
        "roles": [role.name for role in session.session_roles],
        "public_key": publicKey,   
    }

    result = json.dumps({
        "digest": sign_document(result, rep_priv_key, rep_priv_key_password)
        **result
    })
    
    return result, 201