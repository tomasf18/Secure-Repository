import json

from dao.SessionDAO import SessionDAO

from utils.session_utils import encrypt_payload, decrypt_payload, verify_message_order

def load_session(data: dict, session_dao: SessionDAO, organization_name: str) -> tuple[dict, bytes]:
    """
    Processes the session data and returns the session and organization name.
    Throws exceptions on errors.
    
    :param data: Dictionary containing input data, including session_id.
    :param db_session: Database session for accessing DAOs.
    :param organization_name: Name of the organization for validation.
    :return: Tuple containing the session and organization name.
    :raises ValueError: On errors such as invalid session, keys, or permissions.
    """
    # Get session
    session_id = data.get("session_id")
    session = session_dao.get_by_id(session_id)
    if session is None:
        raise ValueError(
                json.dumps(f"Session with id {session_id} not found"), 404
            )

    session_key = session_dao.get_decrypted_key(session_id)

    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        raise ValueError(
            encrypt_payload({
                    "error": f"Invalid session key"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    if (decrypted_data.get("counter") is None) or (decrypted_data.get("nonce") is None):
        raise ValueError(
            encrypt_payload({
                    "error": f"No counter or nonce provided!"
                }, session_key[:32], session_key[32:]
            ), 403
        )
        
    if not verify_message_order(decrypted_data, counter=session.counter, nonce=session.nonce):
        raise ValueError(
            encrypt_payload({
                    "error": f"Invalid message order"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    if organization_name != session.organization_name:
        raise ValueError(
            encrypt_payload({
                    "error": f"Cannot access organization {organization_name}"
                }, session_key[:32], session_key[32:]
            ), 403
        )

    return decrypted_data, session, session_key