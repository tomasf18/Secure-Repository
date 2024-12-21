import json
from dao.OrganizationDAO import SessionDAO
from dao.KeyStoreDAO import KeyStoreDAO
from utils.utils import decrypt_payload, verify_message_order
import base64

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
                f"Session with id {session_id} not found", 404, None
            )

    session_key = session_dao.get_decrypted_key(session_id)

    decrypted_data = decrypt_payload(data, session_key[:32], session_key[32:])
    if decrypted_data is None:
        raise ValueError(
            f"Invalid session key", 403, session_key # TODO: Verificar se está correto, nao tenho a certeza
        )

    if (decrypted_data.get("counter") is None) or (decrypted_data.get("nonce") is None):
        raise ValueError(
            f"No counter or nonce provided!", 403, session_key
        )
        
    if not verify_message_order(decrypted_data, counter=session.counter, nonce=session.nonce):
        raise ValueError(
            f"Invalid message order", 403, session_key
        )

    if organization_name != session.organization_name:
        raise ValueError(
            f"Cannot access organization {organization_name}", 403, session_key
        )

    return decrypted_data, session, session_key