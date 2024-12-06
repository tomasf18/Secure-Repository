import os
import sys
import json
import base64
import logging
import datetime
import argparse

from dotenv import load_dotenv
from api.api_consumer import ApiConsumer

from utils.cryptography.ECC import ECC
from utils.cryptography.AES import AES, AESModes

from utils.constants.http_method import HTTPMethod
from utils.constants.return_code import ReturnCode

from utils.file_operations import read_file
from utils.utils import get_private_key_file, get_public_key_file, get_session_file, convert_bytes_to_str, convert_str_to_bytes, get_client_file, get_metadata_path, get_encrypted_file_path, get_decrypted_file_path

from cryptography.hazmat.primitives import serialization

# --------------------------- Commands Handling --------------------------- #

load_dotenv()

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
    else:
        state['REP_ADDRESS'] = "http://localhost:5000/"
        
    logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
    else:
        rep_pub_key = "../keys/rep_pub_key.pem"

    logger.debug('Loading REP_PUB_KEY from: ' + rep_pub_key)
    
    if os.path.exists(rep_pub_key):
        with open(rep_pub_key, 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    
    # flags for rep_list_docs command
    parser.add_argument("-s", "--subject", help="Username for filtering documents")
    parser.add_argument("-d", "--date", nargs=2, metavar=('FILTER', 'DATE'), help="Date filter with type (nt/ot/et) and date in DD-MM-YYYY format")
    
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {
        'command': args.command, 
        'subject': args.subject if args.subject else None,
        'date_filter': args.date[0] if args.date else None,
        'date': args.date[1] if args.date else None,
        'arg0': args.arg0, 
        'arg1': args.arg1, 
        'arg2': args.arg2, 
        'arg3': args.arg3, 
        'arg4': args.arg4, 
        'arg5': args.arg5
    }

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

# ---------------------------------------------------------------------------------------------------------- #

def saveContext(session_file, session_file_content):
    session_file_content["counter"] += 1                # Update counter to the one used by the last request
    with open(session_file, "w") as file:               # Save updated session context (the rest remains the same: sess_key, sess_id, username, org, and, for now, roles)
        file.write(json.dumps(session_file_content))
        
# -------------------------------

state = load_state()
state = parse_env(state)
state, args = parse_args(state)

if 'REP_ADDRESS' not in state:
  logger.error("Must define Repository Address")
  sys.exit(-1)

if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)
  
""" Do something """
logger.debug("Arguments: " + str(args))


# ---------------------------- Init API Consumer ---------------------------- #
apiConsumer = ApiConsumer(
    rep_pub_key = str(state["REP_PUB_KEY"]).encode(),
    rep_address = state["REP_ADDRESS"]
)
# --------------------------------------------------------------------------- #


# ****************************************************
# Local Commands
#
# These commands work without any interaction with 
# the Repository.
#
# ****************************************************


def rep_subject_credentials(password, credentials_file):
    """
    rep_subject_credentials <password> <credentials_file> 
    - This command does not interact with the Repository and 
    creates a key pair for a subject. You can either create a 
    file with a private/public key pair, and encrypt the private 
    component with the password (e.g. if using RSA), or you can 
    use directly the password to generate a private key and store 
    the public key in a file for verification (e.g. if using ECC).
    """

    try:

        ecc = ECC() 
        private_key, public_key = ecc.generate_keypair(password)

        # Save private key
        private_key_path = get_private_key_file(credentials_file)
        with open(private_key_path, "wb") as priv:
            priv.write(private_key)
            logger.info(f"Saved private key to {private_key_path}")

        # Save public key
        public_key_path = get_public_key_file(credentials_file)
        with open(public_key_path, "wb") as pub:
            pub.write(public_key)
            logger.info(f"Saved public key to {public_key_path}")

        logger.info("Key pair successfully generated and saved.")
        print(f"Private key saved to {private_key_path}") 
        sys.exit(ReturnCode.SUCCESS)

    except Exception as e:
        logger.error(f"Error generating key pair: {e}")
        sys.exit(ReturnCode.INPUT_ERROR)

# -------------------------------

def rep_decrypt_file(encrypted_file, encryption_metadata, get_doc_file=False):
    """
    rep_decrypt_file <encrypted_file> <encryption_metadata>
    
    - This command sends to the stdout the contents of an 
    encrypted file upon decryption (and integrity control) 
    with the encryption metadata, that must contain the algorithms 
    used to encrypt its contents and the encryption key.
    """

    encrypted_file = get_encrypted_file_path(encrypted_file)
    encryption_metadata = get_metadata_path(encryption_metadata)
    
    with open(encrypted_file, "rb") as file:
        encrypted_file_content = file.read()
    
    if encrypted_file_content is None:
        logger.error(f"Error reading encrypted file: {encrypted_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    metadata = read_file(encryption_metadata)
    if metadata is None:
        logger.error(f"Error reading metadata file: {encryption_metadata}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    doc_name = metadata['document_name']
    encryption_data = metadata['encryption_data']
    algorithm = encryption_data['algorithm']
    mode = encryption_data['mode']
    key = convert_str_to_bytes(encryption_data['key'])
    iv = convert_str_to_bytes(encryption_data['iv'])

    if algorithm == "AES256":
        aes = AES(AESModes.CBC)
        if mode == "CBC":
            decrypted_file_contents = aes.decrypt_data(encrypted_data=encrypted_file_content, key=key, iv=iv)
        # elif mode == "GCM": (...)
    
    decrypted_file_contents_str = decrypted_file_contents.decode()
    
    if not get_doc_file:
        decrypted_files_path = get_decrypted_file_path(doc_name)
        with open(decrypted_files_path, "w") as file:
            file.write(decrypted_file_contents_str)
        print(decrypted_file_contents_str)
        sys.exit(ReturnCode.SUCCESS)
    else:
        return decrypted_file_contents_str


# ****************************************************
# Anonymous API Commands
#
# These commands use the anonymous API to interact
#
# ****************************************************


def rep_create_org(org, username, name, email, pub_key_file):
    """
    rep_create_org <org> <username> <name> <email> <pub_key_file> 
    - This command creates an organization in a Repository and defines 
    its first subject.
    - Calls POST /organizations endpoint
    """

    client_pub_key_path = get_public_key_file(pub_key_file)
    pub_key = ECC.read_public_key(client_pub_key_path)
    pub_key_data = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) 
    
    if pub_key is None:
        logger.error(f"Error reading public key file: {pub_key_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    endpoint = "/organizations"
    
    data = {
        "organization": org,
        "username": username,
        "name": name,
        "email": email,
        "public_key": convert_bytes_to_str(pub_key_data)    # Convert to string so that it can be sent in the request to the server (bytes are not serializable)
    }
    
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.POST, data=data)
    
    if result is None:
        logger.error("Error creating organization")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    print(result)
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_list_org():
    """
    rep_list_orgs 
    - This command lists all organizations defined in a Repository. 
    - Calls GET /organizations endpoint
    """
    
    endpoint = "/organizations"
    
    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.GET)
    
    if result is None:
        logger.error("Error listing organizations")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    print(result)
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_create_session(org, username, password, credentials_file, session_file):
    """
    rep_create_session <org> <username> <password> <credentials_file> <session_file> 
    - This command creates a session for a username belonging to an organization, 
    and stores the session context in a file.
    - Calls POST /sessions endpoint
    """
    try:
        client_priv_key_file = get_private_key_file(credentials_file)
        private_key = ECC.read_private_key(client_priv_key_file, password)
        
    except Exception as e:
        logger.error(f"Error loading private key: {e}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    data = {
        "organization": org,
        "username": username,
    }

    shared_secret, session_data = apiConsumer.exchange_keys(private_key=private_key, data=data)
    logger.debug(f"SHARED SECRET: {shared_secret}")

    if shared_secret is None:
        logger.error("Error creating session")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    # result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.POST, data=data)
    logging.debug(f"Session created with sessionId: {session_data['session_id']}, session_key: {shared_secret}")

    session_file = get_session_file(session_file)
    with open(session_file, "w") as file:
        file.write(json.dumps({
            "session_key": convert_bytes_to_str(shared_secret),
            "session_id": session_data["session_id"],
            "username": session_data["username"],
            "organization": session_data["organization"],
            "roles": session_data["roles"],
            "nonce" : session_data["nonce"],
            "counter": 0,
        }))

    print(f"Session created and saved to {session_file}, sessionId={session_data['session_id']}")    
    sys.exit(ReturnCode.SUCCESS)
       
# -------------------------------
        
def rep_get_file(file_handle, output_file=None, get_doc_file=False):
    """
    rep_get_file <file_handle> [file] 
    - This command downloads a file given its handle. 
    The file contents are written to stdout or to the 
    file referred in the optional last argument.
    - Calls GET /files/{file_handle} endpoint
    """
    
    endpoint = f"/files/{file_handle}"
    
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.GET)
    
    if result is None:
        sys.exit(ReturnCode.REPOSITORY_ERROR)
        
    file_contents = convert_str_to_bytes(result["data"])

    if output_file is not None:
        encrypted_file_path = get_encrypted_file_path(output_file)
        with open(encrypted_file_path, "wb") as file:
            file.write(file_contents)
    else:
        print(file_contents)
            
    if not get_doc_file:
        sys.exit(ReturnCode.SUCCESS)
    else:
        return file_contents


# ****************************************************
# Authenticated API Commands
#
# These commands use the authenticated API to interact.
# All these commands use as first parameter a file with 
# the session key.
#
# ****************************************************

def rep_assume_role(session_file, role):
    """
    rep_assume_role <session_file> <role>
    This command requests the given role for the session.
    - Calls PUT /organizations/{organization_name}/sessions/{session_id}/roles/{role} endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    endpoint = f"/organizations/{session_file_content['organization']}/sessions/{session_id}/roles/{role}"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"]
    }
    
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.PUT, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error assuming role")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
        
    roles = result["roles"]
    session_file_content["roles"] = roles
    
    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_drop_role(session_file, role):
    """
    rep_drop_role <session_file> <role>
    - This command releases the given role for the session.
    - Calls DELETE /organizations/{organization_name}/sessions/{session_id}/roles/{role} endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)

    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    endpoint = f"/organizations/{session_file_content['organization']}/sessions/{session_id}/roles/{role}"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"]
    }
    
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.DELETE, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error dropping role")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
        
    roles = result["roles"]
    session_file_content["roles"] = roles
    
    saveContext(session_file, session_file_content)

    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)
    
# -------------------------------

def rep_list_roles(session_file, role):
    """
    rep_list_roles <session_file> <role>
    - This command lists the current session roles.
    - Calls GET /sessions/roles endpoint
    """
    
    print("rep_list_roles")
    pass

# -------------------------------

def rep_list_subjects(session_file, username=None):
    """
    rep_list_subjects <session_file> [username]
    - This command lists the subjects of the organization 
    with which I have currently a session. The listing should 
    show the status of all the subjects (active or suspended). 
    - This command accepts an extra command to show only one subject.
    - Calls GET /organizations/{organization_name}/subjects endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    base_endpoint = f"/organizations/{session_file_content['organization']}/subjects"
    endpoint = base_endpoint if username is None else f"{base_endpoint}/{username}"

    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])

    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1, # Increment counter for each request
        "nonce": session_file_content["nonce"],         
    }
    
    logger.debug(f"NOUNCE: {session_file_content['nonce']}")
    
    
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.GET, data=data, sessionKey=session_key, sessionId=session_id)

    if result is None or result.get("error") is not None:
        print("Error: " + result["error"])
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)
        
# -------------------------------

def rep_list_roles_subject(session_file, role):
    """
    rep_list_roles_subject <session_file> <role>
    - This command lists the subjects of a role of the organization 
    with which I have currently a session.
    - Calls GET /organizations/{organization_name}/subjects/?role={role} endpoint
    """
    
    print("rep_list_roles_subject")
    pass

def rep_list_subject_roles(session_file, username):
    """
    rep_list_subject_roles <session_file> <username>
    - This command lists the roles of a subject of the organization 
    with which I have currently a session.
    - Calls GET /organizations/{organization_name}/subjects/{subject_username}/roles endpoint
    """
    
    print("rep_list_subject_roles")
    pass

def rep_list_role_permissions(session_file, role):
    """
    rep_list_role_permissions <session_file> <role>
    - This command lists the permissions of a role of the organization 
    with which I have currently a session.
    - Calls GET /organizations/{organization_name}/roles/{role}/permissions endpoint
    """
    
    print("rep_list_role_permissions")
    pass

def rep_list_permission_roles(session_file, permission):
    """
    rep_list_permission_roles <session_file> <permission>
    - This command lists the roles of the organization with which I have currently 
    a session that have a given permission. Use the names previously referred 
    for the permission rights.
    - As roles can be used in documents ACLs to associate subjects to permissions, 
    this command should also list the roles per document that have the given permission. 
    Note: permissions for documents are different from the other organization permissions.
    - Calls GET /organizations/{organization_name}/roles?permission={permission} endpoint
    """
    
    print("rep_list_permission_roles")
    pass

# -------------------------------

def rep_list_docs(session_file, username=None, date_filter=None, date=None):
    """
    rep_list_docs <session_file> [-s username] [-d nt/ot/et date]
    - This command lists the documents of the organization with which I 
    have currently a session, possibly filtered by a subject that created 
    them and by a date (newer than, older than, equal to), expressed in the 
    DD-MM-YYYY format.
    - Calls GET /organizations/{organization_name}/documents?subject={subject}&date_filter={date_filter}&date={date} endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    endpoint = f"/organizations/{session_file_content['organization']}/documents"
    params = []
    
    if username:
        params.append(f"subject={username}")
    if date_filter and date:
        params.append(f"date_filter={date_filter}&date={date}")
    
    if params:
        endpoint += "?" + "&".join(params)

    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }
        
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.GET, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None or result.get("error") is not None:
        logger.error("Error listing documents")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# ****************************************************
# Authorized API Commands
#
# These commands use the authorized API to interact.
# All these commands use as first parameter a file 
# with the session key. For that session, the subject 
# must have added one or more roles.
#
# ****************************************************

def rep_add_subject(session_file, username, name, email, credentials_file):
    """
    rep_add_subject <session_file> <username> <name> <email> <credentials_file>
    - This command adds a new subject to the organization with which I have currently a session. 
    - By default the subject is created in the active status. 
    - This commands requires a SUBJECT_NEW permission.
    - Calls POST /organizations/{organization_name}/subjects endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    try:
        public_key_file = get_public_key_file(credentials_file)
        public_key = ECC.read_public_key(public_key_file)
    except Exception as e:
        logger.error(f"Error loading public key: {e}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    endpoint = f"/organizations/{session_file_content['organization']}/subjects"
    
    public_key_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    data = {
        "session_id": session_id,
        "username": username,
        "name": name,
        "email": email,
        "public_key": convert_bytes_to_str(public_key_data),
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }

    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.POST, data=data, sessionKey=session_key, sessionId=session_id)
    
    if result is None:
        logger.error("Error adding subject")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_suspend_subject(session_file, username):
    """
    rep_suspend_subject <session_file> <username>
    - This command suspends a subject of the organization with which I have currently a session. 
    - This commands requires a SUBJECT_DOWN permission.
    - Calls DELETE /organizations/{organization_name}/subjects/{subject_username} endpoint
    """
        
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    endpoint = f"/organizations/{session_file_content['organization']}/subjects/{username}"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }
    
    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.DELETE, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error suspending subject")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_activate_subject(session_file, username):
    """
    rep_activate_subject <session_file> <username>
    - This command activates a subject of the organization with which I have currently a session. 
    - This commands requires a SUBJECT_UP permission.
    - Calls PUT /organizations/{organization_name}/subjects/{subject_username} endpoint
    """
    
    session_file = get_session_file(session_file)    
    session_file_content = read_file(session_file)
    
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    endpoint = f"/organizations/{session_file_content['organization']}/subjects/{username}"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }
    
    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.PUT, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error activating subject")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_add_role(session_file, role):
    """
    rep_add_role <session_file> <role>
    - This command adds a role to the organization with which I have currently a session. 
    - This commands requires a ROLE_NEW permission.
    - Calls POST /organizations/{organization_name}/roles endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    endpoint = f"/organizations/{session_file_content['organization']}/roles"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
        "new_role": role,
    }
    
    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.POST, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error suspending subject")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)
    
# -------------------------------

def rep_suspend_role(session_file, role):
    """
    rep_suspend_role <session_file> <role>
    - This command suspends a role of the organization with which I have currently a session. 
    - This commands requires a ROLE_DOWN permission.
    - Calls DELETE /organizations/{organization_name}/roles/{role} endpoint
    """
    
    print("rep_suspend_role")
    pass

def rep_reactivate_role(session_file, role):
    """
    rep_reactivate_role <session_file> <role>
    - This command activates a role of the organization with which I have currently a session. 
    - This commands requires a ROLE_UP permission.
    - Calls PUT /organizations/{organization_name}/roles/{role} endpoint
    """
    
    print("rep_reactivate_role")
    pass

def rep_add_permission(session_file, role, target):
    """
    rep_add_permission <session_file> <role> <username/permission>
    - This command change the properties of a role of the organization with which I have currently a session,
    by adding a subject/permission. 
    - This commands requires a ROLE_MOD permission.
    - Calls ... endpoint
    """
    
    print("rep_add_permission")
    pass

def rep_remove_permission(session_file, role, target):
    """
    rep_remove_permission <session_file> <role> <username/permission>
    - This command change the properties of a role of the organization with which I have currently a session,
    by removing a subject/permission. 
    - This commands requires a ROLE_MOD permission.
    - Calls ... endpoint
    """
    
    print("rep_remove_permission")
    pass

# -------------------------------

def rep_add_doc(session_file, document_name, file):
    """
    rep_add_doc <session_file> <document_name> <file>
    - This command adds a document with a given name to the organization with which I have currently a session. 
    - The documents contents is provided as parameter with a file name.
    - This commands requires a DOCUMENT_NEW permission.
    - Calls POST /organizations/{organization_name}/documents endpoint
    """
        
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])
    
    file = get_client_file(file)
    file_contents = read_file(file)
    if file_contents is None:
        logger.error(f"Error reading file: {file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    # Encrypt file_contents using AES mode CBC
    algorithm = "AES256"
    mode = "CBC"
    aes = AES(AESModes.CBC)
    random_key = aes.generate_random_key()
    encrypted_file_content, iv = aes.encrypt_data(file_contents.encode(), random_key)
    
    endpoint = f"/organizations/{session_file_content['organization']}/documents"
    
    data = {
        "session_id": session_id,
        "document_name": document_name,
        "file": convert_bytes_to_str(encrypted_file_content),
        "alg": algorithm + "-" + mode,
        "key": convert_bytes_to_str(random_key),
        "iv": convert_bytes_to_str(iv),
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }
    
    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.POST, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error adding document")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    saveContext(session_file, session_file_content)
    
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_get_doc_metadata(session_file, document_name, doc_get_file=False):
    """
    rep_get_doc_metadata <session_file> <document_name>
    - This command fetches the metadata of a document with a given name to the organization with which I have currently a session.
    - The output of this command is useful for getting the clear text contents of a documents file.
    - This commands requires a DOC_READ permission
    - Calls GET /organizations/{organization_name}/documents/{document_name} endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])

    endpoint = f"/organizations/{session_file_content['organization']}/documents/{document_name}"
    
    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }

    result = apiConsumer.send_request(endpoint=endpoint,  method=HTTPMethod.GET, data=data, sessionId=session_id, sessionKey=session_key)
    
    if result is None:
        logger.error("Error getting document metadata")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    saveContext(session_file, session_file_content)
    
    data = result["data"]
    
    document_name = data["document_name"]
    metadata_path = get_metadata_path(document_name)
    
    with open(metadata_path, "w") as file:
        file.write(json.dumps(data))
    
    if doc_get_file:
        return data
    
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_get_doc_file(session_file, document_name, output_file=None):
    """
    rep_get_doc_file <session_file> <document_name> [file]
    - This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file.
    - The file contents are written to stdout or to the file referred in the optional last argument.
    - This commands requires a DOC_READ permission
    - Calls GET /organizations/{organization_name}/documents/{document_name}/file endpoint
    """

    output_encrypted_file = document_name
    
    document_metadata = rep_get_doc_metadata(session_file, document_name, doc_get_file=True)
    rep_get_file(document_metadata["file_handle"], output_encrypted_file, get_doc_file=True)
    decrypted_file_content = rep_decrypt_file(document_name, document_name, get_doc_file=True)
    
    if output_file is None:
        output_file = document_name
    
    output_decrypted_file = get_decrypted_file_path(output_file)
    with open(output_decrypted_file, "w") as file:
        file.write(decrypted_file_content)
        
    print("\n", decrypted_file_content)

# -------------------------------

def rep_delete_doc(session_file, document_name):
    """
    rep_delete_doc <session_file> <document_name>
    - This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session.
    The output of this command is the file_handle that ceased to exist in the documents metadata.
    - This commands requires a DOC_DELETE permission.
    - Calls DELETE /organizations/{organization_name}/documents/{document_name} endpoint
    """
    
    session_file = get_session_file(session_file)
    session_file_content = read_file(session_file)
    if session_file_content is None:
        logger.error(f"Error reading session file: {session_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    endpoint = f"/organizations/{session_file_content['organization']}/documents/{document_name}"

    session_id = session_file_content['session_id']
    session_key = convert_str_to_bytes(session_file_content["session_key"])

    data = {
        "session_id": session_id,
        "counter": session_file_content["counter"] + 1,
        "nonce": session_file_content["nonce"],
    }
        
    result = apiConsumer.send_request(endpoint=endpoint, method=HTTPMethod.DELETE, data=data, sessionId=session_id, sessionKey=session_key)

    if result is None:
        logger.error("Error deleting document")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    saveContext(session_file, session_file_content)
    print(result["data"])
    sys.exit(ReturnCode.SUCCESS)

# -------------------------------

def rep_acl_doc(session_file, document_name, operator, role, permission):
    """
    rep_acl_doc <session_file> <document_name> [+/-] <role> <permission>
    - This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role.
    - Use the names previously referred for the permission rights.
    - This commands requires a DOC_ACL permission.
    - Calls PUT/DELETE /organizations/{organization_name}/documents/{document_name}/acl endpoint
    """

    print("rep_acl_doc")
    pass


# ****************************************************
# Arguments Validation and Command Execution
#
# This section validates the arguments of the command
# and calls the appropriate function.
#
# ****************************************************

def validate_args(command_name, required_args, usage):
    """
    Checks if the required arguments are present in the command.
    
    :param command_name: The name of the command to print error messages.
    :param required_args: A list of required arguments.
    :param usage: The usage of the command to print in case of missing arguments.
    """
    missing_args = [arg for arg, value in required_args.items() if value is None]
    
    if missing_args:
        logger.error(f"Missing arguments: {', '.join(missing_args)}. Usage: {command_name} {usage}")
        sys.exit(ReturnCode.INPUT_ERROR)


print("Program name:", args["command"])
        
if args["command"] == "rep_subject_credentials":
    usage = "<password> <credentials_file>"
    validate_args("rep_subject_credentials", {"password": args["arg0"], "credentials_file": args["arg1"]}, usage)
    rep_subject_credentials(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_decrypt_file":
    usage = "<encrypted_file> <encryption_metadata>"
    validate_args("rep_decrypt_file", {"encrypted_file": args["arg0"], "encryption_metadata": args["arg1"]}, usage)
    rep_decrypt_file(args["arg0"], args["arg1"])
    
elif args["command"]  == "rep_create_org":
    usage = "<org> <username> <name> <email> <pub_key_file>"
    validate_args("rep_create_org", {"org": args["arg0"], "username": args["arg1"], "name": args["arg2"], "email": args["arg3"], "pub_key_file": args["arg4"]}, usage)
    rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
    
elif args["command"] == "rep_list_orgs":
    rep_list_org()
    
elif args["command"] == "rep_create_session":
    usage = "<organization> <username> <password> <credentials_file> <session_file>"
    validate_args("rep_create_session", {"organization": args["arg0"], "username": args["arg1"], "password": args["arg2"], "credentials_file": args["arg3"], "session_file": args["arg4"]}, usage)
    rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
    
elif args["command"] == "rep_get_file":
    usage = "<file_handle> [file]"
    validate_args("rep_get_file", {"file_handle": args["arg0"]}, usage)
    rep_get_file(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_assume_role":
    usage = "<session_file> <role>"
    validate_args("rep_assume_role", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_assume_role(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_drop_role":
    usage = "<session_file> <role>"
    validate_args("rep_drop_role", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_drop_role(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_roles":
    usage = "<session_file> <role>"
    validate_args("rep_list_roles", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_list_roles(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_subjects":
    usage = "<session_file> [username]"
    validate_args("rep_list_subjects", {"session_file": args["arg0"]}, usage)
    rep_list_subjects(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_roles_subject":
    usage = "<session_file> <role>"
    validate_args("rep_list_roles_subject", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_list_roles_subject(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_subject_roles":
    usage = "<session_file> <username>"
    validate_args("rep_list_subject_roles", {"session_file": args["arg0"], "username": args["arg1"]}, usage)
    rep_list_subject_roles(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_role_permissions":
    usage = "<session_file> <role>"
    validate_args("rep_list_role_permissions", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_list_role_permissions(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_permission_roles":
    usage = "<session_file> <permission>"
    validate_args("rep_list_permission_roles", {"session_file": args["arg0"], "permission": args["arg1"]}, usage)
    rep_list_permission_roles(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_list_docs":
    usage = "<session_file> [-s username] [-d nt/ot/et date]"
    validate_args("rep_list_docs", {"session_file": args["arg0"]}, usage)
    
    valid_filters = ["nt", "ot", "et"]
    date_filter = args["date_filter"]
    date = args["date"]
    datetime_date = None
    
    if date_filter and date_filter not in valid_filters:
        logger.error(f"Invalid date filter: {date_filter}. Use one of: {valid_filters}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    if date:
        try:
            day, month, year = map(int, date.split("-"))
            datetime_date = datetime.date(year, month, day) # Check if date is valid
        except Exception as e:
            logger.error(f"Invalid date format: {date}. Use DD-MM-YYYY")
            sys.exit(ReturnCode.INPUT_ERROR)
    
    rep_list_docs(args["arg0"], args["subject"], date_filter, datetime_date)
    
elif args["command"] == "rep_add_subject":
    usage = "<session_file> <username> <name> <email> <credentials_file>"
    validate_args("rep_add_subject", {"session_file": args["arg0"], "username": args["arg1"], "name": args["arg2"], "email": args["arg3"], "credentials_file": args["arg4"]}, usage)
    rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
    
elif args["command"] == "rep_suspend_subject":
    usage = "<session_file> <username>"
    validate_args("rep_suspend_subject", {"session_file": args["arg0"], "username": args["arg1"]}, usage)
    rep_suspend_subject(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_activate_subject":
    usage = "<session_file> <username>"
    validate_args("rep_activate_subject", {"session_file": args["arg0"], "username": args["arg1"]}, usage)
    rep_activate_subject(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_add_role":
    usage = "<session_file> <role>"
    validate_args("rep_add_role", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_add_role(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_suspend_role":
    usage = "<session_file> <role>"
    validate_args("rep_suspend_role", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_suspend_role(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_reactivate_role":
    usage = "<session_file> <role>"
    validate_args("rep_reactivate_role", {"session_file": args["arg0"], "role": args["arg1"]}, usage)
    rep_reactivate_role(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_add_permission":
    usage = "<session_file> <role> <username/permission>"
    validate_args("rep_add_permission", {"session_file": args["arg0"], "role": args["arg1"], "target": args["arg2"]}, usage)
    rep_add_permission(args["arg0"], args["arg1"], args["arg2"])
    
elif args["command"] == "rep_remove_permission":
    usage = "<session_file> <role> <username/permission>"
    validate_args("rep_remove_permission", {"session_file": args["arg0"], "role": args["arg1"], "target": args["arg2"]}, usage)
    rep_remove_permission(args["arg0"], args["arg1"], args["arg2"])
    
elif args["command"] == "rep_add_doc":
    usage = "<session_file> <document_name> <file>"
    validate_args("rep_add_doc", {"session_file": args["arg0"], "document_name": args["arg1"], "file": args["arg2"]}, usage)
    rep_add_doc(args["arg0"], args["arg1"], args["arg2"])
    
elif args["command"] == "rep_get_doc_metadata":
    usage = "<session_file> <document_name>"
    validate_args("rep_get_doc_metadata", {"session_file": args["arg0"], "document_name": args["arg1"]}, usage)
    rep_get_doc_metadata(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_get_doc_file":
    usage = "<session_file> <document_name> [file]"
    validate_args("rep_get_doc_file", {"session_file": args["arg0"], "document_name": args["arg1"]}, usage)
    rep_get_doc_file(args["arg0"], args["arg1"], args["arg2"])
    
elif args["command"] == "rep_delete_doc":
    usage = "<session_file> <document_name>"
    validate_args("rep_delete_doc", {"session_file": args["arg0"], "document_name": args["arg1"]}, usage)
    rep_delete_doc(args["arg0"], args["arg1"])
    
elif args["command"] == "rep_acl_doc":
    usage = "<session_file> <document_name> [+/-] <role> <permission>"
    validate_args("rep_acl_doc", {"session_file": args["arg0"], "document_name": args["arg1"], "operator": args["arg2"], "role": args["arg3"], "permission": args["arg4"]}, usage)
    
    operator = args["arg2"]
    if operator not in ["+", "-"]:
        logger.error(f"Invalid operator: {operator}. Use '+' to add or '-' to remove")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    rep_acl_doc(args["arg0"], args["arg1"], operator, args["arg3"], args["arg4"])
    
else:
  logger.error("Invalid command")