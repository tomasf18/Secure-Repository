import os
import sys
import argparse
import logging
import json
from apiConsumer.APIConsumer import ApiConsumer
from constants.httpMethod import httpMethod
from constants.return_code import ReturnCode
from utils.files import read_file

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + rep_pub_key)
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
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

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
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))


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

apiConsumer = ApiConsumer(
    rep_pub_key = state["REP_PUB_KEY"],
)


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
    
    print("rep_subject_credentials")
    pass

def rep_decrypt_file(encrypted_file, encryption_metadata):
    """
    rep_decrypt_file <encrypted_file> <encryption_metadata>
    
    - This command sends to the stdout the contents of an 
    encrypted file upon decryption (and integrity control) 
    with the encryption metadata, that must contain the algorithms 
    used to encrypt its contents and the encryption key.
    """
    
    print("rep_decrypt_file")
    pass


# ****************************************************
# Anonymous API Commands
#
# These commands use the anonymous API to interact
#
# ****************************************************


def rep_create_org(org, username, name, email, pubkey_file):
    """
    rep_create_org <org> <username> <name> <email> <pubkey_file> 
    - This command creates an organization in a Repository and defines 
    its first subject.
    - Calls POST /organizations endpoint
    """
    
    endpoint = "/organizations"
    url = state['REP_ADDRESS'] + endpoint
    logger.debug(f'Calling {url}')
    
    pubKey = read_file(pubkey_file)
    if pubKey is None:
        logger.error(f"Error reading public key file: {pubkey_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
    
    data = {
        "organization": org,
        "username": username,
        "name": name,
        "email": email,
        "public_key_file": pubKey
    }
    
    result = apiConsumer.send_request(url=url, method=httpMethod.POST, data=data)
    
    if result is None:
        logger.error("Error creating organization")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    print(result)
    sys.exit(ReturnCode.SUCCESS)

def rep_list_org():
    """
    rep_list_orgs 
    - This command lists all organizations defined in a Repository. 
    - Calls GET /organizations endpoint
    """
    
    endpoint = "/organizations"
    url = state['REP_ADDRESS'] + endpoint
    logger.debug(f'Calling {url}')
    
    result = apiConsumer.send_request(url=url, method=httpMethod.GET)
    
    if result is None:
        logger.error("Error listing organizations")
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    print(result)
    sys.exit(ReturnCode.SUCCESS)

def rep_create_session(org, username, password, credentials_file, session_file):
    """
    rep_create_session <org> <username> <password> <credentials_file> <session_file> 
    - This command creates a session for a username belonging to an organization, 
    and stores the session context in a file.
    - Calls POST /sessions endpoint
    """
    
    endpoint = "/sessions"
    url = state['REP_ADDRESS'] + endpoint
    logger.debug(f'Calling {url}')
    
    credentials = read_file(credentials_file)
    if credentials is None:
        logger.error(f"Error reading credentials file: {credentials_file}")
        sys.exit(ReturnCode.INPUT_ERROR)
        
    data = {
        "organization": org,
        "username": username,
        "password": password,
        "credentials_file": credentials,
    }
    
    result = apiConsumer.send_request(url=url, method=httpMethod.POST, data=data)
    
    if result is None:
        logger.error("Error creating session")
        sys.exit(ReturnCode.REPOSITORY_ERROR)
    
    with open(session_file, "w") as file:
        file.write(result)
    
    sys.exit(ReturnCode.SUCCESS)
        
def rep_get_file(file_handle, output_file=None):
    """
    rep_get_file <file_handle> [file] 
    - This command downloads a file given its handle. 
    The file contents are written to stdout or to the 
    file referred in the optional last argument.
    - Calls GET /files/{file_handle} endpoint
    """
    
    endpoint = "/files"
    if file_handle is None:
        sys.exit(ReturnCode.INPUT_ERROR)
    url = state['REP_ADDRESS'] + endpoint + '/' + file_handle
    
    result = apiConsumer.send_request(url=url, method=httpMethod.GET)
    
    if result is None:
        sys.exit(ReturnCode.REPOSITORY_ERROR)

    if output_file is not None:
        with open('./' + output_file, "w") as file:
            file.write(result)
    else:
        print(result)

    sys.exit(ReturnCode.SUCCESS)


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
    - Calls /sessions/roles/{role} endpoint
    """

    print("rep_assume_role")
    pass

def rep_drop_role(session_file, role):
    """
    rep_drop_role <session_file> <role>
    - This command releases the given role for the session.
    - Calls DELETE /sessions/roles/{role} endpoint
    """
    
    print("rep_drop_role")
    pass

def rep_list_roles(session_file, role):
    """
    rep_list_roles <session_file> <role>
    - This command lists the current session roles.
    - Calls GET /sessions/roles endpoint
    """
    
    print("rep_list_roles")
    pass

def rep_list_subjects(session_file, username=None):
    """
    rep_list_subjects <session_file> [username]
    - This command lists the subjects of the organization 
    with which I have currently a session. The listing should 
    show the status of all the subjects (active or suspended). 
    This command accepts an extra command to show only one subject.
    - Calls GET /organizations/{organization_name}/subjects endpoint
    """
    
    print("rep_list_subjects")
    pass

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

def rep_list_docs(session_file, username=None, date_filter=None, date=None):
    """
    rep_list_docs <session_file> [-s username] [-d nt/ot/et date]
    - This command lists the documents of the organization with which I 
    have currently a session, possibly filtered by a subject that created 
    them and by a date (newer than, older than, equal to), expressed in the 
    DD-MM-YYYY format.
    - Calls GET /organizations/{organization_name}/documents?subject={subject}&date={date} endpoint
    """
    
    print(session_file, username, date_filter, date)
    print("rep_list_docs")
    pass


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
    
    print("rep_add_subject")
    pass

def rep_suspend_subject(session_file, username):
    """
    rep_suspend_subject <session_file> <username>
    - This command suspends a subject of the organization with which I have currently a session. 
    - This commands requires a SUBJECT_DOWN permission.
    - Calls DELETE /organizations/{organization_name}/subjects/{subject_username} endpoint
    """
    
    print("rep_suspend_subject")
    pass

def rep_activate_subject(session_file, username):
    """
    rep_activate_subject <session_file> <username>
    - This command activates a subject of the organization with which I have currently a session. 
    - This commands requires a SUBJECT_UP permission.
    - Calls PUT /organizations/{organization_name}/subjects/{subject_username} endpoint
    """
    
    print("rep_activate_subject")
    pass

def rep_add_role(session_file, role):
    """
    rep_add_role <session_file> <role>
    - This command adds a role to the organization with which I have currently a session. 
    - This commands requires a ROLE_NEW permission.
    - Calls POST /organizations/{organization_name}/roles endpoint
    """
    
    print("rep_add_role")
    pass

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

def rep_add_doc(session_file, document_name, file):
    """
    rep_add_doc <session_file> <document_name> <file>
    - This command adds a document with a given name to the organization with which I have currently a session. 
    - The documents contents is provided as parameter with a file name.
    - This commands requires a DOCUMENT_NEW permission.
    - Calls POST /organizations/{organization_name}/documents endpoint
    """
    
    print("rep_add_doc")
    pass

def rep_get_doc_metadata(session_file, document_name):
    """
    rep_get_doc_metadata <session_file> <document_name>
    - This command fetches the metadata of a document with a given name to the organization with which I have currently a session.
    - The output of this command is useful for getting the clear text contents of a documents file.
    - This commands requires a DOC_READ permission
    - Calls GET /organizations/{organization_name}/documents/{document_name} endpoint
    """
    
    print("rep_get_doc_metadata")
    pass

def rep_get_doc_file(session_file, document_name, output_file=None):
    """
    rep_get_doc_file <session_file> <document_name> [file]
    - This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file.
    - The file contents are written to stdout or to the file referred in the optional last argument.
    - This commands requires a DOC_READ permission
    - Calls ... endpoint
    """
    
    print("rep_get_doc_file")
    pass

def rep_delete_doc(session_file, document_name):
    """
    rep_delete_doc <session_file> <document_name>
    - This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session.
    The output of this command is the file_handle that ceased to exist in the documents metadata.
    - This commands requires a DOC_DELETE permission.
    - Calls DELETE /organizations/{organization_name}/documents/{document_name} endpoint
    """
    
    print("rep_delete_doc")
    pass

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

print("Program name:", args["command"])
print("Arguments:", args)
if args["command"] == "rep_subject_credentials":
    rep_subject_credentials(args["arg0"], args["arg1"])
elif args["command"] == "rep_decrypt_file":
    rep_decrypt_file(args["arg0"], args["arg1"])
elif args["command"]  == "rep_create_org":
    rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif args["command"] == "rep_list_orgs":
    rep_list_org()
elif args["command"] == "rep_create_session":
    rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif args["command"] == "rep_get_file":
    rep_get_file(args["arg0"], args["arg1"])
elif args["command"] == "rep_assume_role":
    rep_assume_role(args["arg0"], args["arg1"])
elif args["command"] == "rep_drop_role":
    rep_drop_role(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_roles":
    rep_list_roles(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_subjects":
    rep_list_subjects(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_roles_subject":
    rep_list_roles_subject(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_subject_roles":
    rep_list_subject_roles(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_role_permissions":
    rep_list_role_permissions(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_permission_roles":
    rep_list_permission_roles(args["arg0"], args["arg1"])
elif args["command"] == "rep_list_docs":
    session_file = args["arg0"]
    
    username = None
    date_filter = None
    date = None
    
    i = 1
    while f"arg{i}" in args:
        current_arg = args[f"arg{i}"]
        if current_arg == "-s":
            username = args[f"arg{i+1}"]
            i += 1
        elif current_arg == "-d":
            date_filter = args[f"arg{i+1}"]
            date = args[f"arg{i+2}"]
            i += 2
        i += 1
    rep_list_docs(session_file, username, date_filter, date)
elif args["command"] == "rep_add_subject":
    rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif args["command"] == "rep_suspend_subject":
    rep_suspend_subject(args["arg0"], args["arg1"])
elif args["command"] == "rep_activate_subject":
    rep_activate_subject(args["arg0"], args["arg1"])
elif args["command"] == "rep_add_role":
    rep_add_role(args["arg0"], args["arg1"])
elif args["command"] == "rep_suspend_role":
    rep_suspend_role(args["arg0"], args["arg1"])
elif args["command"] == "rep_reactivate_role":
    rep_reactivate_role(args["arg0"], args["arg1"])
elif args["command"] == "rep_add_permission":
    rep_add_permission(args["arg0"], args["arg1"], args["arg2"])
elif args["command"] == "rep_remove_permission":
    rep_remove_permission(args["arg0"], args["arg1"], args["arg2"])
elif args["command"] == "rep_add_doc":
    rep_add_doc(args["arg0"], args["arg1"], args["arg2"])
elif args["command"] == "rep_get_doc_metadata":
    rep_get_doc_metadata(args["arg0"], args["arg1"])
elif args["command"] == "rep_get_doc_file":
    rep_get_doc_file(args["arg0"], args["arg1"], args["arg2"])
elif args["command"] == "rep_delete_doc":
    rep_delete_doc(args["arg0"], args["arg1"])
elif args["command"] == "rep_acl_doc":
    rep_acl_doc(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
else:
  logger.error("Invalid command")