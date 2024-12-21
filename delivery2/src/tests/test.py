import signal
import time
import pytest
import os
import subprocess
import json

CONFIG = {
    "current_dir": os.getcwd(),
    "server_dir": os.path.abspath("server"),
    "server_path": os.path.abspath("server/server.py"),
    "commands_dir": os.path.abspath("client/commands"),
}

with open("tests/data.json", "r") as f:
    data = json.load(f)

# NOTE: The scope "session" runs the fixture only once for the entire test session.
# Use "function" scope to execute the fixture before each individual test.

# ================== Clear All Data ==================

# Auxiliar function to clear all data
def clear_all_data():
    print("\n======================== Clearing data ========================\n")
    try:
        subprocess.run(["bash", "clear_all_data.sh"], check=True)
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Error clearing data: {e}")

@pytest.fixture(scope="session", autouse=True)
def clear_data():
    """Run the clear_all_data.sh script before running the tests."""
    clear_all_data()
        
# ================== Start Server ==================

# Auxiliar function to start the server
def start_server_process():
    """Start the server and return the process."""
    print("\n======================== Starting server ========================\n")
    
    os.chdir(CONFIG["server_dir"])
    server_process = subprocess.Popen(
        ["python3", CONFIG["server_path"]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1)  # Wait for the server to start
    os.chdir(CONFIG["current_dir"])
    return server_process

# Auxiliar function to stop the server
def stop_server_process(server_process):
    print("\n======================== Stopping server ========================\n")
    
    """Stop the server process."""
    os.kill(server_process.pid, signal.SIGTERM)
    server_process.wait()
    print("Server stopped successfully!")

@pytest.fixture(scope="session", autouse=True)
def start_server():
    """Start the server befre each test and stop it afterward."""
    
    try:
        server_process = start_server_process()
        
        # Check if the server is running
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            raise Exception(f"Server failed to start. STDOUT: {stdout.decode()}, STDERR: {stderr.decode()}")
        print("Server started successfully!")
        
        yield
        
    finally:
        stop_server_process(server_process)
        clear_all_data()
        
# ================== Helper Functions ==================

def execute_and_validate(command, args, expected_stdout, expected_stderr="", print_message=None):
    """
    Execute a command and validate its output.

    :param command: Name of the command to run (e.g., 'rep_subject_credentials').
    :param args: List of arguments to pass to the command.
    :param expected_stdout: Expected string or substring in the stdout.
    :param expected_stderr: Expected string or substring in the stderr (default is empty).
    :param print_message: Optional message to print before running the command.
    """
    if print_message:
        print(f"\n{print_message}")
    
    stdout, stderr = run_command(command, *args)
    
    assert expected_stdout in stdout, f"Expected '{expected_stdout}' in stdout, but got: {stdout}"
    assert expected_stderr in stderr, f"Expected '{expected_stderr}' in stderr, but got: {stderr}"
    
    print(stdout)

def run_command(command, *args):
    """
    Helper function to run a shell command with arguments and capture its output.
    
    :param command: Name of the command to run (e.g., './rep_subject_credentials').
    :param args: Arguments to pass to the command.
    :return: A tuple (stdout, stderr).
    """
    
    commands_dir = CONFIG["commands_dir"]
    try:
        result = subprocess.run(
            # Change directory to the client/commands folder and run the command
            [
                "bash", "-c", 
                f"cd {commands_dir} && ./{command} {' '.join(args)}"
            ],
            text=True,  # Capture output as text (str)
            capture_output=True,  # Capture both stdout and stderr
            check=True,  # Raise CalledProcessError for non-zero exit codes
        )
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr

# ================== Tests ==================

def test_simple():
    """A simple test to add some data to the database."""
    print("\n======================== Testing simple commands ========================\n")
    
    subjects = data["subjects"]
    subjects_dict = {subject["username"]: subject for subject in subjects}
    organizations = data["organizations"]
    sessions = data["sessions"]
    
    
    # ----------------- Add Subject Credentials -----------------
    
    for subject in subjects:
        username = subject["username"]
        password = subject["password"]
        cred_file = subject["public_key"]
        
        # Create subject credentials
        execute_and_validate(
            command="rep_subject_credentials",
            args=[password, cred_file],
            expected_stdout=f"Private key saved to ../keys/subject_keys/priv_{cred_file}.pem",
            print_message=f"Creating {username} credentials..."
        )
    
    # ----------------- Create Organizations -----------------
    
    for org in organizations:
        org_name = org["org_name"]
        owner_username = org["owner_username"]
        
        # Get the owner's data
        owner = subjects_dict[owner_username]
        full_name = owner["full_name"]
        email = owner["email"]
        cred_file = owner["public_key"]
        
        # Create organizations
        execute_and_validate(
            command="rep_create_org",
            args=[org_name, owner_username, full_name, email, cred_file],
            expected_stdout=f"Organization {org_name} created successfully",
            print_message=f"Creating organization {org_name} with owner {owner_username}..."
        )
    
    # List organizations
    execute_and_validate(
        command="rep_list_orgs",
        args=[],
        expected_stdout="[{'name': 'org1'}, {'name': 'org2'}]",
        print_message="Listing organizations..."
    )
    
    # ----------------- Create Sessions -----------------
    target_subjects = {"user1", "user6"}
    
    for session in sessions:
        if session["session_user"] in target_subjects:
            session_org = session["session_org"]
            session_user = session["session_user"]
            session_file = session["session_file"]
            session_id = session["session_id"]
            
            # Get the session user's data
            subject = subjects_dict[session_user]
            password = subject["password"]
            cred_file = subject["public_key"]

            # Create sessions
            execute_and_validate(
                command="rep_create_session",
                args=[session_org, session_user, password, cred_file, session_file],
                expected_stdout=f"Session created and saved to ../sessions/{session_file}.json, sessionId={session_id}",
                print_message=f"Creating a session with {session_user}..."
            )
    
    # ----------------- Add subjects to organizations -----------------
    org1_target_subjects = {"user2", "user3", "user4", "user5"}
    user1_org1_session_file = sessions[0]["session_file"]
    org2_target_subjects = {"user7", "user8", "user9", "user10"}
    user6_org2_session_file = sessions[5]["session_file"]
    
    for subject in org1_target_subjects:
        # Get the subject's data
        subject_data = subjects_dict[subject]
        username = subject_data["username"]
        full_name = subject_data["full_name"]
        email = subject_data["email"]
        cred_file = subject_data["public_key"]
        
        # Add subjects to org1
        execute_and_validate(
            command="rep_add_subject",
            args=[user1_org1_session_file, username, full_name, email, cred_file],
            expected_stdout=f"Subject {username} added to organization org1 successfully",
            print_message=f"Adding {username} to org1..."
        )
    
    for subject in org2_target_subjects:
        # Get the subject's data
        subject_data = subjects_dict[subject]
        username = subject_data["username"]
        full_name = subject_data["full_name"]
        email = subject_data["email"]
        cred_file = subject_data["public_key"]
        
        # Add subjects to org
        execute_and_validate(
            command="rep_add_subject",
            args=[user6_org2_session_file, username, full_name, email, cred_file],
            expected_stdout=f"Subject {username} added to organization org2 successfully",
            print_message=f"Adding {username} to org2..."
        )
    
    # ----------------- List subjects -----------------
    execute_and_validate(
        command="rep_list_subjects",
        args=[user1_org1_session_file],
        expected_stdout="[{'username': 'user1', 'status': 'ACTIVE'}, {'username': 'user2', 'status': 'ACTIVE'}, {'username': 'user3', 'status': 'ACTIVE'}, {'username': 'user4', 'status': 'ACTIVE'}, {'username': 'user5', 'status': 'ACTIVE'}]",
        print_message="Listing subjects for org1..."
    )
    
    execute_and_validate(
        command="rep_list_subjects",
        args=[user1_org1_session_file, "user3"],
        expected_stdout="{'username': 'user3', 'status': 'ACTIVE'}",
        print_message="Listing subject user3..."
    )
    
    execute_and_validate(
        command="rep_list_subjects",
        args=[user6_org2_session_file],
        expected_stdout="[{'username': 'user10', 'status': 'ACTIVE'}, {'username': 'user6', 'status': 'ACTIVE'}, {'username': 'user7', 'status': 'ACTIVE'}, {'username': 'user8', 'status': 'ACTIVE'}, {'username': 'user9', 'status': 'ACTIVE'}]",
        print_message="Listing subjects for org2..."
    )

def test_subjects():
    """A simple test to check if the subject commands work."""
    print("\n======================== Testing subjects ========================\n")
    

def test_docs():
    """A simple test to check if the document commands work."""
    print("\n======================== Testing documents ========================\n")