import signal
import time
import pytest
import os
import subprocess

# NOTE: The scope "session" runs the fixture only once for the entire test session.
# Use "function" scope to execute the fixture before each individual test.

# ======================== Clear all data ========================

@pytest.fixture(scope="session", autouse=True)
def clear_data():
    """Run the clear_all_data.sh script before running the tests."""
    print("\n======================== Clearing data ========================\n")
    try:
        subprocess.run(["bash", "clear_all_data.sh"], check=True)
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Error clearing data: {e}")
        
# ======================== Start Server ========================

@pytest.fixture(scope="session", autouse=True)
def start_server():
    """Start the server befre each test and stop it afterward."""
    print("\n======================== Starting server ========================\n")
    
    server_dir = os.path.abspath("server")
    server_path = os.path.join(server_dir, "server.py")
    
    original_dir = os.getcwd()
    
    try:
        # Start the server
        os.chdir(server_dir)
        server_process = subprocess.Popen(
            ["python3", server_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)  # Wait for the server to start
        os.chdir(original_dir)
        
        # Check if the server is running
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            raise Exception(f"Server failed to start. STDOUT: {stdout.decode()}, STDERR: {stderr.decode()}")
        
        print("Server started successfully!")
        
        # Yield control to the test
        yield
        
    finally:
        # Stop the server
        os.kill(server_process.pid, signal.SIGTERM)
        server_process.wait()
        
        print("\nServer stopped successfully!")
        
# ======================== Test helpers ========================

def run_command(command, *args):
    """
    Helper function to run a shell command with arguments and capture its output.
    
    :param command: Name of the command to run (e.g., './rep_subject_credentials').
    :param args: Arguments to pass to the command.
    :return: A tuple (stdout, stderr).
    """
    try:
        result = subprocess.run(
            # Change directory to the client/commands folder and run the command
            ["bash", "-c", f"cd client/commands && ./{command} {' '.join(args)}"],
            text=True,  # Capture output as text (str)
            capture_output=True,  # Capture both stdout and stderr
            check=True,  # Raise CalledProcessError for non-zero exit codes
        )
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr

# ======================== Test cases ========================

def test_simple():
    """A simple test to add some data to the database."""
    print("\n======================== Testing simple commands ========================\n")
    
    # Create user1 credentials
    print(f"\nCreating user1 credentials...")
    stdout, stderr = run_command("rep_subject_credentials", "123", "user1_cred_file")
    assert "Private key saved to ../keys/subject_keys/priv_user1_cred_file.pem" in stdout
    assert stderr == ""  # No errors expected
    print(stdout)
    
    # Create an organization with the user1
    print(f"\nCreating an organization with the user1...")
    stdout, stderr = run_command("rep_create_org", "org1", "user1", "User1", "user1@gmail.com", "user1_cred_file")
    assert "Organization org1 created successfully" in stdout
    assert stderr == ""  # No errors expected
    print(stdout)
    
    # List organizations
    print(f"\nListing organizations...")
    stdout, stderr = run_command("rep_list_orgs")
    assert "[{'name': 'org1'}]" in stdout
    assert stderr == ""  # No errors expected
    print(stdout)
    
    # Create a session with the user1
    print(f"\nCreating a session with the user1...")
    stdout, stderr = run_command("rep_create_session", "org1", "user1", "123", "user1_cred_file", "user1_session_file")
    assert "Session created and saved to ../sessions/user1_session_file.json, sessionId=1" in stdout
    assert stderr == ""  # No errors expected
    print(stdout)
    
    # List subjects
    print(f"\nListing subjects...")
    stdout, stderr = run_command("rep_list_subjects", "user1_session_file")
    assert "[{'username': 'user1', 'status': 'ACTIVE'}]" in stdout
    assert stderr == ""  # No errors expected
    print(stdout)

def test_subjects():
    """A simple test to check if the subject commands work."""
    print("\n======================== Testing subjects ========================\n")
    

def test_docs():
    """A simple test to check if the document commands work."""
    print("\n======================== Testing documents ========================\n")
      

# ./rep_subject_credentials 123 user1_cred_file
# ./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
# ./rep_list_orgs
# ./rep_create_session org1 user1 123 user1_cred_file user1_session_file
# ./rep_list_subjects user1_session_file

# ./rep_subject_credentials 456 user2_cred_file
# ./rep_add_subject user1_session_file user2 User2 user2@gmail.com user2_cred_file

# ./rep_subject_credentials 789 user3_cred_file
# ./rep_add_subject user1_session_file user3 User3 user3@gmail.com user3_cred_file

# ./rep_subject_credentials 101112 user4_cred_file
# ./rep_add_subject user1_session_file user4 User4 user4@gmail.com user4_cred_file

# ./rep_list_subjects user1_session_file
# ./rep_list_subjects user1_session_file user2

# ---

# ./rep_create_session org1 user2 456 user2_cred_file user2_session_file
# ./rep_suspend_subject user2_session_file user4
# ./rep_list_subjects user2_session_file user4

# --- 

# ./rep_create_session org1 user3 789 user3_cred_file user3_session_file
# ./rep_activate_subject user3_session_file user4
# ./rep_list_subjects user3_session_file user4

# ---

# ./rep_add_doc user1_session_file doc1 file1.txt

# def test_create_org():
#     orgname1='org1'
#     pub_key = 'pub_key.pem'

#     ret = os.system(f'./rep_create_org {orgname1} joao Joao joao@gmail.com {pub_key}')
#     assert ret == 0

# def test_list_orgs():
#     orgname2='org2'
#     pub_key = 'pub_key.pem'

#     os.system(f'./rep_create_org {orgname2} danilo Danilo danilo@gmail.com {pub_key}')
#     output = subprocess.check_output(f'./rep_list_orgs', shell=True, text=True)
#     assert "{'name': 'org1'}, {'name': 'org2'}" in output

# def test_create_session():
#     orgname='org1'
#     session_file = 'session1.json'
#     priv_key = 'key.pem'
#     priv_key_password = 123

#     ret = os.system(f'./rep_create_session {orgname} joao {priv_key_password} {priv_key} {session_file}')
#     assert ret == 0

# def test_list_subjects():
#     session_file = 'session1.json'

#     ret = os.system(f'./rep_list_subjects {session_file}')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_subjects {session_file}', shell=True, text=True)
#     assert "{'username': 'joao', 'status': 'ACTIVE'}" in output

# def test_add_subject():
#     session_file = 'session1.json'
#     pub_key = 'pub_key.pem'

#     ret = os.system(f'./rep_add_subject {session_file} pedro Pedro pedro@gmail.com {pub_key}')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_subjects {session_file}', shell=True, text=True)
#     assert "{'username': 'pedro', 'status': 'ACTIVE'}" in output

# def test_suspend_subject():
#     session_file = 'session1.json'

#     ret = os.system(f'./rep_suspend_subject {session_file} pedro')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_subjects {session_file}', shell=True, text=True)
#     assert "{'username': 'pedro', 'status': 'SUSPENDED'}" in output

# def test_activate_subject():
#     session_file = 'session1.json'

#     ret = os.system(f'./rep_activate_subject {session_file} pedro')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_subjects {session_file}', shell=True, text=True)
#     assert "{'username': 'pedro', 'status': 'ACTIVE'}" in output
    
# def test_add_doc():
#     session_file = 'session1.json'
#     doc_name = 'doc1'
#     file = 'file_contents.txt'
    
#     ret = os.system(f'./rep_add_doc {session_file} {doc_name} {file}')
#     assert ret == 0
    
# def test_list_docs():
#     session_file = 'session1.json'
    
#     ret = os.system(f'./rep_list_docs {session_file}')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_docs {session_file}', shell=True, text=True)
#     assert "{'document_name': 'doc1'}" in output
    
#     session_file2 = 'session2.json'
#     os.system(f'./rep_create_session org2 danilo 123 key.pem {session_file2}')
    
#     ret = os.system(f'./rep_add_doc {session_file2} doc2 file_contents.txt')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_list_docs {session_file}', shell=True, text=True)
#     assert "{'document_name': 'doc2'}" not in output

# def test_get_doc_metadata():
#     session_file = 'session1.json'
#     doc_name = 'doc1'
    
#     ret = os.system(f'./rep_get_doc_metadata {session_file} {doc_name}')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_get_doc_metadata {session_file} {doc_name}', shell=True, text=True)
#     print("\n\nOUTPUT = ", output)
#     assert "'document_name': 'doc1'" in output
    
# def test_get_doc_file():
#     session_file = 'session1.json'
#     doc_name = 'doc1'
    
#     ret = os.system(f'./rep_get_doc_file {session_file} {doc_name}')
#     assert ret == 0
#     output = subprocess.check_output(f'./rep_get_doc_file {session_file} {doc_name}', shell=True, text=True)
#     assert "Message to encrypt" in output

# def test_delete_doc():
#     session_file = 'session1.json'
#     doc_name = 'doc1'
    
#     ret = os.system(f'./rep_delete_doc {session_file} {doc_name}')
#     assert ret == 0

#     try:
#         output = subprocess.check_output(
#             f'./rep_get_doc_file {session_file} {doc_name}', 
#             shell=True, 
#             text=True, 
#             stderr=subprocess.STDOUT
#         )
#     except subprocess.CalledProcessError as e:
#         output = e.output

#     assert "404" in output
#     assert "Document 'doc1' does not have an associated file handle" in output