import pytest
import os
import subprocess

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

def test_create_org():
    orgname1='org1'
    pub_key = 'pub_key.pem'

    ret = os.system(f'./rep_create_org {orgname1} joao Joao joao@gmail.com {pub_key}')
    assert ret == 0

def test_list_orgs():
    orgname2='org2'
    pub_key = 'pub_key.pem'

    os.system(f'./rep_create_org {orgname2} danilo Danilo danilo@gmail.com {pub_key}')
    output = subprocess.check_output(f'./rep_list_orgs', shell=True, text=True)
    assert "{'name': 'org1'}, {'name': 'org2'}" in output

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