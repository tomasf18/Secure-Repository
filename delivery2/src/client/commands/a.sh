#!/bin/bash

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file

# Create organization
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create sessions
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file

# Add subjects (without permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file

# Assume role (Manager)
./rep_assume_role user1_org1_session_file Manager

# Add subjects (with permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file

# Add roles and permissions
./rep_add_role user1_org1_session_file ROLE_1
./rep_add_permission u1_session_file ROLE_1 SOME_PERMISSION
./rep_add_role user1_org1_session_file ROLE_2
./rep_add_permission user1_org1_session_file ROLE_2 DOC_NEW


# List organizations
./rep_list_orgs

# Add user1 to ROLE_1
./rep_add_permission user1_org1_session_file ROLE_1 user1

# Assume and drop roles
./rep_assume_role user1_org1_session_file ROLE_1
./rep_drop_role user1_org1_session_file ROLE_1

# List session roles
./rep_list_roles user1_org1_session_file

# User 2 creates session
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file

# Assume role (not bound to)
./rep_assume_role user2_org1_session_file ROLE_2    # Should fail

# Add user 2 to ROLE_2
./rep_add_permission user1_org1_session_file ROLE_2 user2
./rep_assume_role user2_org1_session_file ROLE_2

# List user2 roles on org1
./rep_list_subject_roles user1_org1_session_file user2

# List subjects on org1
./rep_list_subjects user1_org1_session_file

# List subjects who have a role
./rep_list_role_subjects user1_org1_session_file ROLE_1

# List permissions of a role
./rep_list_role_permissions user2_org1_session_file Manager

# List the roles which have a permission
./rep_list_permission_roles user1_org1_session_file ROLE_ACL

# Suspend subject
./rep_suspend_subject user1_org1_session_file user2

# User 2 attempts actions while suspended
./rep_add_doc user2_org1_session_file doc1 file1.txt
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file

# Activate subject
./rep_activate_subject user1_org1_session_file user2

# User 2 attempts actions while already activated
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file
./rep_add_doc user2_org1_session_file doc1 file1.txt

# Document metadata and access
./rep_get_doc_metadata user1_org1_session_file doc1 # Should fail, only the owner can access
./rep_get_doc_metadata user2_org1_session_file doc1 
# ./rep_get_file <file handle> doc1_encrypted
# ./rep_decrypt_file doc1_encrypted doc1_metadata.json
./rep_get_doc_file user2_org1_session_file doc1
./rep_list_docs user2_org1_session_file

# Add document ACL
./rep_acl_doc user1_org1_session_file doc1 + Manager DOC_READ  # Does not have acl permission
./rep_acl_doc user2_org1_session_file doc1 + Manager DOC_READ 
./rep_get_doc_metadata user1_org1_session_file doc1 # Can read

./rep_acl_doc user1_org1_session_file doc1 - Manager DOC_READ  # Does not have acl permission
./rep_get_doc_metadata user1_org1_session_file doc1 # Should fail


# Delete document (without permission)
./rep_delete_doc user1_org1_session_file doc1 # Should fail, only the owner can delete
./rep_acl_doc user2_org1_session_file doc1 + Manager DOC_DELETE  
./rep_delete_doc user1_org1_session_file doc1 
./rep_get_doc_metadata user2_org1_session_file doc1 


# # Suspend and reactivate roles
./rep_suspend_role user1_org1_session_file ROLE_2

# ./rep_create_session u2
# ./rep_reactivate_role u1_session_file ROLE_2
# ./rep_create_session u2

# # Drop and assume roles
# ./rep_drop_role u1_session_file Manager
# ./rep_assume_role u1_session_file ROLE_1
# ./rep_suspend_subject u1_session_file u2
# ./rep_activate_subject u1_session_file u2

# # Manage permissions
# ./rep_add_permission u1_session_file ROLE_1 SUBJDOWN
# ./rep_add_permission u1_session_file ROLE_1 SUBJUP
# ./rep_remove_permission u1_session_file ROLE_1 SUBJDOWN

# # Suspend subject without permission
# ./rep_suspend_subject u1_session_file u2

# # Final assume role and session creation
# ./rep_assume_role u1_session_file Manager
# ./rep_create_session u2

# # Role management and document addition
# ./rep_assume_role u2_session_file ROLE_2
# ./rep_add_doc u2_session_file file1.txt
# ./rep_remove_permission u1_session_file ROLE_2 u2
# ./rep_add_doc u2_session_file file2.txt
