#!/bin/bash
cd ../commands

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file

# Create organization
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create sessions
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file

# Add subjects (without permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file # Should fail

# Assume role (Manager)
./rep_assume_role user1_org1_session_file Manager

# Add subjects (with permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file

# Add roles and permissions
./rep_add_role user1_org1_session_file ROLE_1
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
./rep_add_doc user2_org1_session_file doc1 file1.txt

# Document metadata and access
./rep_get_doc_metadata user1_org1_session_file doc1 # Should fail, only the owner can access
./rep_get_doc_metadata user2_org1_session_file doc1 
# ./rep_get_file org1_a2e86de4670ad42936825ce9eb9fac5b2c3a1f14a186a4413d3068c1f7ab5d5b doc1_encrypted
# ./rep_decrypt_file doc1_encrypted user2_org1/doc1_metadata.json
./rep_get_doc_file user2_org1_session_file doc1
./rep_list_docs user2_org1_session_file

# Add document ACL
./rep_acl_doc user2_org1_session_file doc1 - ROLE_2 DOC_ACL     # Should fail, this role is the only one with DOC_ACL
./rep_acl_doc user2_org1_session_file doc1 + Manager DOC_READ   
./rep_get_doc_metadata user1_org1_session_file doc1 # Can read

./rep_acl_doc user1_org1_session_file doc1 - Manager DOC_READ  # Does not have acl permission
./rep_get_doc_metadata user1_org1_session_file doc1 # Should still be able to read


# Delete document (without permission)
./rep_delete_doc user1_org1_session_file doc1 # Should fail, only the owner can delete
./rep_acl_doc user2_org1_session_file doc1 + Manager DOC_DELETE  
./rep_delete_doc user1_org1_session_file doc1 
./rep_get_doc_metadata user1_org1_session_file doc1 

#---
# # Suspend and reactivate roles
./rep_add_permission user1_org1_session_file ROLE_2 user1
./rep_assume_role user1_org1_session_file ROLE_2     
./rep_suspend_role user1_org1_session_file ROLE_2
./rep_list_roles user1_org1_session_file                # Should not list ROLE_2
./rep_list_roles user2_org1_session_file                # Should not list ROLE_2
./rep_assume_role user2_org1_session_file ROLE_2        # Should fail
./rep_reactivate_role user1_org1_session_file ROLE_2
./rep_assume_role user2_org1_session_file ROLE_2     
./rep_add_doc user2_org1_session_file doc2 file2.txt 


./rep_remove_permission user1_org1_session_file ROLE_2 user2
./rep_add_doc user2_org1_session_file doc3 file3.txt  # Should fail


# # Drop and assume roles
./rep_add_permission user1_org1_session_file ROLE_1 SUBJECT_DOWN

./rep_drop_role user1_org1_session_file Manager
./rep_assume_role user1_org1_session_file ROLE_1
./rep_suspend_subject user1_org1_session_file user1 # Should fail because can't suspend a manager

# Manage permissions
./rep_assume_role user1_org1_session_file Manager
./rep_remove_permission user2_org1_session_file ROLE_1 user1 # Should fail because doesn't have ROLE_MOD permission
./rep_remove_permission user1_org1_session_file ROLE_1 user1

./rep_remove_permission user1_org1_session_file Manager ROLE_ACL # Should fail
./rep_remove_permission user1_org1_session_file Manager user1    # Should fail

./rep_add_permission user1_org1_session_file Manager user2

./rep_assume_role user2_org1_session_file Manager
./rep_remove_permission user2_org1_session_file Manager user1

./rep_add_doc user2_org1_session_file doc3 file3.txt
./rep_acl_doc user2_org1_session_file doc3 + Manager DOC_ACL
./rep_acl_doc user2_org1_session_file doc3 + Manager DOC_READ
./rep_acl_doc user2_org1_session_file doc3 + Manager DOC_DELETE


# List permissions of a role
./rep_list_role_permissions user2_org1_session_file Manager