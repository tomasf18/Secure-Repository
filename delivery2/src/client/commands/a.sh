#!/bin/bash

# Add subjects credentials
./rep_subject_credentials u1
./rep_subject_credentials u2

# Create organization
./rep_create_org

# Create sessions
./rep_create_session u1

# Add subjects (without permission)
./rep_add_subject u1_session_file

# Assume role (Manager)
./rep_assume_role u1_session_file Manager

# Add subjects (with permission)
./rep_add_subject u1_session_file

# Add roles and permissions
./rep_add_role u1_session_file ROLE_1
./rep_add_permission u1_session_file ROLE_1 SOME_PERMISSION
./rep_add_role u1_session_file ROLE_2
./rep_add_permission u1_session_file ROLE_2 SOME_PERMISSION

# List organizations
./rep_list_orgs

# Add permissions to roles
./rep_add_permission u1_session_file ROLE_1 u1

# Assume and drop roles
./rep_assume_role u1_session_file ROLE_1
./rep_drop_role u1_session_file ROLE_1

# List roles
./rep_list_roles u1_session_file

# User 2 creates session
./rep_create_session u2

# Assume role (not bound to)
./rep_assume_role u2_session_file ROLE_2

# Add permissions to roles for another user
./rep_add_permission u1_session_file ROLE_2 u2
./rep_assume_role u2_session_file ROLE_2

# List subject roles and subjects
./rep_list_subject_roles u2_session_file
./rep_list_subjects u2_session_file
./rep_list_role_subjects u2_session_file
./rep_list_role_permissions u2_session_file
./rep_list_permission_roles u2_session_file

# Suspend subject
./rep_suspend_subject u1_session_file u2

# User 2 attempts actions while suspended
./rep_add_doc u2_session_file file1.txt
./rep_create_session u2

# Activate subject
./rep_activate_subject u1_session_file u2
./rep_create_session u2
./rep_add_doc u2_session_file file1.txt

# Document metadata and access
./rep_get_doc_metadata u1_session_file
./rep_get_doc_metadata u2_session_file
./rep_get_doc_file u2_session_file
./rep_decrypt_file u2_session_file
./rep_list_docs u1_session_file

# Add document ACL
./rep_acl_doc u2_session_file doc1 + u1 DOC_READ
./rep_get_doc_metadata u1_session_file
./rep_get_doc_file u1_session_file

# Delete document (without permission)
./rep_delete_doc u1_session_file doc1

# Suspend and reactivate roles
./rep_suspend_role u1_session_file ROLE_2
./rep_create_session u2
./rep_reactivate_role u1_session_file ROLE_2
./rep_create_session u2

# Drop and assume roles
./rep_drop_role u1_session_file Manager
./rep_assume_role u1_session_file ROLE_1
./rep_suspend_subject u1_session_file u2
./rep_activate_subject u1_session_file u2

# Manage permissions
./rep_add_permission u1_session_file ROLE_1 SUBJDOWN
./rep_add_permission u1_session_file ROLE_1 SUBJUP
./rep_remove_permission u1_session_file ROLE_1 SUBJDOWN

# Suspend subject without permission
./rep_suspend_subject u1_session_file u2

# Final assume role and session creation
./rep_assume_role u1_session_file Manager
./rep_create_session u2

# Role management and document addition
./rep_assume_role u2_session_file ROLE_2
./rep_add_doc u2_session_file file1.txt
./rep_remove_permission u1_session_file ROLE_2 u2
./rep_add_doc u2_session_file file2.txt
