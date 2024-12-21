#!/bin/bash
cd ../commands

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file

# Create organization
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create an org that already exists
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create session with wrong password, should fail
./rep_create_session org1 user1 124 user1_cred_file user1_org1_session_file

# Create sessions
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file

# Add subjects (without permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file # Should fail

# Assume role (ROLE_1), should fail because it doesn't exist
./rep_assume_role user1_org1_session_file ROLE_1

# Assume role (Manager)
./rep_assume_role user1_org1_session_file Manager
./rep_assume_role user1_org1_session_file Manager

# Add subjects (with permission)
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file

# Add the subject again, should fail
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file

# List organizations
./rep_list_orgs

# --------------------------------------------------------------------------------------

# Add roles and permissions
./rep_add_role user1_org1_session_file ROLE_1
./rep_add_role user1_org1_session_file ROLE_2
./rep_add_permission user1_org1_session_file ROLE_2 DOC_NEW

# Add user1 to ROLE_1
./rep_add_permission user1_org1_session_file ROLE_1 user1

# Assume role
./rep_assume_role user1_org1_session_file ROLE_1

# Assume the same role again, should fail
./rep_assume_role user1_org1_session_file ROLE_1                      # !!!!!!!!!!!!!!!!

# Assume a role that doesnt exist, should fail
./rep_assume_role user1_org1_session_file ROLE_3

# Show ROLE_1 permissions, should return []
./rep_list_role_permissions user1_org1_session_file ROLE_1

# Show ROLE_2 permissions, should return [DOC_NEW]
./rep_list_role_permissions user1_org1_session_file ROLE_2

# Show ROLE_3 permissions, should fail because it doesn't exist
./rep_list_role_permissions user1_org1_session_file ROLE_3

# Reactivate ROLE_3, should fail because it doesn't exist
./rep_reactivate_role user1_org1_session_file ROLE_3

# Drop a role that i dont have, should fail
./rep_drop_role user1_org1_session_file ROLE_2

# Drop a role that doesn't exist, should fail
./rep_drop_role user1_org1_session_file ROLE_3

# Drop role
./rep_drop_role user1_org1_session_file ROLE_1

# Drop Manager role
./rep_drop_role user1_org1_session_file Manager

# List session roles, ther is no roles in session
./rep_list_roles user1_org1_session_file

./rep_assume_role user1_org1_session_file Manager

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

# User2 tries to suspend user1, should fail (doesnt have SUBJECT_DOWN permission)
./rep_suspend_subject user2_org1_session_file user1

# Add SUBJECT_DOWN permission to ROLE_2
./rep_add_permission user1_org1_session_file ROLE_2 SUBJECT_DOWN

# User2 tries to suspend user1, should fail (user1 is the Manager)
./rep_suspend_subject user2_org1_session_file user1


# --------------------------------------------------------------------------------------

./rep_add_permission user1_org1_session_file ROLE_1 ROLE_DOWN
./rep_add_permission user1_org1_session_file ROLE_1 ROLE_UP

./rep_add_permission user1_org1_session_file ROLE_2 ROLE_NEW

./rep_list_role_permissions user1_org1_session_file ROLE_2
./rep_list_subject_roles user1_org1_session_file user2

./rep_add_role user2_org1_session_file ROLE_3 # should work

./rep_suspend_role user1_org1_session_file ROLE_2

./rep_add_role user2_org1_session_file ROLE_4 # should fail

./rep_reactivate_role user1_org1_session_file ROLE_2
./rep_reactivate_role user1_org1_session_file ROLE_4
./rep_assume_role user2_org1_session_file ROLE_2

./rep_list_role_permissions user1_org1_session_file ROLE_2
./rep_list_subjects user1_org1_session_file user2
./rep_list_subject_roles user1_org1_session_file user2
./rep_list_roles user2_org1_session_file

./rep_add_role user2_org1_session_file ROLE_4 # should work
./rep_add_role user2_org1_session_file ROLE_4 # should fail, already exists