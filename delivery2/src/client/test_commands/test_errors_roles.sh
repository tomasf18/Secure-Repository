#!/bin/bash
cd ../commands

USER1_SESSION=user1_org1_session_file
USER2_SESSION=user2_org1_session_file

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file

# Create org1
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create an org that already exists, should fail
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file

# Create session with wrong password, should fail
./rep_create_session org1 user1 124 user1_cred_file $USER1_SESSION

# Create session for user1
./rep_create_session org1 user1 123 user1_cred_file $USER1_SESSION

# Add subjects (without permission), should fail
./rep_add_subject $USER1_SESSION user2 User2 user2@gmail.com user2_cred_file

# Assume role (ROLE_1), should fail because it doesn't exist
./rep_assume_role $USER1_SESSION ROLE_1

# Assume role (Manager)
./rep_assume_role $USER1_SESSION Manager

# Assume role (Manager) again, should fail
./rep_assume_role $USER1_SESSION Manager

# Add subjects (with permission), should work
./rep_add_subject $USER1_SESSION user2 User2 user2@gmail.com user2_cred_file

# Add the subject again, should fail
./rep_add_subject $USER1_SESSION user2 User2 user2@gmail.com user2_cred_file

# List organizations
./rep_list_orgs

# Add roles and permissions
./rep_add_role $USER1_SESSION ROLE_1
./rep_add_role $USER1_SESSION ROLE_2
./rep_add_permission $USER1_SESSION ROLE_2 DOC_NEW

# Add user1 to ROLE_1
./rep_add_permission $USER1_SESSION ROLE_1 user1

# Assume role
./rep_assume_role $USER1_SESSION ROLE_1

# Assume the same role again, should fail
./rep_assume_role $USER1_SESSION ROLE_1

# Assume a role that doesn't exist, should fail
./rep_assume_role $USER1_SESSION ROLE_3

# Show ROLE_1 permissions, should return []
./rep_list_role_permissions $USER1_SESSION ROLE_1

# Show ROLE_2 permissions, should return [DOC_NEW]
./rep_list_role_permissions $USER1_SESSION ROLE_2

# Show ROLE_3 permissions, should fail because ROLE_3 doesn't exist
./rep_list_role_permissions $USER1_SESSION ROLE_3

# Reactivate ROLE_3, should fail because ROLE_3 doesn't exist
./rep_reactivate_role $USER1_SESSION ROLE_3

# Drop a role that I do not have, should fail
./rep_drop_role $USER1_SESSION ROLE_2

# Drop a role that doesn't exist, should fail
./rep_drop_role $USER1_SESSION ROLE_3

# Drop role
./rep_drop_role $USER1_SESSION ROLE_1

# Drop Manager role
./rep_drop_role $USER1_SESSION Manager

# List session roles, there is no roles in session
./rep_list_roles $USER1_SESSION

# Assume role (Manager)
./rep_assume_role $USER1_SESSION Manager

# Create session for user2
./rep_create_session org1 user2 456 user2_cred_file $USER2_SESSION

# Assume role (not bound to), should fail
./rep_assume_role $USER2_SESSION ROLE_2

# Add user 2 to ROLE_2
./rep_add_permission $USER1_SESSION ROLE_2 user2
./rep_assume_role $USER2_SESSION ROLE_2

# List user2 roles on org1
./rep_list_subject_roles $USER1_SESSION user2

# List subjects on org1
./rep_list_subjects $USER1_SESSION

# User2 tries to suspend user1, should fail (doesnt have SUBJECT_DOWN permission)
./rep_suspend_subject $USER2_SESSION user1

# Add SUBJECT_DOWN permission to ROLE_2
./rep_add_permission $USER1_SESSION ROLE_2 SUBJECT_DOWN

# User2 tries to suspend user1, should fail (user1 is the Manager)
./rep_suspend_subject $USER2_SESSION user1

# Add permissions to ROLE_2
./rep_add_permission $USER1_SESSION ROLE_1 ROLE_DOWN
./rep_add_permission $USER1_SESSION ROLE_1 ROLE_UP
./rep_add_permission $USER1_SESSION ROLE_2 ROLE_NEW

# List role permissions and subjects
./rep_list_role_permissions $USER1_SESSION ROLE_2
./rep_list_subject_roles $USER1_SESSION user2

# User2 tries to add a new role, should work
./rep_add_role $USER2_SESSION ROLE_3

# Suspend ROLE_2
./rep_suspend_role $USER1_SESSION ROLE_2

# User2 tries to add a new role, should fail (ROLE_2 is suspended)
./rep_add_role $USER2_SESSION ROLE_4

# Reactivate ROLE_2, should work
./rep_reactivate_role $USER1_SESSION ROLE_2

# Reactivate ROLE_4, should fail (ROLE_4 doesn't exist)
./rep_reactivate_role $USER1_SESSION ROLE_4

# User2 assumes ROLE_2
./rep_assume_role $USER2_SESSION ROLE_2

# List roles, permissions, subjects
./rep_list_role_permissions $USER1_SESSION ROLE_2
./rep_list_subjects $USER1_SESSION user2
./rep_list_subject_roles $USER1_SESSION user2
./rep_list_roles $USER2_SESSION

# User2 tries to add a new role, should work
./rep_add_role $USER2_SESSION ROLE_4

# User2 tries to add an existing role, should fail
./rep_add_role $USER2_SESSION ROLE_4