#!/bin/bash

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file
./rep_subject_credentials 789 user3_cred_file
./rep_subject_credentials 321 user4_cred_file


# Create organization
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file


# List organizations
./rep_list_orgs


# Create session
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file


# Add subjects to organization
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file
./rep_add_subject user1_org1_session_file user3 User3 user3@gmail.com user3_cred_file
./rep_add_subject user1_org1_session_file user4 User4 user4@gmail.com user4_cred_file


# List subjects
./rep_list_subjects user1_org1_session_file


# Create sessions for the new subjects
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file
./rep_create_session org1 user3 789 user3_cred_file user3_org1_session_file
./rep_create_session org1 user4 321 user4_cred_file user4_org1_session_file


# Add roles
./rep_add_role user1_org1_session_file ROLE_1
./rep_add_role user1_org1_session_file ROLE_2
./rep_add_role user1_org1_session_file ROLE_3


# Assume roles
./rep_assume_role user1_org1_session_file ROLE_1
./rep_assume_role user1_org1_session_file ROLE_2
./rep_assume_role user1_org1_session_file ROLE_3
./rep_assume_role user2_org1_session_file ROLE_1
./rep_assume_role user2_org1_session_file ROLE_2
./rep_assume_role user3_org1_session_file ROLE_3
./rep_assume_role user3_org1_session_file ROLE_1
./rep_assume_role user4_org1_session_file ROLE_2


# List session roles
./rep_list_roles user1_org1_session_file
./rep_list_roles user2_org1_session_file
./rep_list_roles user3_org1_session_file
./rep_list_roles user4_org1_session_file


# Drop roles
./rep_drop_role user2_org1_session_file ROLE_2

# user1: [ROLE_1, ROLE_2, ROLE_3]
# user2: [ROLE_1]
# user3: [ROLE_1, ROLE_3]
# user4: [ROLE_2]


# List session roles
./rep_list_roles user1_org1_session_file
./rep_list_roles user2_org1_session_file
./rep_list_roles user3_org1_session_file
./rep_list_roles user4_org1_session_file


# List subjects who have a role
./rep_list_role_subjects user1_org1_session_file ROLE_1
./rep_list_role_subjects user1_org1_session_file ROLE_2
./rep_list_role_subjects user1_org1_session_file ROLE_3


# List roles of a subject
./rep_list_subject_roles user1_org1_session_file user1
./rep_list_subject_roles user1_org1_session_file user2
./rep_list_subject_roles user1_org1_session_file user3
./rep_list_subject_roles user1_org1_session_file user4


# Suspend roles
./rep_suspend_role user2_org1_session_file ROLE_2


# Reactivate roles
./rep_reactivate_role user2_org1_session_file ROLE_2


# List role permissions
./rep_list_role_permissions user2_org1_session_file ROLE_1
./rep_list_role_permissions user2_org1_session_file ROLE_2
./rep_list_role_permissions user2_org1_session_file ROLE_3


# Add permissions to roles
./rep_add_permission user2_org1_session_file ROLE_2 DOC_ACL
./rep_add_permission user2_org1_session_file ROLE_2 DOC_READ
./rep_add_permission user2_org1_session_file ROLE_2 DOC_DELETE
./rep_add_permission user2_org1_session_file ROLE_2 ROLE_ACL
./rep_add_permission user2_org1_session_file ROLE_3 DOC_NEW
./rep_add_permission user2_org1_session_file ROLE_3 ROLE_NEW
./rep_add_permission user2_org1_session_file ROLE_3 ROLE_MOD
./rep_add_permission user2_org1_session_file ROLE_1 DOC_READ
./rep_add_permission user2_org1_session_file ROLE_1 DOC_DELETE
./rep_add_permission user2_org1_session_file ROLE_1 DOC_NEW


# List role permissions again
./rep_list_role_permissions user2_org1_session_file ROLE_1
./rep_list_role_permissions user2_org1_session_file ROLE_2
./rep_list_role_permissions user2_org1_session_file ROLE_3

# ROLE_1: [DOC_READ, DOC_DELETE, DOC_NEW]
# ROLE_2: [DOC_ACL, DOC_READ, DOC_DELETE, ROLE_ACL]
# ROLE_3: [DOC_NEW, ROLE_NEW, ROLE_MOD]


# Add subjects to roles
./rep_list_subject_roles user1_org1_session_file user4      # Org level
./rep_add_permission user2_org1_session_file ROLE_1 user4   # Org level
./rep_list_subject_roles user1_org1_session_file user4      # Org level     [ROLE_1, ROLE_2]
./rep_list_roles user4_org1_session_file                    # Session level [ROLE_2]

./rep_list_subject_roles user1_org1_session_file user3      # Org level
./rep_add_permission user2_org1_session_file ROLE_2 user3   # Org level
./rep_list_subject_roles user1_org1_session_file user3      # Org level     [ROLE_1, ROLE_2, ROLE_3]    -> This uses the organization acl roles
./rep_list_roles user3_org1_session_file                    # Session level [ROLE_1, ROLE_3]            -> This uses the session context

# IMPORTANT:
# Notice how the last two commands show different results for user3. 
# This is because the first one is at organization level and the second one is at session level.
# User3 has ROLE_2 at organization level but not at session level, because he has not assumed it.


# Remove subjects from roles
./rep_remove_permission user2_org1_session_file ROLE_1 user4
./rep_list_subject_roles user1_org1_session_file user4      # Org level     [ROLE_2]
./rep_list_roles user4_org1_session_file                    # Session level [ROLE_2]


# Remove permissions from roles
./rep_remove_permission user2_org1_session_file ROLE_2 DOC_READ
./rep_list_role_permissions user2_org1_session_file ROLE_2

./rep_remove_permission user2_org1_session_file ROLE_1 DOC_READ
./rep_list_role_permissions user2_org1_session_file ROLE_1

# ROLE_1: [DOC_DELETE, DOC_NEW]
# ROLE_2: [DOC_ACL, DOC_DELETE, ROLE_ACL]

# Add document permissions to roles
./rep_acl_doc user1_org1_session_file doc1 + ROLE_1 DOC_ACL
./rep_acl_doc user1_org1_session_file doc1 + ROLE_1 DOC_READ
./rep_acl_doc user1_org1_session_file doc1 + ROLE_1 DOC_DELETE
./rep_acl_doc user1_org1_session_file doc1 + ROLE_2 DOC_ACL
./rep_acl_doc user1_org1_session_file doc1 + ROLE_2 DOC_READ
./rep_acl_doc user1_org1_session_file doc1 + ROLE_2 DOC_DELETE
./rep_acl_doc user1_org1_session_file doc1 + ROLE_3 DOC_ACL
./rep_acl_doc user1_org1_session_file doc1 + ROLE_3 DOC_READ
./rep_acl_doc user1_org1_session_file doc1 + ROLE_3 DOC_DELETE

# Remove document permissions from roles
./rep_acl_doc user1_org1_session_file doc1 - ROLE_1 DOC_ACL
./rep_acl_doc user1_org1_session_file doc1 - ROLE_2 DOC_READ
./rep_acl_doc user1_org1_session_file doc1 - ROLE_3 DOC_DELETE

