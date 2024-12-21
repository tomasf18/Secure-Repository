#!/bin/bash
cd ../commands

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file


# Create organization
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file


# List organizations
./rep_list_orgs


# Create session
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file

./rep_assume_role user1_org1_session_file Manager

# Add subjects to organization
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file


# List subjects
./rep_list_subjects user1_org1_session_file


# Create sessions for the new subjects
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file


# Add roles
./rep_add_role user1_org1_session_file ROLE_1
./rep_add_role user1_org1_session_file ROLE_2
./rep_add_role user1_org1_session_file ROLE_3
./rep_add_role user1_org1_session_file ROLE_4


# Assume roles
./rep_assume_role user1_org1_session_file ROLE_1
./rep_assume_role user1_org1_session_file ROLE_2
./rep_assume_role user1_org1_session_file ROLE_3
./rep_assume_role user2_org1_session_file ROLE_2
./rep_assume_role user2_org1_session_file ROLE_4


# List session roles in use by the subject
./rep_list_roles user1_org1_session_file
./rep_list_roles user2_org1_session_file


# List subjects who have a role in the organization
./rep_list_role_subjects user1_org1_session_file ROLE_1
./rep_list_role_subjects user1_org1_session_file ROLE_2
./rep_list_role_subjects user1_org1_session_file ROLE_3
./rep_list_role_subjects user1_org1_session_file ROLE_4


# List roles of a subject in the organization
./rep_list_subject_roles user1_org1_session_file user1
./rep_list_subject_roles user1_org1_session_file user2


# Add subjects to roles
./rep_add_permission user1_org1_session_file ROLE_1 user2   # Org level
./rep_list_subject_roles user1_org1_session_file user2      # Org level     
./rep_list_roles user2_org1_session_file                    # Session level 


# Remove subjects from roles
# ./rep_remove_permission user2_org1_session_file ROLE_1 user4
# ./rep_list_subject_roles user1_org1_session_file user4      # Org level     
# ./rep_list_roles user4_org1_session_file                    # Session level 

