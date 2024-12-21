#!/bin/bash

USER1_ORG1_SESSION=user1_org1_session_file
USER1_ORG2_SESSION=user1_org2_session_file
USER2_SESSION=user2_org1_session_file
USER3_SESSION=user3_org2_session_file
DOCUMENT=doc1

INPUT_FILE=file1.txt

# Test invalid key
./rep_subject_credentials 123 user1_cred_file
# SHOULD FAIL
./rep_create_org -k '../keys/subject_keys/pub_user1_cred_file.pub' org1 user1 User1 user1@gmail.com user1_cred_file 
./rep_create_org -r 'localhost:5001' org1 user1 User1 user1@gmail.com user1_cred_file 

                                    

# Create Users
./rep_subject_credentials 123 user2_cred_file

# Create Organizatrion
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
./rep_create_org org2 user1 User1 user1@gmail.com user1_cred_file


# Create Session with wrong password
./rep_create_session org1 user1 12 user1_cred_file user1_org1_session_fille

# Create Session
./rep_create_session org1 user1 123 user1_cred_file $USER1_ORG1_SESSION
./rep_create_session org2 user1 123 user1_cred_file $USER1_ORG2_SESSION
./rep_assume_role $USER1_ORG1_SESSION Manager
./rep_assume_role $USER1_ORG2_SESSION Manager
./rep_add_subject $USER1_ORG1_SESSION user2 User2 user2@gmail.com user2_cred_file
# ORG1 -> (user1: Manager), (user2: None)
# ORG2 -> (user1: Manager)
./rep_list_subjects $USER1_ORG1_SESSION user2
# Should list user2

## SHOULD FAIL
./rep_add_subject $USER1_ORG1_SESSION user2 User2 user4@gmail.com user2_cred_file # Repeated user
./rep_add_subject $USER1_ORG1_SESSION user3 User3 user2@gmail.com user2_cred_file # different user with repeated email
##

# Create session at org1 for user2
./rep_create_session org1 user2 123 user2_cred_file $USER2_SESSION
# Create session at org2 for user2
# SHOULD FAIL
./rep_create_session org2 user2 123 user2_cred_file $USER2_SESSION

clear
# List roles
# SHOULD FAIL
./rep_list_permission_roles $USER1_ORG1_SESSION invalid_permission

# SHOULD FAIL
./rep_list_role_permissions $USER1_ORG1_SESSION invalid_role

# Should fail
./rep_list_subject_roles $USER1_ORG1_SESSION invalid_user