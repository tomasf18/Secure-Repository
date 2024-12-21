#!/bin/bash
cd ../commands

USER1_ORG1_SESSION=user1_org1_session_file
USER1_ORG2_SESSION=user1_org2_session_file
USER2_SESSION=user2_org1_session_file
USER3_SESSION=user3_org2_session_file
DOCUMENT=doc1

INPUT_FILE=file1.txt

# Test invalid key
./rep_subject_credentials 123 user1_cred_file
## SHOULD FAIL
./rep_create_org -k '../keys/subject_keys/pub_user1_cred_file.pub' org1 user1 User1 user1@gmail.com user1_cred_file 
./rep_create_org -r 'localhost:5001' org1 user1 User1 user1@gmail.com user1_cred_file 

                      
echo
# Create Users
./rep_subject_credentials 123 user2_cred_file

echo
# Create Organizatrion
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
./rep_create_org org2 user1 User1 user1@gmail.com user1_cred_file


echo
# Create Session with wrong password
./rep_create_session org1 user1 12 user1_cred_file user1_org1_session_fille

echo
# Create Session
./rep_create_session org1 user1 123 user1_cred_file $USER1_ORG1_SESSION
./rep_create_session org2 user1 123 user1_cred_file $USER1_ORG2_SESSION
./rep_assume_role $USER1_ORG1_SESSION Manager
./rep_assume_role $USER1_ORG2_SESSION Manager
./rep_add_role $USER1_ORG1_SESSION ROLE1


echo
./rep_add_subject $USER1_ORG1_SESSION user2 User2 user2@gmail.com user2_cred_file
# ORG1 -> (user1: Manager), (user2: None)
# ORG2 -> (user1: Manager)
./rep_list_subjects $USER1_ORG1_SESSION user2
# Should list user2

echo
## SHOULD FAIL
./rep_add_subject $USER1_ORG1_SESSION user2 User2 user4@gmail.com user2_cred_file # Repeated user
./rep_add_subject $USER1_ORG1_SESSION user3 User3 user2@gmail.com user2_cred_file # different user with repeated email
##

echo
# Create session at org1 for user2
./rep_create_session org1 user2 123 user2_cred_file $USER2_SESSION
# Create session at org2 for user2
# SHOULD FAIL
./rep_create_session org2 user2 123 user2_cred_file $USER2_SESSION #User2 doest exist at org2


echo
## SHOULD FAIL
./rep_list_permission_roles $USER1_ORG1_SESSION invalid_permission
./rep_list_role_permissions $USER1_ORG1_SESSION invalid_role
./rep_list_subject_roles $USER1_ORG1_SESSION invalid_user

echo
./rep_reactivate_role $USER1_ORG1_SESSION invalid_role
./rep_suspend_role $USER1_ORG1_SESSION invalid_user

echo
    # Invalid roles
./rep_add_permission $USER1_ORG1_SESSION invalid_role user2
./rep_remove_permission $USER1_ORG1_SESSION invalid_role user2
./rep_add_permission $USER1_ORG1_SESSION invalid_role DOC_NEW
./rep_remove_permission $USER1_ORG1_SESSION invalid_role DOC_NEW

echo
    # Invalid users
./rep_add_permission $USER1_ORG1_SESSION ROLE1 invalid_user
./rep_remove_permission $USER1_ORG1_SESSION ROLE1 invalid_user

echo
    # Invalid permission
./rep_add_permission $USER1_ORG1_SESSION ROLE1 invalid_permission
./rep_remove_permission $USER1_ORG1_SESSION ROLE1 invalid_permission
##

echo
# Add documents
./rep_add_doc $USER1_ORG1_SESSION $DOCUMENT $INPUT_FILE
## SHOULD FAIL
./rep_add_doc $USER1_ORG1_SESSION $DOCUMENT $INPUT_FILE
##

echo
./rep_acl_doc $USER1_ORG1_SESSION $DOCUMENT + invalid_role DOC_READ
./rep_acl_doc $USER1_ORG1_SESSION $DOCUMENT + ROLE1 invalid_permission
./rep_acl_doc $USER1_ORG1_SESSION $DOCUMENT - invalid_role DOC_READ
./rep_acl_doc $USER1_ORG1_SESSION $DOCUMENT - ROLE1 invalid_permission
