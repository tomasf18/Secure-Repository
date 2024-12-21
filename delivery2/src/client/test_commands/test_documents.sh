#!/bin/bash
cd ../commands

USER1_ORG1_SESSION=user1_org1_session_file
USER1_ORG2_SESSION=user1_org2_session_file
USER2_ORG1_SESSION=user2_org1_session_file
USER3_ORG2_SESSION=user3_org2_session_file
DOCUMENT=doc1

INPUT_FILE=file1.txt
OUTPUT_FILE=output.txt

# Create Users
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 123 user2_cred_file
./rep_subject_credentials 123 user3_cred_file

echo
# Create Organizatrion
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
./rep_create_org org2 user3 User3 user3@gmail.com user3_cred_file

echo
# Create Session
./rep_create_session org1 user1 123 user1_cred_file $USER1_ORG1_SESSION
./rep_create_session org2 user3 123 user3_cred_file $USER3_ORG2_SESSION
./rep_assume_role $USER1_ORG1_SESSION Manager
./rep_assume_role $USER3_ORG2_SESSION Manager
./rep_add_subject $USER1_ORG1_SESSION user2 User2 user2@gmail.com user2_cred_file
./rep_add_subject $USER3_ORG2_SESSION user1 User1 user1@gmail.com user1_cred_file
./rep_create_session org1 user2 123 user2_cred_file $USER2_ORG1_SESSION
./rep_create_session org2 user1 123 user1_cred_file $USER1_ORG2_SESSION

# Org1 -> [User1, User2]
# Org2 -> [User3, User1]
# Sessions
# User1 -> [org1 {role: Manager}]
# User2 -> [org1 {role: }]
# User3 -> [org2 {role: Manager}]
# User1 -> [org2 {role: }]

echo
# Non existent docs
# SHOULD FAIL (No documents)
./rep_list_docs $USER1_ORG1_SESSION
./rep_get_doc_metadata  $USER1_ORG1_SESSION $DOCUMENT
./rep_get_doc_file $USER1_ORG1_SESSION $DOCUMENT
./rep_delete_doc $USER1_ORG1_SESSION $DOCUMENT
./rep_get_file $DOCUMENT # Anonymous

echo
# Add doc WITHOUT PERMISSION
# (SHOULD FAIL) (NO DOC_NEW)
./rep_add_doc $USER2_ORG1_SESSION $DOCUMENT $INPUT_FILE
./rep_list_docs $USER2_ORG1_SESSION
# Org1Files -> [doc1 {Creator: user1}]
# Org2Files -> []

echo
# Add doc WITH PERMISSION
./rep_add_doc $USER1_ORG1_SESSION $DOCUMENT $INPUT_FILE
./rep_list_docs $USER1_ORG1_SESSION

echo
# Fetch added docs WITHOUT PERMISSION
# (SHOULD FAIL)
./rep_get_doc_metadata $USER2_ORG1_SESSION $DOCUMENT
./rep_get_doc_file $USER2_ORG1_SESSION $DOCUMENT


echo
# Fetch added docs WITH PERMISSION
./rep_get_doc_metadata $USER1_ORG1_SESSION $DOCUMENT
./rep_get_doc_file $USER1_ORG1_SESSION $DOCUMENT

echo 
# SHould write to file
./rep_get_doc_file $USER1_ORG1_SESSION $DOCUMENT $OUTPUT_FILE

# Fetch file from other organization
# Should fail
./rep_get_doc_file $USER1_ORG2_SESSION $DOCUMENT

echo
# Delete docs WITHOUT PERMISSION
# (SHOULD FAIL) (NO DOC_DELETE)
./rep_delete_doc $USER2_ORG1_SESSION $DOCUMENT
./rep_list_docs $USER2_ORG1_SESSION

echo
# Delete docs WITH PERMISSION
./rep_delete_doc $USER1_ORG1_SESSION $DOCUMENT

echo
./rep_list_docs $USER1_ORG2_SESSION

echo
# Fetch deleted docs
# (SHOULD RETURN METADATA with file_handle = nill)
./rep_get_doc_metadata $USER1_ORG1_SESSION $DOCUMENT
# (SHOULD FAIL file not found)
./rep_get_doc_file $USER1_ORG1_SESSION $DOCUMENT