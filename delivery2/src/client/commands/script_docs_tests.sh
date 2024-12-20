#!/bin/bash

USER1_SESSION=user1_org1_session_file
USER2_SESSION=user2_org1_session_file
USER3_SESSION=user3_org2_session_file
DOCUMENT=doc1

INPUT_FILE=input.txt
OUTPUT_FILE=output.txt

# Create Users
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 123 user2_cred_file
# Create Organizatrion
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
# Create Session
./rep_create_session org1 user1 123 user1_cred_file $USER1_SESSION
./rep_assume_role $USER1_SESSION Manager
./rep_add_subject $USER1_SESSION user2 User2 user2@gmail.com user2_cred_file
./rep_create_session org1 user2 123 user2_cred_file $USER2_SESSION


# Non existent docs
./rep_list_docs $USER1_SESSION
./rep_get_doc_metadata  $USER1_SESSION $DOCUMENT
./rep_get_doc_file $USER1_SESSION $DOCUMENT $OUTPUT_FILE
./rep_delete_doc $USER1_SESSION $DOCUMENT


# Add doc
./rep_add_doc $USER1_SESSION $DOCUMENT $INPUT_FILE
./rep_list_docs $USER1_SESSION

# Fetch added docs WITHOUT PERMISSION
./rep_get_doc_metadata $USER2_SESSION $DOCUMENT
./rep_get_doc_file $USER2_SESSION $DOCUMENT $OUTPUT_FILE

# Fetch added docs WITH PERMISSION
./rep_get_doc_metadata $USER1_SESSION $DOCUMENT
./rep_get_doc_file $USER1_SESSION $DOCUMENT $OUTPUT_FILE
### Counter está a 5!


# Delete docs WITHOUT PERMISSION
./rep_delete_doc $USER2_SESSION $DOCUMENT
./rep_list_docs $USER2_SESSION

# Delete docs WITH PERMISSION
./rep_delete_doc $USER1_SESSION $DOCUMENT
./rep_list_docs $USER1_SESSION


# Fetch deleted docs
./rep_get_doc_metadata  $USER1_SESSION $DOCUMENT
./rep_get_doc_file $USER1_SESSION $DOCUMENT $OUTPUT_FILE
