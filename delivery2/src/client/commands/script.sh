#!/bin/bash

./rep_subject_credentials 123 user1_cred_file
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
./rep_list_orgs
./rep_create_session org1 user1 123 user1_cred_file user1_session_file
./rep_list_subjects user1_session_file

./rep_subject_credentials 456 user2_cred_file
./rep_add_subject user1_session_file user2 User2 user2@gmail.com user2_cred_file

./rep_subject_credentials 789 user3_cred_file
./rep_add_subject user1_session_file user3 User3 user3@gmail.com user3_cred_file

./rep_subject_credentials 101112 user4_cred_file
./rep_add_subject user1_session_file user4 User4 user4@gmail.com user4_cred_file

./rep_list_subjects user1_session_file
./rep_list_subjects user1_session_file user2

# ---

./rep_create_session org1 user2 456 user2_cred_file user2_session_file
./rep_suspend_subject user2_session_file user4
./rep_list_subjects user2_session_file user4

# ---

./rep_create_session org1 user3 789 user3_cred_file user3_session_file
./rep_activate_subject user3_session_file user4
./rep_list_subjects user3_session_file user4

# ---

./rep_add_doc user1_session_file doc1 file1.txt
./rep_add_doc user1_session_file doc2 file2.txt

# ---

./rep_get_doc_metadata user1_session_file doc1
./rep_get_doc_metadata user1_session_file doc2

# ---
