#!/bin/bash

# Add subjects credentials
./rep_subject_credentials 123 user1_cred_file
./rep_subject_credentials 456 user2_cred_file
./rep_subject_credentials 789 user3_cred_file
./rep_subject_credentials 321 user4_cred_file
./rep_subject_credentials 654 user5_cred_file
./rep_subject_credentials 987 user6_cred_file
./rep_subject_credentials 213 user7_cred_file
./rep_subject_credentials 645 user8_cred_file
./rep_subject_credentials 978 user9_cred_file
./rep_subject_credentials 312 user10_cred_file


# Create organizations
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
./rep_create_org org2 user6 User6 user6@gmail.com user6_cred_file


# List organizations
./rep_list_orgs


# Create sessions
./rep_create_session org1 user1 123 user1_cred_file user1_org1_session_file
./rep_create_session org2 user6 987 user6_cred_file user6_org2_session_file


# Add subjects to organizations
./rep_add_subject user1_org1_session_file user2 User2 user2@gmail.com user2_cred_file
./rep_add_subject user1_org1_session_file user3 User3 user3@gmail.com user3_cred_file
./rep_add_subject user1_org1_session_file user4 User4 user4@gmail.com user4_cred_file
./rep_add_subject user1_org1_session_file user5 User5 user5@gmail.com user5_cred_file

./rep_add_subject user6_org2_session_file user7 User7 user7@gmail.com user7_cred_file
./rep_add_subject user6_org2_session_file user8 User8 user8@gmail.com user8_cred_file
./rep_add_subject user6_org2_session_file user9 User9 user9@gmail.com user9_cred_file
./rep_add_subject user6_org2_session_file user10 User10 user10@gmail.com user10_cred_file


# List subjects
./rep_list_subjects user1_org1_session_file
./rep_list_subjects user1_org1_session_file user3
./rep_list_subjects user6_org2_session_file


# Create sessions for the new subjects
./rep_create_session org1 user2 456 user2_cred_file user2_org1_session_file
./rep_create_session org1 user3 789 user3_cred_file user3_org1_session_file
./rep_create_session org1 user4 321 user4_cred_file user4_org1_session_file
./rep_create_session org1 user5 654 user5_cred_file user5_org1_session_file

./rep_create_session org2 user7 213 user7_cred_file user7_org2_session_file
./rep_create_session org2 user8 645 user8_cred_file user8_org2_session_file
./rep_create_session org2 user9 978 user9_cred_file user9_org2_session_file
./rep_create_session org2 user10 312 user10_cred_file user10_org2_session_file


# Suspend 2 subjects
./rep_suspend_subject user1_org1_session_file user2
./rep_suspend_subject user7_org2_session_file user10


# List subjects
./rep_list_subjects user1_org1_session_file user2
./rep_list_subjects user6_org2_session_file user10


# Activate 1 subject
./rep_activate_subject user1_org1_session_file user2


# List subjects
./rep_list_subjects user1_org1_session_file 
./rep_list_subjects user6_org2_session_file


# Add documents
./rep_add_doc user1_org1_session_file doc1 file1.txt
./rep_add_doc user1_org1_session_file doc2 file2.txt
./rep_add_doc user1_org1_session_file doc3 file3.txt
./rep_add_doc user1_org1_session_file doc4 file4.txt
./rep_add_doc user1_org1_session_file doc5 file5.txt

./rep_add_doc user6_org2_session_file doc6 file6.txt
./rep_add_doc user6_org2_session_file doc7 file7.txt
./rep_add_doc user6_org2_session_file doc8 file8.txt
./rep_add_doc user6_org2_session_file doc9 file9.txt
./rep_add_doc user6_org2_session_file doc10 file10.txt


# Get decrypted files
./rep_get_doc_file user1_org1_session_file doc1
./rep_get_doc_file user1_org1_session_file doc2
./rep_get_doc_file user1_org1_session_file doc3

./rep_get_doc_file user6_org2_session_file doc6
./rep_get_doc_file user6_org2_session_file doc7
./rep_get_doc_file user6_org2_session_file doc8


# Delete documents and get their metadata to check if they were deleted
./rep_delete_doc user1_org1_session_file doc4
./rep_get_doc_metadata user1_org1_session_file doc4

./rep_delete_doc user6_org2_session_file doc9
./rep_get_doc_metadata user6_org2_session_file doc9


# Add roles
./rep_add_role user1_org1_session_file ROLE_1
./rep_add_role user1_org1_session_file ROLE_2
./rep_add_role user1_org1_session_file ROLE_3

./rep_add_role user6_org2_session_file ROLE_4
./rep_add_role user6_org2_session_file ROLE_5
./rep_add_role user6_org2_session_file ROLE_6


# Assume roles
./rep_assume_role user1_org1_session_file ROLE_1
./rep_assume_role user1_org1_session_file ROLE_2
./rep_assume_role user1_org1_session_file ROLE_3
./rep_assume_role user2_org1_session_file ROLE_1
./rep_assume_role user2_org1_session_file ROLE_2

./rep_assume_role user2_org1_session_file ROLE_3 # To drop

./rep_assume_role user3_org1_session_file ROLE_3
./rep_assume_role user3_org1_session_file ROLE_1
./rep_assume_role user4_org1_session_file ROLE_2


./rep_assume_role user6_org2_session_file ROLE_4
./rep_assume_role user6_org2_session_file ROLE_5
./rep_assume_role user6_org2_session_file ROLE_6
./rep_assume_role user7_org2_session_file ROLE_4
./rep_assume_role user7_org2_session_file ROLE_5

./rep_assume_role user7_org2_session_file ROLE_6 # To drop

./rep_assume_role user8_org2_session_file ROLE_6
./rep_assume_role user8_org2_session_file ROLE_4
./rep_assume_role user9_org2_session_file ROLE_5


# List session roles
./rep_list_roles user1_org1_session_file
./rep_list_roles user2_org1_session_file
./rep_list_roles user3_org1_session_file
./rep_list_roles user4_org1_session_file

./rep_list_roles user6_org2_session_file
./rep_list_roles user7_org2_session_file
./rep_list_roles user8_org2_session_file
./rep_list_roles user9_org2_session_file


# Drop roles
./rep_drop_role user2_org1_session_file ROLE_3
./rep_drop_role user7_org2_session_file ROLE_6


# List seession roles
./rep_list_roles user1_org1_session_file
./rep_list_roles user2_org1_session_file
./rep_list_roles user3_org1_session_file
./rep_list_roles user4_org1_session_file

./rep_list_roles user6_org2_session_file
./rep_list_roles user7_org2_session_file
./rep_list_roles user8_org2_session_file
./rep_list_roles user9_org2_session_file

# User 1: [ROLE_1, ROLE_2, ROLE_3]
# User 2: [ROLE_1, ROLE_2]
# User 3: [ROLE_1, ROLE_3]
# User 4: [ROLE_2]

# User 6: [ROLE_4, ROLE_5, ROLE_6]
# User 7: [ROLE_4, ROLE_5]
# User 8: [ROLE_4, ROLE_6]
# User 9: [ROLE_5]


# List subjects who have a role
./rep_list_role_subjects user1_org1_session_file ROLE_1
./rep_list_role_subjects user1_org1_session_file ROLE_2
./rep_list_role_subjects user1_org1_session_file ROLE_3

./rep_list_role_subjects user6_org2_session_file ROLE_4
./rep_list_role_subjects user6_org2_session_file ROLE_5
./rep_list_role_subjects user6_org2_session_file ROLE_6


# List roles of a subject
./rep_list_subject_roles user1_org1_session_file user1
./rep_list_subject_roles user1_org1_session_file user2
./rep_list_subject_roles user1_org1_session_file user3
./rep_list_subject_roles user1_org1_session_file user4

./rep_list_subject_roles user6_org2_session_file user6
./rep_list_subject_roles user6_org2_session_file user7
./rep_list_subject_roles user6_org2_session_file user8
./rep_list_subject_roles user6_org2_session_file user9


# Suspend roles
./rep_suspend_role user2_org1_session_file ROLE_3
./rep_suspend_role user9_org2_session_file ROLE_4


# Reactivate roles
./rep_reactivate_role user2_org1_session_file ROLE_3
./rep_reactivate_role user9_org2_session_file ROLE_4


# List role permissions
./rep_list_role_permissions user2_org1_session_file Manager
./rep_list_role_permissions user2_org1_session_file ROLE_2
./rep_list_role_permissions user9_org2_session_file ROLE_5


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

./rep_add_permission user9_org2_session_file ROLE_5 DOC_ACL
./rep_add_permission user9_org2_session_file ROLE_5 DOC_READ
./rep_add_permission user9_org2_session_file ROLE_5 DOC_DELETE
./rep_add_permission user9_org2_session_file ROLE_4 DOC_NEW
./rep_add_permission user9_org2_session_file ROLE_4 ROLE_NEW
./rep_add_permission user9_org2_session_file ROLE_4 ROLE_MOD
./rep_add_permission user9_org2_session_file ROLE_6 DOC_READ
./rep_add_permission user9_org2_session_file ROLE_6 DOC_DELETE
./rep_add_permission user9_org2_session_file ROLE_6 DOC_NEW

# List role permissions
./rep_list_role_permissions user2_org1_session_file ROLE_1
./rep_list_role_permissions user2_org1_session_file ROLE_2
./rep_list_role_permissions user2_org1_session_file ROLE_3

./rep_list_role_permissions user9_org2_session_file ROLE_4
./rep_list_role_permissions user9_org2_session_file ROLE_5
./rep_list_role_permissions user9_org2_session_file ROLE_6

# ROLE_1: [DOC_READ, DOC_DELETE, DOC_NEW]
# ROLE_2: [DOC_ACL, DOC_READ, DOC_DELETE, ROLE_ACL]
# ROLE_3: [DOC_NEW, ROLE_NEW, ROLE_MOD]

# ROLE_4: [DOC_NEW, ROLE_NEW, ROLE_MOD]
# ROLE_5: [DOC_ACL, DOC_READ, DOC_DELETE]
# ROLE_6: [DOC_READ, DOC_DELETE, DOC_NEW]