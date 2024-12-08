# SIO Project

## <i class="fa-solid fa-people-group"></i> Our Team 

| <div align="center"><a href="https://github.com/tomasf18"><img src="https://avatars.githubusercontent.com/u/122024767?v=4" width="150px;" alt="Tomás Santos"/></a><br/><strong>Tomás Santos</strong><br/>112981</div> | <div align="center"><a href="https://github.com/DaniloMicael"><img src="https://avatars.githubusercontent.com/u/115811245?v=4" width="150px;" alt="Danilo Silva"/></a><br/><strong>Danilo Silva</strong><br/>113384</div> | <div align="center"><a href="https://github.com/Affapple"><img src="https://avatars.githubusercontent.com/u/65315165?v=4" width="150px;" alt="João Gaspar"/></a><br/><strong>João Gaspar</strong><br/>114514</div> |
| --- | --- | --- |

---

## 📂 Folder Structure

```plaintext
.
├── docs/                     # Documentation files                   
├── src/                      # Source code
│   ├── client/               # Client-side code
│   │   ├── api/              # API consumer
│   │   ├── commands/         # Repository commands
│   │   ├── data/             # Data from the client
│   │   ├── keys/             # Keys used in the client
│   │   ├── sessions/         # Sessions created by the client
│   │   ├── utils/            # Utility functions
│   │   └── client.py         # Main client script
│   ├── server/               # Server-side code
│   │   ├── controllers/      # Request handlers
│   │   ├── dao/              # Data access objects
│   │   ├── data/             # Data from the server
│   │   ├── models/           # Data models
│   │   ├── repkeys/          # Repository keys
│   │   ├── services/         # Business logic
│   │   ├── utils/            # Utility functions
│   │   └── server.py         # Main server script
│   ├── tests/                # Test files
│   │   ├── test.py           # Test script
│   │   └── data.json         # Test data
│   └── clear_all_data.sh     # Script to clear all data
├── .env                      # Environment variables
├── .gitignore                # Git ignore file
├── requirements.txt          # Python dependencies
└── README.md                 # Project README
```

---

## 📄 API Documentation

### </> API Endpoints

| **Endpoint**                                | **Method** | **Description**                                    | **Access**              | **Parameters**                                                                 |
|---------------------------------------------|------------|----------------------------------------------------|-------------------------|--------------------------------------------------------------------------------|
| `/sessions`                                 | POST       | Create a new session                              | Anonymous API           | -                                                                              |
| `/organizations`                            | POST       | Create a new organization                         | Anonymous API           | -                                                                              |
| `/organizations`                            | GET        | List organizations                                | Anonymous API           | -                                                                              |
| `/organizations/{organization_name}/subjects` | GET        | List subjects (with a role)                      | Authenticated API       | `role={role}`                                                                 |
| `/organizations/{organization_name}/subjects` | POST       | Add a subject to the organization                | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}` | GET        | Get subject details                              | Authenticated API       | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}` | PUT        | Activate a subject                               | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}` | DELETE     | Suspend a subject                                | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}/roles` | GET        | Get roles of a subject                           | Authenticated API       | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}/roles/{role}` | PUT        | Add role to subject                              | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/subjects/{subject_username}/roles/{role}` | DELETE     | Remove role from subject                         | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/roles`  | GET        | List roles (with permission)                     | Authenticated API       | `permission={permission}`                                                     |
| `/organizations/{organization_name}/roles`  | POST       | Add a new role                                   | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/roles/{role}` | PUT      | Activate a role                                  | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/roles/{role}` | DELETE   | Deactivate a role                                | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/roles/{role}/subject-permissions` | GET | Get role permissions                              | Authenticated API       | -                                                                              |
| `/organizations/{organization_name}/roles/{role}/subject-permissions` | PUT | Add subject/permission to role                   | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/roles/{role}/subject-permissions` | DELETE | Remove subject/permission from role              | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents` | GET       | Query documents                                  | Authenticated API       | `username`, `date_filter`, `date`                                       |
| `/organizations/{organization_name}/documents` | POST      | Add a document                                   | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents/{document_name}` | GET | Get document metadata                            | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents/{document_name}` | DELETE | Delete a document                                | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents/{document_name}/file` | GET       | Download file of a document                      | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents/{document_name}/ACL` | PUT       | Update document ACL                              | Authorized API          | -                                                                              |
| `/organizations/{organization_name}/documents/{document_name}/ACL` | DELETE    | Remove document ACL                              | Authorized API          | -                                                                              |
| `/files/{file_handle}`                       | GET        | Download a file                                  | Anonymous API           | -                                                                              |

---

### <i class="fa-solid fa-lock"></i> Authentication & Authorization

- **Authenticated API**: Requires the user to be authenticated with a valid session.
- **Authorized API**: Requires the user to have the appropriate permissions to perform the requested action.
- **Anonymous API**: Accessible without authentication, but some actions may still require minimal input or constraints.

---

### <i class="fa-solid fa-reply"></i> Response Codes

#### <i class="fa-solid fa-check"></i> Success Codes

#### <i class="fa-solid fa-user-xmark"></i> Client Error Codes

- **400 Bad Request**: The request is malformed or missing required parameters.
- **401 Unauthorized**: Authentication is required to access the resource.
- **403 Forbidden**: The authenticated user does not have permission to access the resource.
- **404 Not Found**: The requested resource could not be found.

#### <i class="fa-solid fa-circle-exclamation"></i> Server Error Codes

---


## <i class="fa-solid fa-terminal"></i> Commands Implemented

### Local Commands

#### `rep_subject_credentials <password> <credentials file>`
- This command creates a key pair for a subject, storing it in a given credentials file.

**Note:** to generate the key pair we use the ECC with a given password to encrypt the private key

#### `rep_decrypt_file <encrypted file> <encyption metadata>`
- This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata.
  
**Note:** to decrypt the file we use the algorithm and mode provided in the metadata (currently using AES256-CBC)

### Anonymous API Commands

#### `rep_create_org <organization> <username> <name> <email> <public key file>`
- This command creates an organization in a Repository and defines its first subject.

#### `rep_list_orgs`
- This command lists all organizations defined in a Repository. Should be implemented in the first delivery.

#### `rep_create_session <organization> <username> <password> <credentials file> <session file>`
- This command creates a session for a username belonging to an organization, and stores the session context in a file.

#### `rep_get_file <file handle> [file]`
- This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

### Authenticated API Commands

#### `rep_assume_role <session file> <role>`
- This command requests the given role for the session.

#### `rep_drop_role <session file> <role>`
- This command releases the given role for the session.

#### `rep_list_roles <session file>`
- This command lists the current session roles.

#### `rep_list_subjects <session file> [username]`
- This command lists the subjects of the organization with which I have currently a session. This command accepts an extra command to show only one subject.

#### `rep_list_role_subjects <session file> <role>`
- This command lists the subjects of a role of the organization with which I have currently a session.

#### `rep_list_subject_roles <session file> <username>`
- This command lists the roles of a subject of the organization with which I have currently a session.

#### `rep_list_role_permissions <session file> <role>`
- This command lists the permissions of a role of the organization with which I have currently a session.

#### `rep_list_permission_roles <session file> <permission>`
- This command lists the roles of the organization with which I have currently a session that have a given permission. 

#### `rep_list_docs <session file> [-s username] [-d nt/ot/et date]`
- This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.

### Authorized API Commands

#### `rep_add_subject <session file> <username> <name> <email> <credentials file>`
- This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active status. This commands requires a **SUBJECT_NEW** permission.

#### `rep_suspend_subject <session file> <username>`
#### `rep_activate_subject <session file> <username>`
- These commands change the status of a subject in the organization with which I have currently a session. These commands require a **SUBJECT_DOWN** and **SUBJECT_UP** permission, respectively.

#### `rep_add_role <session file> <role>`
- This command adds a role to the organization with which I have currently a session. This commands requires a **ROLE_NEW** permission.

#### `rep_suspend_role <session file> <role>`
#### `rep_reactivate_role <session file> <role>`
- These commands change the status of a role in the organization with which I have currently a session. These commands require a **ROLE_DOWN** and **ROLE_UP** permission, respectively.

#### `rep_add_permission <session file> <role> <username>`
#### `rep_remove_permission <session file> <role> <username>`
#### `rep_add_permission <session file> <role> <permission>`
#### `rep_remove_permission <session file> <role> <permission>`
- These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. These commands require a **ROLE_MOD** permission.

#### `rep_add_doc <session file> <document name> <file>`
- This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a **DOC_NEW** permission.

#### `rep_get_doc_metadata <session file> <document name>`
- This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a **DOC_READ** permission.

#### `rep_get_doc_file <session file> <document name> [file]`
- This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a **DOC_READ** permission.

#### `rep_delete_doc <session file> <document name>`
- This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a **DOC_DELETE** permission.

#### `rep_acl_doc <session file> <document name> [+/-] <role> <permission>`
- This command changes the ACL of a document by adding (**+**) or removing (**-**) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a **DOC_ACL** permission.

---

## <i class="fa-solid fa-key"></i> Encryption Documentation
Diagrams of message exchange between client-server

![Session Messages Diagram](./docs/SessionMessagesDiagram.pdf)

## <i class="fa-solid fa-file-code"></i> How to run the project

### 1. Install dependencies

-- To install the dependencies go to the `delivery2` folder and run the following commands:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the server

-- To start the Flask server go to the `delivery2/src/server` folder and run the following command:

```bash
python3 server.py
```

### 3. Run a command

-- Before running a command, ensure you are in the `delivery2/src/client/commands` folder. From there, execute the desired command with the appropriate parameters. For example:

```bash
./rep_create_org org1 user1 User1 user1@gmail.com user1_cred_file
```

**Note:** stopping and starting the server will automatically clear all data both from database and from the local files.

## Tests

-- To run the tests: 
1. Navigate to `delivery2/src` folder.
2. Run the following command:

```bash
pytest tests/test.py -v
```

- For more detailed information, you can run the following command that will show the output of the tests:

```bash
pytest tests/test.py -v -s
```

**Note:** make sure the server is **stopped** before running the tests. The test script will automatically clear all data, start the server and stop it after the tests are done.