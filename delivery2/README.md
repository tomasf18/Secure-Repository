# SIO Project

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

### **Important Note about passing arguments to some commands** -> See the tests files for reference on how to run these commands
- On most commands that require a file path as an argument, you **do not need** to pass the full path nor the file extension. The command will automatically store/search the file on the respective directories.
- For the command `rep_subject_credentials <password> <credentials file>` and `rep_add_subject <session file> <username> <name> <email> <credentials file>`, for the `credentials file` you should only pass the name of the file (these files are stored on the `delivery2/src/client/data/keys/subject_keys` folder).
- For the command `rep_decrypt_file <encrypted file> <encyption metadata>`, `encrypted file` should be the file name (or path, inside the `delivery2/src/client/data/encrypted_files` folder). And, as it is a local command, the encryption metadata can be found on the `delivery2/src/client/data/metadatas` folder, and you only need to pass the path **inside this folder** (e.g.: for file `delivery2/src/client/data/metadatas/user1_org1/doc1_metadata.json`, you only need to pass `user1_org1/doc1` - the path inside `metadatas` folder, which includes the name of the document - as an argument).
- On `rep_create_org <organization> <username> <name> <email> <public key file>`, for the public key file, you should do the same as described on the second bullet point for credentials file. These files are stored on the `delivery2/src/client/keys/subject_keys` folder.
- Here: `rep_create_session <organization> <username> <password> <credentials file> <session file>`, for the `credentials file`, you should do the same as described on the second bullet point for credentials file, and for the `session file`, you only need to pass the name of the file, and the command will automatically store the file on the respective directory with the `.json` extension. These files are stored on the `delivery2/src/client/sessions` folder.
- On `rep_get_file <file handle> [file]`, for the [file] argument, you can pass either the name of the file or some path. This path will be inside the `delivery2/src/client/data/encrypted_files` folder.
- For the commands that require a session file, you should only pass the name of the file (without the `.json` extension or the path) that is stored on the `delivery2/src/client/sessions` folder.
- For `rep_add_doc <session file> <document name> <file>` command, the file argument should be only the name of the file that is stored on the `delivery2/src/client/data/files` folder.
- On `rep_get_doc_file <session file> <document name> [file]` command, the file argument should be only the name of the file that is stored on the `delivery2/src/client/data/decrypted_files` folder (or relative path inside this folder).


## Tests
In order to test the implementation, a few scripts were created independently, where a big set of possible actions while using the application were taken.
Those scripts live on the folder `delivery2/src/client/test_commands`.
To test the repository, firstly the database must be cleaned in between each run of each script.

-- To run the tests:
1. Navigate to `delivery2/src/client/test_commands` folder.
2. Run the following command 
    ```bash 
    ./{test_script_name}.sh
    ```
3. Analyze the output given the command ran and the arguments passed into the command 
4. Clear the server database:
    1. Navigate to `delivery2/src`
    2. Run the cleaning script
        ```bash 
        ./clear_all_data.sh
        ```

## <i class="fa-solid fa-people-group"></i> Our Team 

| <div align="center"><a href="https://github.com/tomasf18"><img src="https://avatars.githubusercontent.com/u/122024767?v=4" width="150px;" alt="Tomás Santos"/></a><br/><strong>Tomás Santos</strong><br/>112981</div> | <div align="center"><a href="https://github.com/DaniloMicael"><img src="https://avatars.githubusercontent.com/u/115811245?v=4" width="150px;" alt="Danilo Silva"/></a><br/><strong>Danilo Silva</strong><br/>113384</div> | <div align="center"><a href="https://github.com/Affapple"><img src="https://avatars.githubusercontent.com/u/65315165?v=4" width="150px;" alt="João Gaspar"/></a><br/><strong>João Gaspar</strong><br/>114514</div> |
| --- | --- | --- |

---

## 📂 Folder Structure

```plaintext
.
├── docs/                         # Documentation files                   
├── src/                          # Source code
│   ├── client/                   # Client-side code
│   │   ├── api/                  # API consumer
│   │   ├── test_commands/        # Scripts used to test Repository commands
│   │   ├── commands/             # Repository commands
│   │   ├── data/                 # Data from the client
│   │   │   ├── decrypted_files/  # Files that have been decrypted
│   │   │   ├── encrypted_files/  # Fetched encrypted files
│   │   │   ├── files/            # Files to be uploaded to the repository
│   │   │   └── metadatas/        # Saved fetched document metadatas
│   │   ├── keys/                 # Keys used in the client
│   │   │   └── subject_keys/     # Subject generated keypairs
│   │   ├── sessions/             # Sessions created by the client
│   │   ├── utils/                # Utility functions
│   │   └── client.py             # Main client script
│   ├── server/                   # Server-side code
│   │   ├── controllers/          # Request handlers
│   │   ├── dao/                  # Data access objects
│   │   ├── data/                 # Data from the server
│   │   ├── models/               # Data models
│   │   ├── repkeys/              # Repository keys
│   │   ├── services/             # Business logic
│   │   ├── utils/                # Utility functions
│   │   └── server.py             # Main server script
│   ├── tests/                    # Test files
│   │   ├── test.py               # Test script
│   │   └── data.json             # Test data
│   └── clear_all_data.sh         # Script to clear all data
├── .env                          # Environment variables
├── .gitignore                    # Git ignore file
├── requirements.txt              # Python dependencies
└── README.md                     # Project README
```

---

## 📄 API Documentation

### </> API Endpoints

| **Endpoint**                                                                  | **Method** | **Description**                                  | **Access**              | **Parameters**                      |
|-------------------------------------------------------------------------------|------------|--------------------------------------------------|-------------------------|-------------------------------------|
| `/sessions`                                                                   | POST       | Create a new session                             | Anonymous API           | -                                   |
| `/organizations`                                                              | POST       | Create a new organization                        | Anonymous API           | -                                   |
| `/organizations`                                                              | GET        | List organizations                               | Anonymous API           | -                                   |
| `/organizations/{organization_name}/subjects`                                 | GET        | List subjects (with a role)                      | Authenticated API       | `role={role}`                       |
| `/organizations/{organization_name}/subjects`                                 | POST       | Add a subject to the organization                | Authorized API          | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}`              | GET        | Get subject details                              | Authenticated API       | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}`              | PUT        | Activate a subject                               | Authorized API          | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}`              | DELETE     | Suspend a subject                                | Authorized API          | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}/roles`        | GET        | Get roles of a subject                           | Authenticated API       | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}/roles/{role}` | PUT        | Add role to subject                              | Authorized API          | -                                   |
| `/organizations/{organization_name}/subjects/{subject_username}/roles/{role}` | DELETE     | Remove role from subject                         | Authorized API          | -                                   |
| `/organizations/{organization_name}/roles`                                    | GET        | List roles (with permission)                     | Authenticated API       | `permission={permission}`           |
| `/organizations/{organization_name}/roles`                                    | POST       | Add a new role                                   | Authorized API          | -                                   |
| `/organizations/{organization_name}/roles/{role}`                             | PUT        | Activate a role                                  | Authorized API          | -                                   |
| `/organizations/{organization_name}/roles/{role}`                             | DELETE     | Deactivate a role                                | Authorized API          | -                                   |
| `/organizations/{organization_name}/roles/{role}/subject-permissions`         | GET        | Get role permissions                             | Authenticated API       | -                                   |
| `/organizations/{organization_name}/roles/{role}/subject-permissions`         | PUT        | Add subject/permission to role                   | Authorized API          | -                                   |
| `/organizations/{organization_name}/roles/{role}/subject-permissions`         | DELETE     | Remove subject/permission from role              | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents`                                | GET        | Query documents                                  | Authenticated API       | `username`, `date_filter`, `date`   |
| `/organizations/{organization_name}/documents`                                | POST       | Add a document                                   | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents/{document_name}`                | GET        | Get document metadata                            | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents/{document_name}`                | DELETE     | Delete a document                                | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents/{document_name}/file`           | GET        | Download file of a document                      | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents/{document_name}/ACL`            | PUT        | Update document ACL                              | Authorized API          | -                                   |
| `/organizations/{organization_name}/documents/{document_name}/ACL`            | DELETE     | Remove document ACL                              | Authorized API          | -                                   |
| `/organizations/{sorganization_name}/sessions/{session_id}/roles`              | GET        | List active roles in the session                 | Authenticated API       | -                                   |
| `/organizations/{organization_name}/sessions/{session_id}/roles/{role}`       | PUT        | Assume a role in the session                     | Authenticated API       | -                                   |
| `/organizations/{organization_name}/sessions/{session_id}/roles/{role}`       | DELETE     | Drop an assumed role in the session              | Authorized API          | -                                   |
| `/files/{file_handle}`                                                        | GET        | Download a file                                  | Anonymous API           | -                                   |

---

### <i class="fa-solid fa-lock"></i> Authentication & Authorization

- **Authenticated API**: Requires the user to be authenticated with a valid session.
- **Authorized API**: Requires the user to have the appropriate permissions to perform the requested action.
- **Anonymous API**: Accessible without authentication, but some actions may still require minimal input or constraints.

---

### <i class="fa-solid fa-reply"></i> Response Codes

#### <i class="fa-solid fa-check"></i> Success Codes

- **200 OK**: The requested action was sucessful.
- **201 CREATED**: The requested data insertion/update was sucessfuly saved on the database.

#### <i class="fa-solid fa-user-xmark"></i> Client Error Codes

- **400 Bad Request**: The request is malformed or missing required parameters.
- **401 Unauthorized**: Authentication is required to access the resource.
- **403 Forbidden**: The authenticated user does not have permission to access the resource.
- **404 Not Found**: The requested resource could not be found.

#### <i class="fa-solid fa-circle-exclamation"></i> Server Error Codes
- **500 Internal Server Error**: Something went wrong in the server while completing the request, no useful data returned.

---


## <i class="fa-solid fa-terminal"></i> Implemented Commands

### Commands Return Codes

All client commands follow UNIX semantics on return codes:
* **0** - The command ran and finished with sucess
* **1** - The command terminated earlier because of an input error, happens when user try to run a command with invalid values, such as passing a file that does not exists. This means that no connection to the server was made
* **-1** - The command terminated earlier because of an error in the repository, happens when the command was sucessfuly sent to the repository, but some error ocurred, e.g. `role not bound to user` when attempting to assume a new role in the session

### Local Commands

#### `rep_subject_credentials <password> <credentials file>`
- This command creates a key pair for a subject, storing it in a given credentials file.

**Note:** to generate the key pair we use the ECC with a given password to encrypt the private key

#### `rep_decrypt_file <encrypted file> <encyption metadata>`
- This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata.
  
**Note:** to decrypt the file we use the algorithm and mode provided in the metadata (currently using AES256-CBC)

### Anonymous API Commands

#### How do we make this communication secure?
- To secure an anonymous communication between the client and the server, we use ECDH to generate a shared secret.
- Client generates a random public key and sends it in plaintext to the server.
- Server uses the public key sent by the client to generate the shared secret.
- Then, the server generates a random public key and sends it **signed** with the repository private key to the client.
- Client verifies the signature and generates the shared secret.
- Then, the client can use the shared secret to encrypt the anonymous message to be sent to the server.
- The server decrypts the message using the shared secret.
- When sending the response, the server uses the shared secret to encrypt the message.
- The client decrypts the message using the shared secret and does what it needs to do with the response.
- This way, we can guarantee that the communication is secure and that the client is talking to the correct server.
- As, in this kind of communication, the client is anonymous, we don't need to worry about the server authenticating the client.

The following diagram takes a closer look at how this is done in the code:
![Session Messages Diagram](./docs/AnonymousAPICommunication.pdf)

#### `rep_create_org <organization> <username> <name> <email> <public key file>`
- This command creates an organization in a Repository and defines its first subject.

#### `rep_list_orgs`
- This command lists all organizations defined in a Repository. Should be implemented in the first delivery.

#### `rep_create_session <organization> <username> <password> <credentials file> <session file>`
- This command creates a session for a username belonging to an organization, and stores the session context in a file.

#### `rep_get_file <file handle> [file]`
- This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

### Authenticated API Commands

#### How do we make this communication secure?
- To secure the communication between the client and the server during a session, we generate a 64-bit shared secret using ECDH.
- All the security of a session comes from its creation moment.
- The client generates a random ECC public key, this one is to obtain the **session shared key**. We refer to the ECC public keys generated on both sides as **session public keys**.
- And, having already shared its credentials with the repository, signs the session info (with the generated session public key included) he wants to send to the server (namely the organization and username).
- Then, as this still is an anonymous communication, the same process described above is used to generate an ephemeral shared secret, just for this command (this is, just to take the session - signed - information from the client to the server). Here, we refer to the ECC public keys generated on both sides as **ephemeral**.
- Once the **ephemeral** secret is agreed, the client sends the signed session info to the server, securely encrypted.
- The server then decrypts the message.
- With the session info decrypted, on `create_session()` function, the server verifies the signature using the public key of the client on that organization.
- After that, he generates its own **session public key**.
- Then, the server generates the **session shared key/secret** using the **session public key** of the client.
- The server creates a response message with all the session information for the client's session file. This information also includes the **session public key** of the server, so that the client can generate the **session shared key/secret**.
- The server signs the response message with the **repository private key**.
- Then, all this information is encrypted with the **ephemeral shared key/secret** agreed for this command execution.
- The server sends the encrypted message to the client.
- The client decrypts the message.
- The client verifies the signature using the **repository public key**.
- The client generates the **session shared key/secret** using the **session public key** of the server.
- Finally, the client stores the session information in the session file.

- The following diagram shows how the session secret is obtained, and, consequently, how the session is created.
![Session Messages Diagram](./docs/CreatingSecureSession.pdf)

- The following diagram shows how the session contents are encrypted on both sides.
![Session Messages Diagram](./docs/EncryptionDiagram.pdf)

- The following diagram shows how the session contents are decrypted on both sides.
![Session Messages Diagram](./docs/DecryptionDiagram.pdf)


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

## Implemented Features

All previous commands where completely implemented, with the following requirements:
* When an organization is created, its creator becomes a Manager of the organization
    * Each Organization must always have a role Manager
    * Each Organization must have, at all times, at least one subject with the role Manager
        * When a subject is suspended/removed, it's ensured that the operation is only sucessful if exists other managers in the organization
* Subjects have:
    * An Elliptic Curve Key Pair, used to be authenticated in a session
    * An unique username
    * An unique email
    * Full name
* Subjects can be added to organizations by other subjects 
    * Subject can be also suspendend/reactivated by users in the organization who have permission SUBJECT_DOWN/SUBJECT_UP
    * Subject Manager can never be suspended
* Roles must have:
    * A name
    * A set of permissions
    * A List of Subjects associated to it
* New Roles can be created in the context of each organization with the permission ROLE_NEW
    * Permissions can be added to roles by users with the permission ROLE_MOD
    * Roles can be deactivated/reactivated by subjects who have the permission ROLE_DOWN/ROLE_UP
* Sessions have:
    * One or mode keys
        * Keys are used for integrity check and to ensure confidentiality
        * Keys are generated through ECDH and passed through an Hash Based Key Derivation Function to get a session key with a length of 64 bytes, of which the first 32 are used to encrypt the sent data and the remaining 32 to generate a Message Authentication Code (a signed digest)
    * An identifier
    * An associated organization
    * A predefined Time To Live, that is refreshed on each operation
    * Active Roles
    * A message counter, that is strictly increasing, in order to prevent out of order messages
        * If a message with a counter lower than the last message, message is discarded
    * A nonce, a random value, that ensures that replay attack is impossible, especially when combined with the message counter
* Subjects can assume roles in a session, but only if it's bounded to him
    * A subject can request to activate roles that are bounded to him
    * When a user assumes roles, he becomes allowed to perform actions based on all the permissions of all the active roles in the current session
* Documents can be added to the repository
    * When a file is uploaded, it must be encrypted with a given algorithm and mode
        * The key to encrypt the file is randomly generated
    * File Integrity must be checked after being received by the Repository
        * When user uploads a file, he also uploads a file_handle that consist of the digest of the original file which is used by the server to carry out a integrity check
    * A document has an ACL that link roles to permissions on that document
    * Only the creator has full access to the document, when created, however permissions can be added to the each role on the document, initally by the creator and then by users who also get access to permission DOC_ACL
    * There must be always one subject in the document with access to permission DOC_ACL
    * A document can also be "deleted"
        * When a document is "deleted", the file_handle entry is nullified
        * The file must always be accessible by subjects who have the file handle of the original file
* Subjects can download files from the repository
    * Subjects who have access to the metadata can also decrypt the file using the file_handle provided in the metadata
    * Uppon a decryption, the file handle provided in the metadata is used to carry out an integrity check.
* Repository has a well-known public key that is used by the client to verify integrity and source authentication of the returned data
    * All assymmetric keys used in the repository and in the client are generated through Elliptic Cryptography
* Sensitive data is encrypted on the server by a master key before being saved in disk
    * Data that needs to be encrypted on the repository, such as (as)symmetric keys, files, etc. are encrypted with a key generated from a password based key derivation function (PBKDF) using the repository password as argument. 
    * In order to create entropy in the generated key used to encrypt the data, a different, random, salt is passed to the PBKDF each time a key is needed. This salt value is saved in the database for future use when decrypting the data