# SIO - Secure Repository for Organizations

### **Grade: 19.4/20**

## Project Abstract

The **Secure Repository for Organizations** is a system designed to enable organizations to securely manage and share documents among their members. The repository ensures confidentiality, integrity, and access control by employing encryption, robust session management, and role-based access control (RBAC). 
Tools like `SQLite` with `SQLAlchemy`, `Flask`, and `cryptography` python module are used to implement the system, which includes a server and client-side application. The server manages the database, handles requests, and enforces security policies, while the client interacts with the server through a command-line interface. The client can perform various operations, such as creating organizations, adding subjects, uploading documents, and fetching files. The system ensures that all data is securely encrypted and stored in a separate physical storage from the repository data.

**Key Features:**
- **Encrypted File Storage**: Files are stored in encrypted format to protect sensitive information, and on a different physical storage from all the Repository data.
- **Role-Based Access Control**: Permissions are assigned to roles rather than individuals, allowing flexible access management.
- **Session Security**: Sessions enforce authentication, integrity, and protection against eavesdropping, manipulation, replay and impersonation attacks.
- **Transit Security**: All data transmitted between the client and server (even anonymous interactions) is properly encrypted to prevent unauthorized access.
- **Comprehensive Private Information Management**: All private data is securely encrypted at rest by the repository, ensuring confidentiality and integrity.
- **API Support**: Includes anonymous, authenticated, and authorized APIs for interaction.

This system ensures secure collaboration within organizations, adhering to best practices in information security.

---

## Folder Structure

This project consists of 3 deliverables:
1. **Delivery 1**: Contains the initial project structure, including the API and database setup.
2. **Delivery 2**: Includes the full implementation of the project, with all features and functionalities (this is where the main project code resides).

```plaintext
delivery2/
    |
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

3. **Delivery 3**: Contains the project's report. Here, you can find all the features, functionalities, and implementation details of the system, including a detailed explanation on how we addressed the security requirements, justification of design choices, and the system's Application Security Verification Standard (ASVS) evaluation focusing on Level 3 (L3) under the scope of V6: Stored Cryptography.

---

## How to Run the Project

### 1. Install Dependencies

Navigate to the `delivery2/` folder and run the following commands:
```bash
cd delivery2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Server

Start the Flask server:
```bash
cd src/server
python3 server.py
```

### 3. Run a Command

1. Open another terminal, navigate to the `delivery2/` folder and run the following command:
```bash
cd delivery2
source venv/bin/activate
```

2. Now, navigate to the `delivery2/src/client/commands` folder and execute the desired command. For example:
```bash
cd src/client/commands
./rep_subject_credentials 123 user1_cred_file
```

---

### **Important Notes on Passing Arguments to Commands**

To ensure smooth execution of commands, it’s important to understand how file paths and arguments are handled. This section provides a detailed guide to avoid mistakes and clarify the expected inputs for each command.

#### **General Notes**
- **Automatic Path Handling**: Most commands automatically handle file paths and extensions. You only need to pass the file name or relative path (depending on the command). The system determines the appropriate directory for storing or searching files.
- **Refer to Test Files**: For detailed examples of command usage, refer to the test scripts in `delivery2/src/client/test_commands`.

---

#### **Specific Commands**

1. **`rep_subject_credentials <password> <credentials file>`**  
   - **Purpose**: Creates a key pair for a subject and stores it in a secure credentials file.  
   - **Argument Details**:
     - `<credentials file>`: Pass only the file name (no extension or path). The file will be stored in the `delivery2/src/client/data/keys/subject_keys` folder.  

2. **`rep_add_subject <session file> <username> <name> <email> <credentials file>`**  
   - **Purpose**: Adds a new subject to the organization.  
   - **Argument Details**:
     - `<credentials file>`: Same as above; pass only the file name. The file is stored in the `delivery2/src/client/data/keys/subject_keys` folder.

3. **`rep_decrypt_file <encrypted file> <encryption metadata>`**  
   - **Purpose**: Decrypts an encrypted file using its metadata.  
   - **Argument Details**:
     - `<encrypted file>`: Provide only the file name or relative path within the `delivery2/src/client/data/encrypted_files` folder.
     - `<encryption metadata>`: Specify the relative path inside the `delivery2/src/client/data/metadatas` folder.  
       - **Example**: For the file `delivery2/src/client/data/metadatas/user1_org1/doc1_metadata.json`, pass `user1_org1/doc1` as the argument.

4. **`rep_create_org <organization> <username> <name> <email> <public key file>`**  
   - **Purpose**: Creates a new organization and defines its first subject.  
   - **Argument Details**:
     - `<public key file>`: Pass only the file name. The file is stored in the `delivery2/src/client/keys/subject_keys` folder.

5. **`rep_create_session <organization> <username> <password> <credentials file> <session file>`**  
   - **Purpose**: Creates a session for a user within an organization.  
   - **Argument Details**:
     - `<credentials file>`: Same as in `rep_subject_credentials`.  
     - `<session file>`: Pass only the file name (without the `.json` extension). The file will be stored in the `delivery2/src/client/sessions` folder.

6. **`rep_get_file <file handle> [file]`**  
   - **Purpose**: Downloads a file using its handle.  
   - **Argument Details**:
     - `[file]`: Optional. Pass either the file name or a relative path inside the `delivery2/src/client/data/encrypted_files` folder.

7. **`rep_add_doc <session file> <document name> <file>`**  
   - **Purpose**: Adds a new document to the repository.  
   - **Argument Details**:
     - `<file>`: Pass only the file name. The file must be located in the `delivery2/src/client/data/files` folder.

8. **`rep_get_doc_file <session file> <document name> [file]`**  
   - **Purpose**: Fetches and decrypts a document’s file.  
   - **Argument Details**:
     - `[file]`: Optional. Pass only the file name or a relative path inside the `delivery2/src/client/data/decrypted_files` folder.

9. **Commands Requiring a Session File**  
   - For commands like `rep_assume_role`, `rep_drop_role`, or any other that require a `<session file>`:
     - Pass only the file name (without the `.json` extension or path). The file is stored in the `delivery2/src/client/sessions` folder.

---

### **Examples for Clarity**
1. **Creating a Subject Credential**:
   ```bash
   ./rep_subject_credentials mypassword user1_cred_file
   ```
   - The `user1_cred_file` will be saved in `delivery2/src/client/data/keys/subject_keys`.

2. **Decrypting a File**:
   ```bash
   ./rep_decrypt_file encrypted_file user1_org1/doc1
   ```
   - The encrypted file is searched in `delivery2/src/client/data/encrypted_files`.
   - The metadata is searched in `delivery2/src/client/data/metadatas/user1_org1/doc1_metadata.json`.

3. **Creating a Session**:
   ```bash
   ./rep_create_session org1 user1 mypassword user1_cred_file user1_session
   ```
   - The `user1_cred_file` is in `delivery2/src/client/data/keys/subject_keys`.
   - The `user1_session` will be stored in `delivery2/src/client/sessions`.

**Note**: For more examples and detailed usage, refer to the test scripts in `delivery2/src/client/test_commands`.

---

## Tests

Scripts for testing the repository are located in `delivery2/src/client/test_commands`. To test:

1. Clear the server database before each test:
```bash
cd delivery2/src
./clear_all_data.sh
```

1. Ensure dependencies are installed and the server is running.
Navigate to the `delivery2/` folder and run the following commands:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd src/server
python3 server.py
```

2. Open another terminal, navigate to the `delivery2/` folder and run the following commands:
```bash
cd delivery2
source venv/bin/activate
```

4. Navigate to the test folder:
```bash
cd src/client/test_commands
```

5. Run a test script:
```bash
./{test_script_name}.sh
```

**Note**: You can verify that all changed and stored data is securely managed.

---

## API Documentation

The repository provides a set of commands categorized into **Local Commands**, **Anonymous API Commands**, **Authenticated API Commands**, and **Authorized API Commands**. Below is the detailed documentation for each command, its purpose, and the required permissions.

---

### **Local Commands**

These commands do not interact with the repository and are executed locally.

#### `rep_subject_credentials <password> <credentials file>`
- **Description**: Creates a key pair for a subject and stores it in a secure credentials file.  
- **Details**:  
  - The key pair is generated using **ECC (Elliptic Curve Cryptography)**.  
  - The private key is encrypted with the provided password.  
- **Example**:
  ```bash
  ./rep_subject_credentials mypassword user1_cred_file
  ```

#### `rep_decrypt_file <encrypted file> <encryption metadata>`
- **Description**: Decrypts an encrypted file using its metadata and performs integrity control.  
- **Output**: The decrypted file contents are sent to `stdout`.  
- **Example**:
  ```bash
  ./rep_decrypt_file encrypted_file user1_org1/doc1
  ```

---

### **Anonymous API Commands**

These commands do not require a session or authentication.

#### `rep_create_org <organization> <username> <name> <email> <public key file>`
- **Description**: Creates a new organization and defines its first subject.  
- **Example**:
  ```bash
  ./rep_create_org org1 user1 User1 user1@gmail.com user1_pub_key
  ```

#### `rep_list_orgs`
- **Description**: Lists all organizations defined in the repository.  
- **Example**:
  ```bash
  ./rep_list_orgs
  ```

#### `rep_create_session <organization> <username> <password> <credentials file> <session file>`
- **Description**: Creates a session for a user within an organization and stores the session context in a file.  
- **Example**:
  ```bash
  ./rep_create_session org1 user1 mypassword user1_cred_file user1_session
  ```

#### `rep_get_file <file handle> [file]`
- **Description**: Downloads a file using its handle.  
- **Details**:
  - If `[file]` is provided, the file contents are saved to the specified location.
  - If `[file]` is omitted, the contents are written to `stdout`.  
- **Example**:
  ```bash
  ./rep_get_file 123abc encrypted_file
  ```

---

### **Authenticated API Commands**

These commands require a session for execution.

#### `rep_assume_role <session file> <role>`
- **Description**: Assigns the specified role to the session.  
- **Example**:
  ```bash
  ./rep_assume_role user1_session Manager
  ```

#### `rep_drop_role <session file> <role>`
- **Description**: Removes the specified role from the session.  
- **Example**:
  ```bash
  ./rep_drop_role user1_session Manager
  ```

#### `rep_list_roles <session file>`
- **Description**: Lists all roles currently associated with the session.  
- **Example**:
  ```bash
  ./rep_list_roles user1_session
  ```

#### `rep_list_subjects <session file> [username]`
- **Description**: Lists all subjects in the organization.  
- **Details**:
  - If `[username]` is provided, only the specified subject’s details are shown.  
- **Example**:
  ```bash
  ./rep_list_subjects user1_session
  ```

#### `rep_list_role_subjects <session file> <role>`
- **Description**: Lists all subjects associated with a specific role in the organization.  
- **Example**:
  ```bash
  ./rep_list_role_subjects user1_session Manager
  ```

#### `rep_list_subject_roles <session file> <username>`
- **Description**: Lists all roles assigned to a specific subject in the organization.  
- **Example**:
  ```bash
  ./rep_list_subject_roles user1_session user2
  ```

#### `rep_list_role_permissions <session file> <role>`
- **Description**: Lists all permissions assigned to a specific role in the organization.  
- **Example**:
  ```bash
  ./rep_list_role_permissions user1_session Manager
  ```

#### `rep_list_permission_roles <session file> <permission>`
- **Description**: Lists all roles associated with a specific permission in the organization.  
- **Example**:
  ```bash
  ./rep_list_permission_roles user1_session DOC_READ
  ```

#### `rep_list_docs <session file> [-s username] [-d nt/ot/et date]`
- **Description**: Lists all documents in the organization.  
- **Details**:
  - Filters can be applied:
    - `-s username`: Filter by creator.
    - `-d nt/ot/et date`: Filter by date (newer than, older than, equal to).  
- **Example**:
  ```bash
  ./rep_list_docs user1_session -s user2 -d nt 01-01-2025
  ```

---

### **Authorized API Commands**

These commands require a session and specific permissions for execution.

#### `rep_add_subject <session file> <username> <name> <email> <credentials file>`
- **Description**: Adds a new subject to the organization.  
- **Permission**: **SUBJECT_NEW**  
- **Example**:
  ```bash
  ./rep_add_subject user1_session user2 User2 user2@gmail.com user2_cred_file
  ```

#### `rep_suspend_subject <session file> <username>`
#### `rep_activate_subject <session file> <username>`
- **Description**: Changes the status of a subject in the organization.  
- **Permissions**:
  - **SUBJECT_DOWN** (suspend)
  - **SUBJECT_UP** (activate)  
- **Example**:
  ```bash
  ./rep_suspend_subject user1_session user2
  ```

#### `rep_add_role <session file> <role>`
- **Description**: Adds a new role to the organization.  
- **Permission**: **ROLE_NEW**  
- **Example**:
  ```bash
  ./rep_add_role user1_session Developer
  ```

#### `rep_suspend_role <session file> <role>`
#### `rep_reactivate_role <session file> <role>`
- **Description**: Changes the status of a role in the organization.  
- **Permissions**:
  - **ROLE_DOWN** (suspend)
  - **ROLE_UP** (reactivate)  
- **Example**:
  ```bash
  ./rep_suspend_role user1_session Developer
  ```

#### `rep_add_permission <session file> <role> <username>`
#### `rep_remove_permission <session file> <role> <username>`
#### `rep_add_permission <session file> <role> <permission>`
#### `rep_remove_permission <session file> <role> <permission>`
- **Description**: Modifies the permissions or subject associations of a role.  
- **Permission**: **ROLE_MOD**  
- **Example**:
  ```bash
  ./rep_add_permission user1_session Manager DOC_READ
  ```

#### `rep_add_doc <session file> <document name> <file>`
- **Description**: Adds a document to the organization.  
- **Permission**: **DOC_NEW**  
- **Example**:
  ```bash
  ./rep_add_doc user1_session doc1 file1.txt
  ```

#### `rep_get_doc_metadata <session file> <document name>`
- **Description**: Fetches the metadata of a document.  
- **Permission**: **DOC_READ**  
- **Example**:
  ```bash
  ./rep_get_doc_metadata user1_session doc1
  ```

#### `rep_get_doc_file <session file> <document name> [file]`
- **Description**: Fetches and decrypts a document’s file.  
- **Permission**: **DOC_READ**  
- **Example**:
  ```bash
  ./rep_get_doc_file user1_session doc1 myfile.txt
  ```

#### `rep_delete_doc <session file> <document name>`
- **Description**: Deletes a document by clearing its file handle.  
- **Permission**: **DOC_DELETE**  
- **Example**:
  ```bash
  ./rep_delete_doc user1_session doc1
  ```

#### `rep_acl_doc <session file> <document name> [+/-] <role> <permission>`
- **Description**: Modifies a document’s ACL by adding (`+`) or removing (`-`) permissions for a role.  
- **Permission**: **DOC_ACL**  
- **Example**:
  ```bash
  ./rep_acl_doc user1_session doc1 + Manager DOC_READ
  ```

---

## Bookmarks

**GitHub Repository (private | source of the project)**  
- [SIO Project - Secure Repository](https://github.com/detiuaveiro/sio-2425-project-sio_112981_113384_114514)

---

## Team

| <div align="center"><a href="https://github.com/tomasf18"><img src="https://avatars.githubusercontent.com/u/122024767?v=4" width="150px;" alt="Tomás Santos"/></a><br/><strong>Tomás Santos</strong></div> | <div align="center"><a href="https://github.com/DaniloMicael"><img src="https://avatars.githubusercontent.com/u/115811245?v=4" width="150px;" alt="Danilo Silva"/></a><br/><strong>Danilo Silva</strong></div> | <div align="center"><a href="https://github.com/Affapple"><img src="https://avatars.githubusercontent.com/u/65315165?v=4" width="150px;" alt="João Gaspar"/></a><br/><strong>João Gaspar</strong></div> |
| --- | --- | --- |
