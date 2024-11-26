# SIO Project

## Our Team 

| <div align="center"><a href="https://github.com/tomasf18"><img src="https://avatars.githubusercontent.com/u/122024767?v=4" width="150px;" alt="Tomás Santos"/></a><br/><strong>Tomás Santos</strong><br/>112981</div> | <div align="center"><a href="https://github.com/DaniloMicael"><img src="https://avatars.githubusercontent.com/u/115811245?v=4" width="150px;" alt="Danilo Silva"/></a><br/><strong>Danilo Silva</strong><br/>113384</div> | <div align="center"><a href="https://github.com/Affapple"><img src="https://avatars.githubusercontent.com/u/65315165?v=4" width="150px;" alt="João Gaspar"/></a><br/><strong>João Gaspar</strong><br/>114514</div> |
| --- | --- | --- |

---

## 📂 Folder Structure

Abaixo está a estrutura de pastas do projeto, com descrições básicas de cada diretório e arquivo principal.

```plaintext
.
├── docs/                   
├── src/                 
│   ├── client/
│   │   ├── apiConsumer/
│   │   ├── constants/
│   │   ├── tests/
│   │   ├── utils/
│   │   ├── client.py
│   │   ├── rep_create_org
│   │   ├── rep_list_org
│   │   └── ...
│   └── server/
│       ├── controllers/
│       ├── dao/
│       ├── models/
│       ├── repkeys/
│       ├── services/
│       ├── utils/
│       ├── server.py
├── .env                
├── .gitignore                
├── requirements.txt        
└── README.md          
```

---

## API Documentation


### Sessions

- **POST /sessions**  
  *Create a new session*  
  (Anonymous API)  
  Allows creating a new session.

    #### /roles
    - **GET /roles**  
      *List assumed roles*  
      (Authenticated API)  
      Lists the roles currently assumed by the authenticated user.

    - **/{role} PUT /roles/{role}**  
      *Assume session Roles: Update Session File*  
      (Authenticated API)  
      Updates the session file to assume a specified role.

    - **/{role} DELETE /roles/{role}**  
      *Release session Roles: Update Session File*  
      (Authenticated API)  
      Updates the session file to release a specified role.

---

### Organizations

- **POST /organizations**  
  *Create a new Organization*  
  (Anonymous API)  
  Allows creating a new organization.

- **GET /organizations**  
  *List Organizations*  
  (Anonymous API)  
  Lists all organizations.

- **/{organization_name}**  
  - **/subjects GET ?role={role}**  
    *List Subjects (with a Role)*  
    (Authenticated API)  
    Lists subjects within the organization filtered by a role.
  
  - **/subjects POST**  
    *Add a Subject to Organization*  
    (Authorized API)  
    Adds a new subject to the organization.

    #### /{subjectId}
    - **GET /{subjectId}**  
      *List Subject*  
      (Authenticated API)  
      Retrieve details of a specific subject.

    - **PUT /{subjectId}**  
      *Activate a subject: Update status of subject*  
      (Authorized API)  
      Activates a subject within the organization.

    - **DELETE /{subjectId}**  
      *Suspend a subject: Update status of subject*  
      (Authorized API)  
      Suspends a subject within the organization.

    #### /roles
    - **GET ?permission={permission}**  
      *List Organization Roles (that have a Permission)*  
      (Authenticated API)  
      Lists the roles in the organization filtered by a specific permission.

    - **POST /roles**  
      *Add a new Role*  
      (Authorized API)  
      Adds a new role to the organization.

    #### /{role}
    - **PUT /{role}**  
      *Activate a Role*  
      (Authorized API)  
      Activates a specified role within the organization.

    - **DELETE /{role}**  
      *Reactivate a Role*  
      (Authorized API)  
      Reactivates a specified role within the organization.

    #### /permissions
    - **GET /permissions**  
      *Get Role Permission*  
      (Authenticated API)  
      Lists the permissions associated with a role.

    - **PUT /permissions**  
      *Add Permission to Role*  
      (Authorized API)  
      Adds a specific permission to a role.

    - **DELETE /permissions**  
      *Remove Permission from Role*  
      (Authorized API)  
      Removes a specific permission from a role.

---

### Documents

- **GET /documents**  
  *Query Organization Documents*  
  (Authenticated API)  
  Allows querying documents in the organization based on filters like `minDate`, `maxDate`, and `creator`.

- **POST /documents**  
  *Add a Document*  
  (Authorized API)  
  Allows adding a new document to the organization.

- **/{document_name}**
  - **GET /{document_name}**  
    *Get document Metadata*  
    (Authorized API)  
    Retrieves metadata for a specific document.

  - **DELETE /{document_name}**  
    *Delete a document*  
    (Authorized API)  
    Deletes a specific document from the organization.

  #### /file
  - **GET /file**  
    *Get file of a document*  
    (Authorized API)  
    Downloads the file associated with a document.

  #### /ACL
  - **PUT /ACL**  
    *Update document ACL*  
    (Authorized API)  
    Updates the Access Control List (ACL) of a document.

  - **DELETE /ACL**  
    *Update document ACL*  
    (Authorized API)  
    Removes or updates the ACL of a document.

---

#### Files

- **/{file_handle} GET /files/{file_handle}**  
  *Download File*  
  (Anonymous API)  
  Allows downloading a file using its handle.

---

### Authentication & Authorization

- **Authenticated API**: Requires the user to be authenticated with a valid session.
- **Authorized API**: Requires the user to have the appropriate permissions to perform the requested action.
- **Anonymous API**: Accessible without authentication, but some actions may still require minimal input or constraints.

---

### Error Handling

- **400 Bad Request**: The request is malformed or missing required parameters.
- **401 Unauthorized**: Authentication is required to access the resource.
- **403 Forbidden**: The authenticated user does not have permission to access the resource.
- **404 Not Found**: The requested resource could not be found.

---


## Commands Implemented in Delivery1

### Local Commands

- rep_subject_credentials

- rep_decrypt_file

**Note:** to generate the key pair we use the ECC with a given password to encrypt the private key, and to decrypt a file we use the algorithm and mode provided by the metadata file (currently we use AES256 CBC to encrypt)

### Anonymous API Commands

- rep_create_org

- rep_list_org

- rep_create_session

- rep_get_file

**Note:** The `rep_create_session` command creates a session for a user within an organization and stores the session details in a file. It involves the following steps:

1. **Load Private Key**  
   The private key is securely read from the specified `credentials_file` using the provided password. If an error occurs, the process stops.

2. **Prepare Session Data**  
   A data object containing the `organization` and `username` is prepared to be sent to the server. 

3. **Key Exchange and Session Creation**  
   The `exchangeKeys` method performs an Elliptic Curve Diffie-Hellman (ECDH) handshake with the server to derive a shared key (`derivedKey`) and retrieve session details:
   - A public key is generated and sent to the server.
   - The request includes a signed digest for validation.
   - The server responds with its own public key and session information.
   - The response also includes a signed digest for validation
   - The shared key is computed from the server's public key and the client private key

4. **Save Session Context**  
   The session file includes:

   - `Session Key`: Used to encrypt and authenticate communication.
   - `Nonce`: A unique random value generated for each message inside a session. It ensures each message have with a unique context, making all messages unique exchange.
   - `Counter`: An incrementing value used to ensure message order during communication. It prevents replay attacks by rejecting messages with counters lower than expected, maintaining the integrity of the message sequence.

5. **Completion**  
   If successful, the session ID is printed, and the program exits with a success code.

### Authenticated API Commands

- rep_list_subjects

- rep_list_docs

### Authorized API Commands

- rep_add_subject

- rep_suspend_subject

- rep_activate_subject

- rep_add_doc

- rep_get_doc_metadata

- rep_get_doc_file

- rep_delete_doc

**Note:** the `rep_add_doc` command involves encrypting the file contents, preparing the necessary data (including session-related fields like `nonce` and `counter`), and sending the request to the server to store the document. These are the key points:

1. **Session File Handling:**
   - The session file is read, and the session ID and session key are extracted from it. This session key is used for encrypting and decrypting communications with the server.

2. **File Handling and Encryption:**
   - The file contents are read, and then AES encryption in CBC mode is used to encrypt the contents. A random AES key and initialization vector (IV) are generated for the encryption process.
   - Both the encrypted file and the IV are base64-encoded before being included in the request to ensure they can be safely transmitted.

3. **API Request:**
   - The command sends a `POST` request to the endpoint `/organizations/{organization_name}/documents` with the prepared data, including the encrypted document and associated metadata (like encryption algorithm, key, and IV).
   - The session ID and session key are also included in the request to authenticate and secure the communication.

4. **Error Handling:**
   - If reading the session file or the document file fails, or if the server responds with an error, the program logs the error and exits with an appropriate return code.

5. **Result Handling:**
   - Upon successful document upload, the server’s response is printed, indicating that the document was successfully added to the organization.

6. **send_request** function:
   - The `send_request` function is responsible for preparing and sending the encrypted request to the server. It handles the encryption of the request body and decrypts the response from the server. It uses the session key to generate both the message key (for encrypting the payload) and the MAC key (for message authentication).
  
7. **Server Side (`create_organization_document`):
   - On the server side, the document is received and decrypted using the session key. The document is then stored securely in the database, and the session's `nonce` and `counter` are updated.
   - The result is encrypted and sent back to the client, ensuring that all sensitive information remains secure during transmission.


## Encryption Image
Diagrams of message exchange between client-server

![Session Messages Diagram](./docs/SessionMessagesDiagram.pdf)

## Run the server

-- To start the Flask server go to the `delivery2/src/server` folder and run the following command:

```bash
python3 server.py
```

**Note:** then it is possible to run command by command, in the `/client` folder using, for example, `./rep_create_orgs org_name username Name email@gmail.com pub_key.pem`, or run the tests in the `client/tests/` folder

## Tests

- To run the tests go to `delivery2/src/client`;
- First, add the following variables to the terminal session:

```bash
export REP_ADDRESS=http://localhost:5000/
export REP_PUB_KEY=./rep_pub_key.pem
``` 
- Then, run the following command:

```bash
pytest tests/test.py -v
```

PS.: ENSURE THE PATH TO DATABASE!
PS..: if you want to rerun the tests, you need to RESTART the server, so that the database is clean again.