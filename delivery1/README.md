endpoints -> The repo service must use an interface compatible withe the commands provided

# Table of contents
1. [High-level functionalities](#high-level-functionalities)
    - [Files](#files)
    - [Document Metadata](#document-metadata)
        - [Public metadata](#public-metadata)
            - [ACL permissions](#acl-permissions)
        - [Private metadata](#private-metadata)
    - [How to store documents](#how-to-store-documents)
        - [Metadata](#metadata)
        - [Files](#files-1)
        - [Keys used in documents encryption](#keys-used-in-documents-encryption)
    - [Organizations](#organizations)
        - [Roles](#roles)
    - [Subjects](#subjects)
        - [Subject attributes](#subject-attributes)
    - [Sessions](#sessions)
        - [Session attacks](#session-attacks)
    - [Roles](#roles)
        - [Permissions](#permissions)
2. [Fundamental Repository operations](#fundamental-repository-operations)
    - [Upload a new document (POST /api/documents)](#upload-a-new-document-post-apidocuments)
    - [Download a document (GET /api/documents/{document_handle})](#download-a-document-get-apidocumentsdocument_handle)
    - [Delete a document (DELETE /api/documents/{document_handle})](#delete-a-document-delete-apidocumentsdocument_handle)
3. [Mandatory API](#mandatory-api)
    - [Anonymous API](#anonymous-api)
    - [Authenticated API](#authenticated-api)
    - [Authorized API](#authorized-api)
4. [Security guidelines](#security-guidelines)
5. [Implementation guidelines](#implementation-guidelines)
6. [Commands](#commands)
    - [Local commands](#local-commands)
    - [Commands that use the anonymous API](#commands-that-use-the-anonymous-api)
    - [Commands that use the authenticated API](#commands-that-use-the-authenticated-api)
    - [Commands that use the authorized API](#commands-that-use-the-authorized-api)


# High-level functionalities

Document
    |-> Metadata    (auxiliary information about the file)
    |-> File        (the fundamental information container)

## Files
-> Files provided by the clients
-> Stored encrypted

## Document Metadata
- Stored in plaintext, publiccly available
- **exception**: the items relatively to the file encryption *are not public*

### Public metadata
- **document_handle**: unique identifier
- **name**
- **create_date**
- **creator**
- **file_handle**: unique identifier of the encrypted file, but as it can be deleted, it is not a permanent reference
- **deleter**
- **acl**

#### ACL permissions
- **DOC_ACL**: role that can add or remove access rights (permissions) for other roles; at least one role must keep this right for each document
- **DOC_READ**: read the encrypted file contents and to decrypt them upon recovering the encryption key
- **DOC_DELETE**: does not destroy information, it just clears the `file_handle`, the file’s contents remain available to those that know their file_handle and encryption key; metadata of deleted documents must register the subject that deleted it using the `deleter` field

**Note:** When a "file" is deleted, only its `file_handle` is removed, the file's contents remain available to those that know their `file_handle` and encryption key (but the document doesn't point to a file anymore)


### Private metadata
- **alg**: procedures used to protect the file (with encryption and integrity control)
- **key**: Key used to encrypt the file


## How to store documents

### Metadata
- physical storage (e.g. a database or a file system)

### Files
- stored apart from the metadata (different physical storage)

### Keys used in documents encryption
- stored encrypted by the Repository

**Note:** **Files** can be **publicly accessible** given their `file_handle`; document’s **metadata** must have a **controlled access**


## Organizations
- Documents are associated to organizations
- The Repository maintains a *list of known organizations*
- Each organization has its own list of documents
- Organizations and the public metadata of their documents can be universally listed

- Each organization has an ACL for governing who manages it
- When an organization is created, it is **the subject that created it that has full control** over the organization’s ACL (Manager)

**!!!!!**
**Doubt:** The initial subject that creates the organization is the manager, but he creates it without an authentication**???**
**!!!!!**

**Subject** -> a user 

### Roles
- `ROLE_ACL`: Modify the ACL
- `SUBJECT_NEW`: Allow a role to add a new subject to the organization
- `SUBJECT_DOWN`: Allow a role to suspend the association of a subject with the organization, **while not removing its profile**
- `SUBJECT_UP`: Allow a role to put an end on a subject’s suspension
- `DOC_NEW`: Allow a role to add a new document to the organization’s repository

**Note:** **Any** subject from an organization *can list its subjects* and *if they are suspended* (down) *or active* (up).

## Subjects
- People or applications that interact with the Repository
- All subjects hold **one or more** key pairs; their public keys are available in the Repository
- Within the process of association with an organization, they choose an existing or new public key 

### Subject attributes
- **username**
- **full_name**
- **email**
- **public_key**


## Sessions
- Are used for subjects to interact with the Repository
- A session is a security context between the Repository and a subject
- Each session must have 
    - **an identifier**: used to identify interactions within the session
    - **one or more keys**: data items used for securing the interactions
- A session always implicitly **refers to one specific Repository** organization. 
- **`A session is created upon a login operation in that organization, performed with the credentials that the organization maintains about the subject`**

**Doubt:** Is the login implemente within the Repository or is it a separate service that the Repository uses to authenticate the subjects? (ex.: detiuaveiro, IDP)

- A subject can have simultaneous sessions with different organizations in the Repository

**Repository** -> the service that provides the functionalities described above

- **Session keys** must be used to enforce the **confidentiality** (when necessary) and the **integrity** (correctness and freshness) of messages exchanged during a session; different keys can be used for the different protections, if considerado necessary.

### Session attacks
- **Eavesdropping**: Contents must be kept confidential
- **Impersonation**: Authentication of sessions (login) and interactions should be implemented
- **Manipulation**: There must be integrity controls
- **Replay**: The software must be able to detect out of order or past messages

**Doubt**: What means replay? Is it when someone stores a packet to send it later? 

**Sessions have a lifetime** defined by the Repository; **should be deleted** upon a period of inactivity.


**Note:** This is exacly like on github, where we login as a detiuaveiro student and we can access the repositories of detiuaveiro, but, for example, as a student I cannot create or delete repositories, only the teacher_role can do that. Also, the session is terminated when we stay a long time without doing anything, or when we logout


## Roles
- Subjects are associated with roles (these state the permissions of the subject within the organization)
- **ACLs must link access rights to roles, and not to subjects** (groups of subjects)
- Subjects have no default role upon logging in into a session
- Can have multiple roles in a session
- Can also release a role during the session, so usa as roles que precisa (imagina que so queres ler os ficheiros, e nao queres dar delete sem querer)
- The set of roles associated to each session is stored by the Repository (in the context of each active session)
- Each organization can have a variable set of roles
- Each role has:
    - a **name**
    - a **set of permissions**
    - a **list of subjects** that have that role
- It is possible, for **any** subject of an organization **to query**, in an organization, which:
    - users have a role and which roles a subject can assume
    - roles have a permission and which permissions a role has

### Permissions
- **ROLE_NEW**: Allow a role to add a new role to **the organization that the requesting subject belongs to**.
- **ROLE_DOWN**: Allow a role to suspend a role from being assumed by subjects of an organization.
- **ROLE_UP**: Allow a role to put an end on a role’s suspension.
- **ROLE_MOD**: Allow a role to add/remove a subject to/from an existing role or add/remove a permission to/from an existing role.

*The set of roles is open*, but **the following role must exist**:
- **Managers**: This is, by default, the role that has the full set of permissions on an organization.
- The relationship between the initial subject and this role can change over time
- Managers **can never be suspended**.
- Managers role **must have at any time an active subject** (not suspended).


# Fundamental Repository operations

## Upload a new document (POST /api/documents)
1. A subject logs-in to the Repository (within one organization) and selects one of its roles with a permission to **add a new document**
2. A random encryption key (file key) is generated by the uploader, and is used to encrypt the document’s file. 
3. The subject then uploads the document with:
    - the encrypted file;
    - some of its metadata: 
        - **name**
        - **file handle**
        - **encryption key**
        - **cryptographic descriptions**
        - **ACL**

The `file_handle` should be **a digest** (cryptographic hash) **of the original file contents**, a value that the Repository must verify.
(Maskes sene, since if two digests are equal, the files are equal, so the files are the same)

## Download a document (GET /api/documents/{document_handle})
1. A subject logs-in in to the Repository (within one organization)and selects one of its roles with a permission to **read a given document**. 
2. Then it gets confidentially the document’s metadata:
    - `file handle` 
    - encryption algorithms `alg` 
    - `encryption key` 
3. Fetches the encrypted file using the `file handle`
4. Decrypts it
5. Verifies if its contents are correct (using again the `file_handle`)

## Delete a document (DELETE /api/documents/{document_handle})
1. A subject logs-in in to the Repository (within one organization) and selects one of its roles with a permission to **delete a given document**. 
2. Then it deletes the document’s 
3. Receives, confidentially and for its own future record, the:
    - `file_handle` 
    - encryption algorithms `alg`  
    - `encryption key`


# Mandatory API

## Anonymous API

Formed by a set of endpoints that can be used **without a session**.

- Create organization (`POST /api/organizations`)
- List organizations (`GET /api/organizations`)
- Create session (`POST /api/sessions`)
- Download file *(note that for this you need to know the file handle)* (`GET /api/files/{file_handle}`)

## Authenticated API
Formed by a set of endpoints that **require a session, but not a role**.

- Assume session role (`POST /api/sessions/{session_id}/roles`)
- Release session role (`DELETE /api/sessions/{session_id}/roles`)
- List session roles (`GET /api/sessions/{session_id}/roles`)
- List subjects (of my organization) (`GET /api/subjects`)
- List roles (from my organization) (`GET /api/roles`)
- List the subjects in one of my organization’s roles (`GET /api/roles/{role_name}/subjects`)
- List the roles of one of my organization’s subjects (`GET /api/subjects/{subject_id}/roles`)
- List the permissions in one of my organization’s roles (`GET /api/roles/{role_name}/permissions`)
- List the roles that have a given permission (`GET /api/permissions/{permission_name}/roles`)
- List documents (with filtering options, such as dates or creators). (`GET /api/documents?filter=...`, filetering options are optional)

## Authorized API
Formed by a set of endpoints that **require a session and at least a role bound to it**.

- Add subject (`POST /api/subjects`)
- Change subject status (suspend/reactivate) (`PUT /api/subjects/{subject_id}`)
- Add role (`POST /api/roles`)
- Change role status (suspend/activate) (`PUT /api/roles/{role_name}`)
- Add/remove subject to role (`POST /api/roles/{role_name}/subjects`, `DELETE /api/roles/{role_name}/subjects/{subject_id}`)
- Add/remove permission to role (`POST /api/roles/{role_name}/permissions`, `DELETE /api/roles/{role_name}/permissions/{permission_name}`)
- Upload a document (`POST /api/documents`)
- Download a document metadata (`GET /api/documents/{document_handle}`)
- Delete a document (`DELETE /api/documents/{document_handle}`)
- Change document ACL (`PUT /api/documents/{document_handle}/acl`)


# Security guidelines
- The Repository must have a **well-known public key** that client applications can use **for confidentiality** and **source authentication**.
- This key must be used to **protect anonymous client-Repository interactions that require some security protection** (not all of them require).
- *Authenticated* and *authorized* APIs must **always** use **session keys** for adding **confidentiality** to sensitive items and add **integrity control** and **source authentication**.
- The Repository should use a **master key**, possibly *derived from a password* (**Key Derivation Functions ???**), to protect the **confidentiality** of **file’s keys**.

**Warning:** You **cannot** use any existing technology for the protection of communications, **such as SSL/TLS, SSH** or any other.


# Implementation guidelines

- For the **authentication of subjects**, use **elliptic cryptography (EC)** key pairs for subjects and for the Repository;
EC private keys can be very easily produced deterministically **from passwords** (**KDF???**).
  
- Implement one console application (**a command**) **for each API function**.

- Each command that produces a **useful persistent result** (e.g. a **session key** upon a login, a `file_handle` and a `file key` upon getting a document metadata, etc.) should be able to **save that into a state file**, in order to be used by other commands.
  
- **The exact command syntax is provided below** and must be respected to conduct evaluation tests;
All *commands should follow the UNIX semantics* of **returning 0 in case of success**, **a positive value in case of input errors**, and **a negative value in case of errors reported by the Repository**.

- Since **the Repository’s public key, stored in a file**, must be used in some commands, you can **use the environment variable REP_PUB_KEY** to indicate its path;
However, each command has the possibility to **override this default setting** using the **-k** file option.

- The **Internet address of the Repository** must be indicated in all the commands that interact with the Repository; 
You can use the environment variable **REP_ADDRESS** to indicate its **IP address and port number**;
However, each command has the possibility to **override this default setting** using the **-r IP:port** option.


# Commands

## Local commands

These work without any interaction with the Repository.

```bash
rep_subject_credentials <password> <credentials file>
```

- Does not interact with the Repository
- **Creates a key pair for a subject**
- We can:
    - **using `RSA`**: create a file with a private/public key pair, and encrypt the private component with the password
    - **using EXX**: use directly the password to generate a private key and store the public key in a file for verification 

---
```bash
rep_decrypt_file <encrypted file> <encryption metadata>
```

- **Sends to the stdout the contents of an encrypted file upon decryption (and integrity control)** with the encryption metadata, that must contain the algorithms used to encrypt its contents and the encryption key (so that the program, a.k.a. we, knows how to decrypt it)


## Commands that use the anonymous API

```bash
rep_create_org <organization> <username> <name> <email> <public key file>
```

- **Creates an organization in a Repository and defines its first subject (Manager)**

---
```bash
rep_list_orgs
```

- **Lists all organizations defined in a Repository**

---
```bash
rep_create_session <organization> <username> <password> <credentials file> <session file>
```

- **Creates a session** for a username belonging to an organization, **and stores the session context in a file**

---
```bash
rep_get_file <file handle> [file]
```

- **Downloads a file given its `handle`**.   
The **file contents** are **written to stdout** or to the **file referred** in the optional last argument


## Commands that use the authenticated API

All these commands use as **first parameter a file with the session key**.

```bash
rep_assume_role <session file> <role>
```

- **Requests the given role for the session**

---
```bash
rep_drop_role <session file> <role>
```

- **Releases the given role for the session**

---
```bash
rep_list_roles <session file> <role>
```

- **Lists the current session roles**

---
```bash
rep_list_subjects <session file> <session file> [username]
```

- **Lists the subjects of the organization `with which I have currently a session`*  
Should show the status of all the subjects (active or suspended)  
Accepts an extra command to show `[only one subject]`

---
```bash
rep_list_role_subjects <session file> <role>
```

- **Lists the subjects of a role of the organization `with which I have currently a session`**

---
```bash
rep_list_subject_roles <session file> <username>
```

- **Lists the roles of a subject of the organization `with which I have currently a session`**

---
```bash
rep_list_role_permissions <session file> <role>
```

- **Lists the permissions of a role of the organization `with which I have currently a session`**

---
```bash
rep_list_subject_roles <session file> <permission>
```

- **Lists the roles `of the organization with which I have currently a session` that have a given permission**  
Use the names previously referred for the permission rights.

---
```bash
rep_list_docs <session file> [-s username] [-d nt/ot/et date]
```

- **Lists the documents `of the organization with which I have currently a session`**  
Possibly `filtered` by a **subject that created them** and by a **date** (newer than, older than, equal to), expressed in the **DD-MM-YYYY format**


## Commands that use the authorized API

All these commands use as first parameter a file with the session key.  
**For that session, the subject must have added one or more roles.**  


```bash
rep_add_subject <session file> <username> <name> <email> <credentials file>
```

- **Adds a new subject to the `organization with which I have currently a session`**  
By default the subject is created in the active status.  
**Requires a `SUBJECT_NEW` permission!**

---
```bash
rep_suspend_subject <session file> <username>
rep_activate_subject <session file> <username>
```

- **Change the status of a subject in the `organization with which I have currently a session`**
**Require, respectively, a `SUBJECT_DOWN` and `SUBJECT_UP` permission!**

---
```bash
rep_add_role <session file> <role>
```

- **Adds a role to the `organization with which I have currently a session`**   
**This commands requires a `ROLE_NEW` permission!**

---
```bash
rep_suspend_role <session file> <role>
rep_reactivate_role <session file> <role>
```

- **Change the status of a role in the `organization with which I have currently a session`** 
**Require, respectively, a `ROLE_DOWN` and `ROLE_UP` permission!**

---
```bash
rep_add_permission <session file> <role> <username>
rep_remove_permission <session file> <role> <username>
rep_add_permission <session file> <role> <permission>
rep_remove_permission <session file> <role> <permission>
```

- **Change the properties of a role in the `organization with which I have currently a session`**, by:
    - adding a subject, 
    - removing a subject, 
    - adding a permission or removing a permission,     
respectively.       
Use the names previously referred for the permission rights.      
**Require a `ROLE_MOD` permission**   

---
```bash
rep_add_doc <session file> <document name> <file>
```

- **Adds a document with a given name to the `organization with which I have currently a session`**    
The document’s contents is provided as parameter with a file name.   
**Requires a `DOC_NEW` permission!**

---
```bash
rep_get_doc_metadata <session file> <document name>
```

- **Fetches the metadata of a document with a given name to the `organization with which I have currently a session`**   
The output of this command **is useful for getting the clear text contents** of a document’s file. 
**Requires a `DOC_READ` permission!**

---
```bash
rep_get_doc_file <session file> <document name> [file]
```

- Is a combination of `rep_get_doc_metadata` with `rep_get_file` and `rep_decrypt_file`.   
**The file contents are written to stdout or to the file referred in the optional last argument.**   
**Requires a `DOC_READ` permission!**

---
```bash
rep_delete_doc <session file> <document name>
```

- **Clears `file_handle` in the metadata of a document with a given name on the `organization with which I have currently a session`**   
The output of this command is the `file_handle` that ceased (deixou) to exist in the document’s metadata.  
**Requires a `DOC_DELETE` permission!**

---
```bash
rep_acl_doc <session file> <document name> [+/-] <role> <permission>
```

- **Changes the ACL of a document by adding (+) or removing (-) a permission for a given role**  
Use the names previously referred for the permission rights.  
**Requires a `DOC_ACL` permission!**

