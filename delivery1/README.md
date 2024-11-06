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
        - [Keys used in docments encryption](#keys-used-in-docments-encryption)
    - [Organizations](#organizations)
        - [Roles](#roles)
    - [Subjects](#subjects)
        - [Subject attributes](#subject-attributes)
    - [Sessions](#sessions)
        - [Session attacks](#session-attacks)
    - [Roles](#roles)
        - [Permissions](#permissions)

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

### Keys used in docments encryption
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






