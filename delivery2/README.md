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

### Anonymous API Commands

### Authenticated API Commands

### Authorized API Commands

---

## <i class="fa-solid fa-key"></i> Encryption Documentation
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