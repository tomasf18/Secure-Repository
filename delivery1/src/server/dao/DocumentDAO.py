import os
import hashlib
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from models.orm import Document, DocumentACL, RestrictedMetadata
from .BaseDAO import BaseDAO
from .SessionDAO import SessionDAO
from .RoleDAO import RoleDAO


class DocumentDAO(BaseDAO):
    """DAO for managing Document entities."""

    # def create(self, name: str, session_id: str, encrypted_data: bytes, alg: str, key: bytes, iv: bytes) -> Document:
    #     """Create a new document, its ACL, and metadata, and store the encrypted file."""

    #     try:
    #         # Step 1: Obtain the session details
    #         session_dao = SessionDAO(self.session)
    #         session = session_dao.get_by_id(session_id)
    #         creator = session.subject
    #         organization = session.organization

    #         if not organization:
    #             raise ValueError("Session is not associated with any organization.")

    #         # Step 2: Generate creation date
    #         creation_date = datetime.now()

    #         # Step 3: Generate a digest for the encrypted data
    #         digest = hashlib.sha256(encrypted_data).hexdigest()
    #         document_handle = digest
    #         file_handle = f"{organization.name}_{digest}"
    #         file_path = os.path.join("data", file_handle)

    #         # Step 4: Encrypt the data and store it in a file
    #         self._store_encrypted_data(file_path, encrypted_data)

    #         # Step 5: Create the Document entity
    #         document = Document(
    #             document_handle=document_handle,
    #             name=name,
    #             create_date=creation_date,
    #             file_handle=file_handle,
    #             creator_username=creator.username,
    #             org_name=organization.name
    #         )
    #         self.session.add(document)

    #         # Step 6: Create the DocumentACL and link it to the Manager role of the organization
    #         role_dao = RoleDAO(self.session)
    #         manager_role = role_dao.get_role_by_name_and_org("Manager", organization.name)
    #         if not manager_role:
    #             raise ValueError("Manager role not found for the organization.")

    #         document_acl = DocumentACL(document=document)
    #         document_acl.roles.append(manager_role)
    #         self.session.add(document_acl)

    #         # Step 7: Create the RestrictedMetadata entity
    #         algorithm, mode = alg.split("-")
    #         metadata = RestrictedMetadata(
    #             document=document,
    #             alg=algorithm,
    #             mode=mode,
    #             key=key,
    #             iv=iv
    #         )
    #         self.session.add(metadata)

    #         # Commit all changes
    #         self.session.commit()

    #         print(f"Document '{name}' created successfully for organization '{organization.name}'.")
    #         return document

    #     except IntegrityError:
    #         self.session.rollback()
    #         raise ValueError("Error while creating the document or its associated entities.")

    # def _store_encrypted_data(self, file_path: str, data: bytes):
    #     # Ensure the directory exists
    #     os.makedirs(os.path.dirname(file_path), exist_ok=True)

    #     # Write the encrypted data to the file
    #     with open(file_path, "wb") as f:
    #         f.write(data)