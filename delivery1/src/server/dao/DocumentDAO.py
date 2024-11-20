import os
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from models.orm import Document, DocumentACL, RestrictedMetadata
from .BaseDAO import BaseDAO
# from .SessionDAO import SessionDAO
from .OrganizationDAO import SessionDAO
from .RoleDAO import RoleDAO

class DocumentDAO(BaseDAO):
    """DAO for managing Document entities."""

    def create(self, name: str, session_id: str, encrypted_data: bytes, alg: str, key: bytes, iv: bytes) -> Document:
        """Create a new document, its ACL, and metadata, and store the encrypted file."""

        try:
            # Step 1: Obtain the session details
            session_dao = SessionDAO(self.session)
            session = session_dao.get_by_id(session_id)
            creator = session.subject
            organization = session.organization

            if not organization:
                raise ValueError("Session is not associated with any organization.")

            # Step 2: Generate creation date
            creation_date = datetime.now()

            # Step 3: Create a file handle for the encrypted file
            file_handle = f"{organization.name}/{creation_date.strftime('%Y%m%d%H%M%S')}_{name}.enc"
            file_path = os.path.join("data", file_handle)

            # Step 4: Encrypt the data and store it in a file
            self._store_encrypted_data(file_path, encrypted_data, key, iv, alg, mode)

            # Step 5: Create the Document entity
            document = Document(
                name=name,
                document_handle=file_handle,
                create_date=creation_date,
                creator_username=creator.username,
                org_name=organization.name
            )
            self.session.add(document)

            # Step 6: Create the DocumentACL and link it to the Manager role of the organization
            role_dao = RoleDAO(self.session)
            manager_role = role_dao.get_role_by_name_and_org("Manager", organization.name)
            if not manager_role:
                raise ValueError("Manager role not found for the organization.")

            document_acl = DocumentACL(document=document)
            document_acl.roles.append(manager_role)
            self.session.add(document_acl)

            # Step 7: Create the RestrictedMetadata entity
            metadata = RestrictedMetadata(
                document=document,
                alg=alg,
                key=self._encrypt_metadata(key),
                mode=mode,
                iv=self._encrypt_metadata(iv) if iv else None
            )
            self.session.add(metadata)

            # Commit all changes
            self.session.commit()

            print(f"Document '{name}' created successfully for organization '{organization.name}'.")
            return document

        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the document or its associated entities.")

    def _store_encrypted_data(self, file_path: str, data: bytes, key: bytes, iv: bytes, alg: str, mode: str):
        """Encrypt the data using AES256 and CBC, then store it in a file."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self._pad_data(data)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Write the encrypted data to the file
        with open(file_path, "wb") as f:
            f.write(encrypted_data)

    def _pad_data(self, data: bytes) -> bytes:
        """Pad data to be a multiple of AES block size (16 bytes)."""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    def _encrypt_metadata(self, metadata: bytes) -> str:
        """Encrypt metadata (like keys or IVs) for secure storage in the database."""
        # In this example, metadata is stored as a base64-encoded string.
        # Replace with actual encryption logic if needed.
        return b64encode(metadata).decode("utf-8")
