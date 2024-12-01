from sqlalchemy import func
from models.database_orm import Document
from datetime import datetime
from .BaseDAO import BaseDAO
from .SessionDAO import SessionDAO
from sqlalchemy.exc import IntegrityError

from .RestrictedMetadataDAO import RestrictedMetadataDAO
from .KeyStoreDAO import KeyStoreDAO
from .RoleDAO import RoleDAO
from models.database_orm import DocumentACL, RestrictedMetadata
from utils.file_operations import write_file
import hashlib
import os


class DocumentDAO(BaseDAO):
    """DAO for managing Document entities."""

    def create(self, document_handle: str, name: str, creation_date: datetime, file_handle: str, creator_username: str, org_name: str) -> Document:
        """ Create a new Document entry. """
        try:
            new_document = Document(
                document_handle=document_handle,
                name=name,
                create_date=creation_date,
                file_handle=file_handle,
                creator_username=creator_username,
                org_name=org_name
            )
            self.session.add(new_document)
            self.session.commit()
            return new_document
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Document '{name}' already exists.")
        
        
    def create_document(self, name: str, session_id: str, encrypted_data: bytes, alg: str, key: str, iv: str) -> Document:
        """Create a new document, its ACL, and metadata, and store the encrypted file."""

        try:
            # Step 1: Obtain the session details
            session_dao = SessionDAO(self.session)
            key_store_dao = KeyStoreDAO(self.session)
            document_dao = DocumentDAO(self.session)
            restricted_metadata_dao = RestrictedMetadataDAO(self.session)
            session = session_dao.get_by_id(session_id)
            creator = session.subject
            organization = session.organization

            if not organization:
                raise ValueError("Session is not associated with any organization.")

            # Step 2: Generate creation date
            creation_date = datetime.now()

            # Step 3: Generate the document handle and file handle
            data_digest = hashlib.sha256(encrypted_data).hexdigest()
            document_handle = data_digest
            file_handle = f"{organization.name}_{data_digest}"
            file_path = os.path.join("data", organization.name, file_handle)

            # Step 4: Store the data of the encrypted document file in a system file
            write_file(file_path, encrypted_data)

            # Step 5: Create the Document entity
            document = document_dao.create(document_handle, name, creation_date, file_handle, creator.username, organization.name)

            # Step 6: Create the DocumentACL and link it to the Manager role of the organization
            role_dao = RoleDAO(self.session)
            manager_role = role_dao.get_by_name_and_acl_id("Manager", organization.acl.id)
            if not manager_role:
                raise ValueError("Manager role not found for the organization.")

            document_acl = DocumentACL(document=document)
            document_acl.roles.append(manager_role)
            self.session.add(document_acl)

            # Step 7: Create the RestrictedMetadata entity
            algorithm, mode = alg.split("-")
            
            print("DECRYPTED METADATA KEY: ", key)
            encrypted_metadata_key, iv_encrypted_key = key_store_dao.create(key, "symmetric")
            print("ENCRYPTED METADATA KEY: ", encrypted_metadata_key.key)

            metadata = restricted_metadata_dao.create(
                document=document, 
                algorithm=algorithm, 
                mode=mode, 
                encrypted_metadata_key_id=encrypted_metadata_key.id,    # Store the key encrypted (used to encrypt the document file)
                iv=iv,                                                  # Store the IV used to encrypt the document file
                iv_encrypted_key=iv_encrypted_key                       # Store the IV used to encrypt the metadata key
            )

            # Commit all changes
            self.session.commit()

            print(f"Document '{name}' created successfully for organization '{organization.name}'.")
            return document

        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the document or its associated entities.")


    def get_encrypted_metadata_key(self, document_id: int) -> bytes:
        """
        Retrieve the encrypted restricted_metadata key.
        """
        restricted_metadata = self.session.query(RestrictedMetadata).filter_by(document_id=document_id).first()
        if not restricted_metadata:
            raise ValueError(f"Session with ID '{document_id}' does not exist.")
        return restricted_metadata.key.key
    
    
    def get_decrypted_metadata_key(self, document_id: int) -> str:
        """
        Retrieve the decrypted restricted_metadata key. 
        """
        restricted_metadata = self.session.query(RestrictedMetadata).filter_by(document_id=document_id).first()
        if not restricted_metadata:
            raise ValueError(f"Session with ID '{document_id}' does not exist.")
        encrypted_key = self.get_encrypted_metadata_key(document_id)
        iv = restricted_metadata.iv_encrypted_key
        return self.decrypt_metadata_key(encrypted_key, iv)
        
        
        
        
        
        
        
        
        
        
        

    def get(self, sessionId: int, creator_username: str = None, date_filter: str = None, date: datetime = None) -> list[Document]:
        """
        Fetches documents based on the organization, optional creator, and date filter.

        :param sessionId: ID of the session.
        :param creator_username: (Optional) Username of the creator to filter by.
        :param date_filter: (Optional) 'lt', 'gt', or 'eq' for filtering by date.
        :param date: (Optional) Date for filtering.
        :return: List of matching Document objects.
        :raises ValueError: If the session is invalid or date_filter is invalid.
        """
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        if not session:
            raise ValueError(f"Session with ID {sessionId} not found.")
        organization_name = session.organization_name
        
        query = self.session.query(Document).filter(Document.org_name == organization_name)

        if creator_username:
            query = query.filter(Document.creator_username == creator_username)

        if date and date_filter:
            if date_filter == "nt":
                query = query.filter(Document.create_date > date)
            elif date_filter == "ot":
                query = query.filter(Document.create_date < date)
            elif date_filter == "et":
                query = query.filter(func.date(Document.create_date) == date)

        return query.all()
    
    def get_metadata(self, sessionId: int, document_name: str) -> Document:
        """
        Fetches metadata for a document.

        :param sessionId: ID of the session.
        :param document_name: Name of the document.
        :return: Document object.
        :raises ValueError: If the session is invalid or the document is not found.
        """
        # Ensure session is valid
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        if not session:
            raise ValueError(f"Session with ID {sessionId} not found.")
        organization_name = session.organization_name

        # Fetch document metadata
        query = self.session.query(Document).filter(Document.org_name == organization_name, Document.name == document_name)
        document = query.first()

        if not document:
            raise ValueError(f"Document '{document_name}' not found in organization '{organization_name}'.")
        
        return document
    
    def delete(self, sessionId: int, document_name: str) -> str:
        """
        Clears the file_handle in the metadata of a document with a given name
        in the organization associated with the current session. Returns the
        file_handle that was cleared.

        :param sessionId: ID of the session.
        :param document_name: Name of the document.
        :return: The cleared file_handle.
        :raises ValueError: If the session or document is invalid or the file_handle is already None.
        """
        # Fetch document metadata
        document = self.get_metadata(sessionId, document_name)

        # Check if file_handle is already None
        if document.file_handle is None:
            raise ValueError(f"Document '{document_name}' already has no file handle.")

        # Clear file_handle
        ceasing_file_handle = document.file_handle
        document.file_handle = None
        
        # Assign deleter
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        document.deleter_username = session.subject_username
        
        self.session.commit()

        return ceasing_file_handle