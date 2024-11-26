import hashlib
import secrets
from .BaseDAO import BaseDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .RoleDAO import RoleDAO
from .OrganizationACLDAO import OrganizationACLDAO
from server.models.database_orm import Organization, Subject, OrganizationSubjects, Permission, Role, KeyStore, Session, DocumentACL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from server.models.database_orm import Document, RestrictedMetadata
from datetime import datetime
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import base64
from ..utils.cryptography import Cryptography

from dotenv import load_dotenv

load_dotenv()

class OrganizationDAO(BaseDAO):
    """DAO for managing Organization entities."""

    def create(self, org_name: str, subject_username: str, subject_full_name: str, subject_email: str, subject_pub_key: str) -> Organization:
        """Create a new organization with the subject as the creator and include their public key."""
        subject_dao = SubjectDAO(self.session)
        key_store_dao = KeyStoreDAO(self.session)
        organization_acl_dao = OrganizationACLDAO(self.session)
        role_dao = RoleDAO(self.session)
        
        try:
            # Step 1: Create an Organization
            new_org = Organization(name=org_name)
            self.session.add(new_org)
            
            # Step 2: Retrieve or create the Subject
            try:
                subject = subject_dao.get_by_username(subject_username)
            except ValueError:
                subject = subject_dao.create(subject_username, subject_full_name, subject_email)
            
            # Step 3: Create the public Key in Key Store
            key = key_store_dao.create(subject_pub_key, "public")
            
            # Step 4: Associate Subject with the organization along with their public key
            self.add_subject_with_key(new_org, subject, key)

            # Step 5: Create new OrganizationACL for this Organization
            org_acl = organization_acl_dao.create(org_name)

            # Step 6: Create new Role "Manager" for this OrganizationACL
            manager_role = role_dao.create("Manager", org_acl.id)
            
            # Step 7: Add the creator Subject to the "Manager" Role
            manager_role.subjects.append(subject)  # add the subject to the role

            # Step 8: Add all Permissions for Manager
            permissions = self.session.query(Permission).filter(Permission.name.in_([
                "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", 
                "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", 
                "ROLE_UP", "ROLE_MOD"
            ])).all()

            for permission in permissions:
                manager_role.permissions.append(permission)

            # Commit all changes in one go
            self.session.commit()

            print(f"Organization '{org_name}' created successfully with 'Manager' (id: {manager_role.id}) role for {subject_username}.")
            
            return new_org
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the organization or associating the subject and key.")
        
    def add_subject_with_key(self, org: Organization, subject: Subject, key: KeyStore):
        org.subjects.append(subject)
        self.session.commit()
        print(f"Subject '{subject.username}' added to organization '{org.name}'.")
        
        if key and key.id:
            # Update the public key for the subject in the organization
            stmt = OrganizationSubjects.update().where(
                (OrganizationSubjects.c.org_name == org.name) &
                (OrganizationSubjects.c.username == subject.username)
            ).values(pub_key_id=key.id)
            self.session.execute(stmt)
            self.session.commit()
            print(f"Public key {key.id} associated with subject '{subject.username}' in organization '{org.name}'.")
        else:
            print(f"Error: Public key not available for subject '{subject.username}'.")
        
        self.session.refresh(org)
        org_subject = self.session.query(OrganizationSubjects).filter_by(
            org_name=org.name, username=subject.username
        ).first()
        
        if org_subject:
            print(f"Organization: {org_subject.org_name}, Subject: {org_subject.username}, Key: {org_subject.pub_key_id}")
        else:
            print(f"Error: Subject '{subject.username}' not found in the organization '{org.name}' after update.")
            
    
    def add_subject_to_organization(self, org_name: str, subject_username: str, subject_full_name: str, subject_email: str, subject_pub_key: str) -> Subject:
        """Add a Subject to an Organization."""
        subject_dao = SubjectDAO(self.session)
        key_store_dao = KeyStoreDAO(self.session)
        org = self.get_by_name(org_name)
        
        try:
            new_subject = subject_dao.get_by_username(subject_username)
        except ValueError:
            new_subject = subject_dao.create(subject_username, subject_full_name, subject_email)
        key = key_store_dao.create(subject_pub_key, "public")
        self.add_subject_with_key(org, new_subject, key)
        
            
    def get_by_name(self, name: str) -> "Organization":
        """Retrieve an Organization by name."""
        organization = self.session.query(Organization).filter_by(name=name).first()
        if not organization:
            raise ValueError(f"Organization with name '{name}' not found.")
        return organization

    def get_all(self) -> list["Organization"]:
        """Retrieve all Organizations."""
        return self.session.query(Organization).all()
    
    # ==================== Retrieve Subjects and their data associated with an Organization =================== #
    
    def get_subjects(self, name: str) -> list[Subject]:
        """Retrieve all Subjects associated with an Organization."""
        organization = self.get_by_name(name)
        return [subject for subject in organization.subjects]
    
    def get_subject_by_username(self, org_name: str, username: str) -> Subject:
        """Retrieve a Subject by username associated with an Organization."""
        subject_dao = SubjectDAO(self.session)
        organization = self.get_by_name(org_name)
        subject = subject_dao.get_by_username(username)
        if not subject:
            raise ValueError(f"Subject with username '{username}' not found.")
        if subject not in organization.subjects:
            raise ValueError(f"Subject '{username}' is not associated with the organization '{org_name}'.")
        return subject
    
    def get_org_subj_association(self, org_name: str, username: str):
        """Retrieve the Organization-Subject association."""
        org_subject = self.session.query(OrganizationSubjects).filter_by(org_name=org_name, username=username).first()
        if not org_subject:
            raise ValueError(f"Subject '{username}' is not associated with the organization '{org_name}'.")
        return org_subject
    
    def update_org_subj_association_status(self, org_name: str, username: str, new_status: str):
        """Update the Organization-Subject association."""
        stmt = OrganizationSubjects.update().where(
            (OrganizationSubjects.c.org_name == org_name) &
            (OrganizationSubjects.c.username == username)
        ).values(status=new_status)
        self.session.execute(stmt)
        self.session.commit()
        
        return self.get_org_subj_association(org_name, username)
    
    # ========================================================================================================= #

    def update(self, name: str, new_name: str = None) -> "Organization":
        """Update an existing Organization's name."""
        organization = self.get_by_name(name)
        if new_name:
            organization.name = new_name
        self.session.commit()
        return organization

    def delete(self, name: str) -> None:
        """Delete an Organization by name."""
        organization = self.get_by_name(name)
        self.session.delete(organization)
        self.session.commit()
        
        
    def verify_creation(self, org_name: str, subject_username: str, pub_key: str):
        # Verify the organization exists
        org = self.session.query(Organization).filter_by(name=org_name).first()
        if not org:
            print("Organization not found!")
            return False
        
        # Verify the subject is associated with the organization
        subject = self.session.query(Subject).filter_by(username=subject_username).first()
        if not subject:
            print("Subject not found!")
            return False

        org_subject = self.session.query(OrganizationSubjects).filter_by(
            org_name=org_name, username=subject_username
        ).first()
        if not org_subject:
            print("Subject is not associated with the organization!")
            return False

        # Verify the public key is associated with the subject
        key_store = self.session.query(KeyStore).filter_by(id=org_subject.pub_key_id).first()
        if not key_store or key_store.key != pub_key:
            print("Public key not found or mismatch!")
            return False

        # Verify the "Manager" role exists and the subject is assigned to it
        role = self.session.query(Role).filter_by(name="Manager", acl_id=org.acl.id).first()
        if not role:
            print("Manager role not found!")
            return False

        if subject not in role.subjects:
            print("Subject not added to Manager role!")
            return False

        # Verify permissions are assigned to the "Manager" role
        permissions = self.session.query(Permission).filter(
            Permission.name.in_([
                "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", 
                "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", 
                "ROLE_UP", "ROLE_MOD"
            ])
        ).all()

        for permission in permissions:
            if permission not in role.permissions:
                print(f"Permission '{permission.name}' not assigned to Manager role!")
                return False

        print("Organization creation and verifications passed!")
        return True
    
    
    def create_document(self, name: str, session_id: str, encrypted_data: bytes, alg: str, key: str, iv: str) -> Document:
        """Create a new document, its ACL, and metadata, and store the encrypted file."""

        try:
            # Step 1: Obtain the session details
            session_dao = SessionDAO(self.session)
            key_store_dao = KeyStoreDAO(self.session)
            session = session_dao.get_by_id(session_id)
            creator = session.subject
            organization = session.organization

            if not organization:
                raise ValueError("Session is not associated with any organization.")

            # Step 2: Generate creation date
            creation_date = datetime.now()

            # Step 3: Generate a digest for the encrypted data
            digest = hashlib.sha256(encrypted_data).hexdigest()
            document_handle = digest
            file_handle = f"{organization.name}_{digest}"
            file_path = os.path.join("data", organization.name, file_handle)

            # Step 4: Encrypt the data and store it in a file
            self._store_encrypted_data(file_path, encrypted_data)

            # Step 5: Create the Document entity
            document = Document(
                document_handle=document_handle,
                name=name,
                create_date=creation_date,
                file_handle=file_handle,
                creator_username=creator.username,
                org_name=organization.name
            )
            self.session.add(document)

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
            encrypted_key, iv_encrypted_key = self.encrypt_metadata_key(key)
            encrypted_metadata_key = key_store_dao.create(encrypted_key, "symmetric")
            print("ENCRYPTED METADATA KEY: ", encrypted_metadata_key.key.hex())
    
            metadata = RestrictedMetadata(
                document=document,
                alg=algorithm,
                mode=mode,
                key_id=encrypted_metadata_key.id,
                iv=iv,
                iv_encrypted_key=iv_encrypted_key
            )
            self.session.add(metadata)

            # Commit all changes
            self.session.commit()

            print(f"Document '{name}' created successfully for organization '{organization.name}'.")
            return document

        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the document or its associated entities.")

    def _store_encrypted_data(self, file_path: str, data: bytes):
        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Write the encrypted data to the file
        with open(file_path, "wb") as f:
            f.write(data)
    
    
    def encrypt_metadata_key(self, metadata_key: str) -> bytes:
        """
        Encrypt the metadata key using AES256 with a derived key from the repository password.
        """
        # Generate a random IV
        iv = os.urandom(16)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = self.derive_aes_key(repository_password)

        encrypted_key, key, iv = Cryptography.aes_cbc_encrypt(metadata_key.encode(), iv, aes_key)

        return encrypted_key, iv


    def derive_aes_key(self, password: str) -> bytes:
        """
        Derive a secure AES key from the repository password using PBKDF2.
        """
        # Generate a salt (e.g., from a secure source)
        salt = 'salt'.encode()

        # Use PBKDF2 to derive the AES key
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode())


    def decrypt_metadata_key(self, encrypted_key: bytes, iv: bytes) -> str:
        """
        Decrypt the metadata key using AES256 with a derived key from the repository password.
        """
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = self.derive_aes_key(repository_password)
        decrypted_key = Cryptography.aes_cbc_decrypt(encrypted_key, iv, aes_key)

        return decrypted_key


    def get_encrypted_key(self, document_id: int) -> bytes:
        """
        Retrieve the encrypted restricted_metadata key.
        """
        restricted_metadata = self.session.query(RestrictedMetadata).filter_by(document_id=document_id).first()
        if not restricted_metadata:
            raise ValueError(f"Session with ID '{document_id}' does not exist.")
        return restricted_metadata.key.key
    
    
    def get_decrypted_key(self, document_id: int) -> str:
        """
        Retrieve the decrypted restricted_metadata key. 
        """
        restricted_metadata = self.session.query(RestrictedMetadata).filter_by(document_id=document_id).first()
        if not restricted_metadata:
            raise ValueError(f"Session with ID '{document_id}' does not exist.")
        encrypted_key = self.get_encrypted_key(document_id)
        iv = restricted_metadata.iv_encrypted_key
        return self.decrypt_metadata_key(encrypted_key, iv)


# ============================================================================================================= #


class SessionDAO(BaseDAO):
    """DAO for managing Session entities."""

    def create(self, subject_username: str, organization_name: str, key: str, counter: int, nonce: str) -> Session:
        """
        Create a new session and optionally associate roles with it.

        :param subject_username: The username of the subject creating the session.
        :param organization_name: The name of the organization associated with the session.
        :param key: The key associated with this session.
        :return: The created Session object.
        :raises ValueError: If any of the parameters are invalid.
        :raises IntegrityError: If a database constraint is violated.
        """
        
        subject_dao = SubjectDAO(self.session)
        organization_dao = OrganizationDAO(self.session)
        key_store_dao = KeyStoreDAO(self.session)
        
        try:
            # Check if the subject exists
            subject = subject_dao.get_by_username(subject_username)
            if not subject:
                raise ValueError(f"Subject with username '{subject_username}' does not exist.")

            # Check if the organization exists
            organization = organization_dao.get_by_name(organization_name)
            if not organization:
                raise ValueError(f"Organization with name '{organization_name}' does not exist.")

            encrypted_key, iv = self.encrypt_session_key(key)
            encrypted_session_key = key_store_dao.create(encrypted_key, "symmetric")
            # Create the session
            new_session = Session(
                subject_username=subject_username,
                organization_name=organization_name,
                key_id=encrypted_session_key.id,
                key_iv=base64.b64encode(iv).decode('utf-8'),
                nonce=nonce,
                counter=counter
            )

            self.session.add(new_session)
            self.session.commit()

            # Optionally load relationships if needed
            self.session.refresh(new_session, attribute_names=['subject', 'organization', 'session_roles'])

            return new_session

        except IntegrityError as e:
            self.session.rollback()
            raise IntegrityError("Failed to create session due to a database constraint violation.") from e
        
        
    def get_iv(self, session_id: int) -> str:
        """
        Retrieve the IV associated with a session.
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        return session.key_iv
        
        
    def encrypt_session_key(self, session_key: str | bytes) -> bytes:
        """
        Encrypt the session key using AES256 with a derived key from the repository password.
        """
        # Generate a random IV
        iv = os.urandom(16)
        
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = self.derive_aes_key(repository_password)

        session_key = session_key.encode() if isinstance(session_key, str) else session_key
        encrypted_key, key, iv = Cryptography.aes_cbc_encrypt(session_key, iv, aes_key)

        return encrypted_key, iv


    def derive_aes_key(self, password: str) -> bytes:
        """
        Derive a secure AES key from the repository password using PBKDF2.
        """
        # Generate a salt (e.g., from a secure source)
        salt = 'salt'.encode()

        # Use PBKDF2 to derive the AES key
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode())


    def decrypt_session_key(self, encrypted_key: bytes, iv: bytes) -> bytes:
        """
        Decrypt the session key using AES256 with a derived key from the repository password.
        """
        # Derive AES key from the repository password
        repository_password = os.getenv("REPOSITORY_PASSWORD")
        aes_key = self.derive_aes_key(repository_password)
        decrypted_key = Cryptography.aes_cbc_decrypt(encrypted_key, iv, aes_key)

        return decrypted_key


    def get_by_id(self, session_id: int) -> Session:
        """
        Retrieve a session by its ID.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject),
            joinedload(Session.organization)
        ).filter_by(id=session_id).one_or_none()

    def get_all(self) -> list[Session]:
        """
        Retrieve all sessions.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject),
            joinedload(Session.organization)
        ).all()

    def get_by_subject(self, subject_username: str) -> list[Session]:
        """
        Retrieve all sessions associated with a given subject.
        """
        return self.session.query(Session).options(
            joinedload(Session.organization)
        ).filter_by(subject_username=subject_username).all()

    def get_by_organization(self, organization_name: str) -> list[Session]:
        """
        Retrieve all sessions associated with a given organization.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject)
        ).filter_by(organization_name=organization_name).all()

    def delete_by_id(self, session_id: int) -> bool:
        """
        Delete a session by its ID.
        """
        try:
            session = self.get_by_id(session_id)
            if session:
                self.session.delete(session)
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            raise

    def update_key(self, session_id: int, new_key: str) -> Session:
        """
        Update the key associated with a session.
        """
        key_store_dao = KeyStoreDAO(self.session)
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")

            # Update key in KeyStore
            session_key = key_store_dao.update(session.key_id, new_key)

            # Reflect updated key in session
            session.key_id = session_key.id
            self.session.commit()
            self.session.refresh(session)

            return session
        except IntegrityError:
            self.session.rollback()
            raise
        
        
    def get_encrypted_key(self, session_id: int) -> bytes:
        """
        Retrieve the encrypted session key.
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        return session.key.key
    
    
    def get_decrypted_key(self, session_id: int) -> str:
        """
        Retrieve the decrypted session key. 
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        encrypted_key = self.get_encrypted_key(session_id)
        iv = base64.b64decode(session.key_iv)
        return self.decrypt_session_key(encrypted_key, iv)
    

    def update_nonce(self, session_id: int, new_nonce: str) -> Session:
        """
        Update the nonce associated with a session.
        """
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")

            session.nonce = new_nonce
            self.session.commit()
            self.session.refresh(session)

            return session
        except IntegrityError:
            self.session.rollback()
            raise
    
    def update_counter(self, session_id: int, new_counter: int) -> Session:
        """
        Update the counter associated with a session.
        """
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")

            session.counter = new_counter
            self.session.commit()
            self.session.refresh(session)

            return session
        except IntegrityError:
            self.session.rollback()
            raise