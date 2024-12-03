import base64

from .BaseDAO import BaseDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .OrganizationDAO import OrganizationDAO

from models.database_orm import Session

from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

class SessionDAO(BaseDAO):
    """DAO for managing Session entities."""

# -------------------------------

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

            # Load relationships 
            self.session.refresh(new_session, attribute_names=['subject', 'organization', 'session_roles'])

            return new_session

        except IntegrityError as e:
            self.session.rollback()
            raise IntegrityError("Failed to create session due to a database constraint violation.") from e

# -------------------------------
        
        
    def get_iv(self, session_id: int) -> str:
        """
        Retrieve the IV associated with a session.
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        return session.key_iv
    
    # def encrypt_session_key(self, session_key: str | bytes) -> bytes:
    #     """
    #     Encrypt the session key using AES256 with a derived key from the repository password.
    #     """
    #     # Generate a random IV
    #     iv = os.urandom(16)
        
    #     # Derive AES key from the repository password
    #     repository_password = os.getenv("REPOSITORY_PASSWORD")
    #     aes_key = self.derive_aes_key(repository_password)

    #     session_key = session_key.encode() if isinstance(session_key, str) else session_key
    #     encrypted_key, key, iv = Cryptography.aes_cbc_encrypt(session_key, iv, aes_key)

    #     return encrypted_key, iv


    # def derive_aes_key(self, password: str) -> bytes:
    #     """
    #     Derive a secure AES key from the repository password using PBKDF2.
    #     """
    #     # Generate a salt (e.g., from a secure source)
    #     salt = 'salt'.encode()

    #     # Use PBKDF2 to derive the AES key
    #     kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    #     return kdf.derive(password.encode())


    # def decrypt_session_key(self, encrypted_key: bytes, iv: bytes) -> bytes:
    #     """
    #     Decrypt the session key using AES256 with a derived key from the repository password.
    #     """
    #     # Derive AES key from the repository password
    #     repository_password = os.getenv("REPOSITORY_PASSWORD")
    #     aes_key = self.derive_aes_key(repository_password)
    #     decrypted_key = Cryptography.aes_cbc_decrypt(encrypted_key, iv, aes_key)

    #     return decrypted_key


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