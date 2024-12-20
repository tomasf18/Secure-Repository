from .BaseDAO import BaseDAO
from .RoleDAO import RoleDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .PermissionDAO import PermissionDAO
from .OrganizationDAO import OrganizationDAO

from models.database_orm import Role, Session, Permission

from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

class SessionDAO(BaseDAO):
    """DAO for managing Session entities."""
    
    def __init__(self, session):
        super().__init__(session)
        self.subject_dao = SubjectDAO(session)
        self.key_store_dao = KeyStoreDAO(session)
        self.organization_dao = OrganizationDAO(session)
        self.role_dao = RoleDAO(session)
        self.permission_dao = PermissionDAO(session)

# -------------------------------

    def create(self, subject_username: str, organization_name: str, key: bytes, counter: int, nonce: str) -> Session:
        """ Create a new session for a subject and an organization
        
        Args:
            subject_username (str): Username of the subject
            organization_name (str): Name of the organization
            key (str): Session key
            counter (int): Counter value
            nonce (str): Nonce value
            
        Returns:
            Session: Created session    
        """
        
        try:
            # Check if the subject exists
            subject = self.subject_dao.get_by_username(subject_username)
            if not subject:
                raise ValueError(f"Subject with username '{subject_username}' does not exist.")

            # Check if the organization exists
            organization = self.organization_dao.get_by_name(organization_name)
            if not organization:
                raise ValueError(f"Organization with name '{organization_name}' does not exist.")

            encrypted_session_key, iv, salt = self.key_store_dao.create(key, "symmetric")
            
            print(f"\n\nSession key iv: {iv} with length {len(iv)}")
            print(f"Decrypted session key: {key}")
            print(f"Encrypted session key: {encrypted_session_key.key}")
            print(f'Again, decrypted session key: {self.key_store_dao.decrypt_key(encrypted_session_key.key, iv, salt)}\n\n')
            
            # Create the session
            new_session = Session(
                subject_username=subject_username,
                organization_name=organization_name,
                key_id=encrypted_session_key.id,
                key_salt=salt,
                key_iv=iv,
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

    def get_by_id(self, session_id: int) -> Session:
        """
        Retrieve a session by its ID.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject),
            joinedload(Session.organization)
        ).filter_by(id=session_id).one_or_none()

# -------------------------------

    def get_all(self) -> list[Session]:
        """
        Retrieve all sessions.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject),
            joinedload(Session.organization)
        ).all()
        
# -------------------------------
            
    def get_encrypted_key(self, session_id: int) -> bytes:
        """
        Retrieve the encrypted session key.
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        return session.key.key
    
# -------------------------------
    
    def get_decrypted_key(self, session_id: int) -> str:
        """
        Retrieve the decrypted session key. 
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        encrypted_key = self.get_encrypted_key(session_id)
        iv = session.key_iv
        salt = session.key_salt
        return self.key_store_dao.decrypt_key(encrypted_key, iv, salt)
    
# -------------------------------    
    
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
       
# -------------------------------   

    def add_session_role(self, session_id: int, role: str) -> Role:
        """
        Add a role to a session.
        """
        try:
            session: Session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")
            
            role_object = self.role_dao.get_by_name_and_acl_id(role, session.organization.acl.id)
            
            session.session_roles.append(role_object)
            self.session.commit()
            
            self.session.refresh(role_object)
            self.session.refresh(session)
            
            return role_object
        except IntegrityError:
            self.session.rollback()
            
# -------------------------------

    def drop_session_role(self, session_id: int, role: str) -> Role:
        """
        Drop a role from a session.
        """
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")
            
            role_object = self.role_dao.get_by_name_and_acl_id(role, session.organization.acl.id)
            
            try:
                session.session_roles.remove(role_object)
                self.session.commit()
                
                self.session.refresh(role_object)
                self.session.refresh(session)
                
                return role_object
            except ValueError:
                raise ValueError(f"Role '{role}' is not associated with session '{session_id}'.")
            
        except IntegrityError:
            self.session.rollback()

# -------------------------------
 
        
    def get_iv(self, session_id: int) -> str:
        """
        Retrieve the IV associated with a session.
        """
        session = self.get_by_id(session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' does not exist.")
        return session.key_iv


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


    def update_key(self, session_id: int, new_key: bytes) -> Session:
        """
        Update the key associated with a session.
        """
        self.key_store_dao = KeyStoreDAO(self.session)
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")

            # Update key in KeyStore
            session_key = self.key_store_dao.update(session.key_id, new_key)

            # Reflect updated key in session
            session.key_id = session_key.id
            self.session.commit()
            self.session.refresh(session)

            return session
        except IntegrityError:
            self.session.rollback()
            raise
        
# -------------------------------

    def missing_org_permitions(self, session_id: int, permissions: list[str]) -> list["Permission"]:
        """
        Check if a subject within a session has the given permission(s).
        """
        missing_permissions = []
        session = self.get_by_id(session_id)
        session_roles = session.session_roles
        for permission in permissions:
            permission_object = self.permission_dao.get_by_name(permission)
            if any(permission_object in role.permissions for role in session_roles):
                continue
            missing_permissions.append(permission_object)
        
        return missing_permissions

# -------------------------------

    def drop_subject_sessions_role(self, subject_username: str, role_name: str) -> Role:
        """
        Drop a role from all sessions associated with a subject.
        """
        subject_sessions = self.get_by_subject(subject_username)
        for session in subject_sessions:
            try:
                self.drop_session_role(session.id, role_name)
            except ValueError:
                pass # If the role is not associated with the session, continue
    
# -------------------------------

    def get_by_role(self, role: Role) -> list[Session]:
        """
        Retrieve all sessions associated with a given role.
        """
        return self.session.query(Session).options(
            joinedload(Session.subject),
            joinedload(Session.organization)
        ).join(Session.session_roles).filter_by(id=role.id).all()
        
        
# -------------------------------

    def remove_role_from_all_sessions(self, role: Role) -> bool:
        """
        Remove a role from all sessions.
        """
        sessions = self.get_by_role(role)
        for session in sessions:
            try:
                self.drop_session_role(session.id, role.name)
            except ValueError:
                pass