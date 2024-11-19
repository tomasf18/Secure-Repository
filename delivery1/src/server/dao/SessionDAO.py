from .BaseDAO import BaseDAO
from .SubjectDAO import SubjectDAO
from .OrganizationDAO import OrganizationDAO
from .KeyStoreDAO import KeyStoreDAO
from models.orm import Session
from models.orm import Subject, Organization
from sqlalchemy.exc import IntegrityError

class SessionDAO(BaseDAO): 
    """DAO for managing Session entities."""

from sqlalchemy.orm import joinedload

class SessionDAO(BaseDAO):
    """DAO for managing Session entities."""

    def create(self, subject_username: str, organization_name: str, key: str) -> Session:
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

            session_key = key_store_dao.create(key, "symmetric")

            # Create the session
            new_session = Session(
                subject_username=subject_username,
                organization_name=organization_name,
                key_id=session_key.id
            )

            self.session.add(new_session)
            self.session.commit()

            # Optionally load relationships if needed
            self.session.refresh(new_session, attribute_names=['subject', 'organization', 'session_roles'])

            return new_session

        except IntegrityError as e:
            self.session.rollback()
            raise IntegrityError("Failed to create session due to a database constraint violation.") from e

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