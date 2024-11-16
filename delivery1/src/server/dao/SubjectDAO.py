from models.orm import Subject
from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError

class SubjectDAO(BaseDAO):
    
    def create(self, username: str, full_name: str, email: str) -> "Subject":
        """Create a new Subject instance."""
        try:
            new_subject = Subject(username=username, full_name=full_name, email=email)
            self.session.add(new_subject)
            self.session.commit()
            return new_subject
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Subject with username '{username}' or email '{email}' already exists.")
    
    def get_by_username(self, username: str) -> "Subject":
        """Retrieve a Subject by username."""
        subject = self.session.query(Subject).filter_by(username=username).first()
        if not subject:
            raise ValueError(f"Subject with username '{username}' not found.")
        return subject
    
    def get_all(self) -> list["Subject"]:
        """Retrieve all Subjects."""
        return self.session.query(Subject).all()
    
    def update(self, username: str, full_name: str = None, email: str = None) -> "Subject":
        """Update an existing Subject's details."""
        subject = self.get_by_username(username)
        if full_name:
            subject.full_name = full_name
        if email:
            subject.email = email
        self.session.commit()
        return subject
    
    def delete_subject(self, username: str) -> None:
        """Delete a Subject by username."""
        subject = self.get_by_username(username)
        self.session.delete(subject)
        self.session.commit()
    
    # def add_to_organization(self, username: str, organization_name: str, pub_key_id: int = None) -> None:
    #     """Add a Subject to an Organization."""
    #     subject = self.get_by_username(username)
    #     organization = self.session.query(Organization).filter_by(name=organization_name).first()
    #     if not organization:
    #         raise ValueError(f"Organization '{organization_name}' not found.")
    #     association_data = {"pub_key_id": pub_key_id} if pub_key_id else {}
    #     organization.subjects.append(subject, **association_data)
    #     self.session.commit()
    
    # def assign_role(self, username: str, role_id: int) -> None:
    #     """Assign a Role to a Subject."""
    #     subject = self.get_by_username(username)
    #     role = self.session.query(Role).filter_by(id=role_id).first()
    #     if not role:
    #         raise ValueError(f"Role with ID '{role_id}' not found.")
    #     subject.roles.append(role)
    #     self.session.commit()
    
    
