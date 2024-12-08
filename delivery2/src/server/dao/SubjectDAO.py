from .BaseDAO import BaseDAO
from models.database_orm import Subject
from sqlalchemy.exc import IntegrityError

class SubjectDAO(BaseDAO):
    
    def __init__(self, session):
        super().__init__(session)
    
# -------------------------------

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
    
# -------------------------------

    def get_by_username(self, username: str) -> "Subject":
        """Retrieve a Subject by username."""
        subject = self.session.query(Subject).filter_by(username=username).first()
        if not subject:
            raise ValueError(f"Subject with username '{username}' not found.")
        return subject

# -------------------------------
