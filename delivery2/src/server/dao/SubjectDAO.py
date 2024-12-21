from .BaseDAO import BaseDAO
from models.database_orm import Subject
from sqlalchemy.exc import IntegrityError

permissions =  [
    "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD", "DOC_ACL", "DOC_READ", "DOC_DELETE"
]

class SubjectDAO(BaseDAO):
    
    def __init__(self, session):
        super().__init__(session)
    
# -------------------------------

    def create(self, username: str, full_name: str, email: str) -> "Subject":
        """Create a new Subject instance."""
        
        if username in permissions:
            raise ValueError(f"Subjects may not have the same name as permissions")
        
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
