from sqlalchemy.orm import Mapped, mapped_column
from .base import Base

class Subject(Base):
    __tablename__ = 'subject'
    
    username: Mapped[str] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    
    def __repr__(self):
        return f"<Subject(username={self.username}, full_name={self.full_name}, email={self.email})>"
