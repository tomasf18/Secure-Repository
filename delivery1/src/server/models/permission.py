from sqlalchemy.orm import Mapped, mapped_column
from base import Base

class Permission(Base):
    __tablename__ = 'permission'

    name: Mapped[str] = mapped_column(primary_key=True)
    
    def __repr__(self):
        return f"<Permission(name={self.name})>"
    