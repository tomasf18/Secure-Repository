from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base
from .role import Role
from .subject import Subject
from .organization import Organization

SessionRoles = Table(
    "session_roles",
    Base.metadata,
    Column("session_id", ForeignKey("session.id"), primary_key=True),
    Column("role_id", ForeignKey("role.id"), primary_key=True),
)


class Session(Base):
    __tablename__ = 'session'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    subject_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=False)
    organization_name: Mapped[str] = mapped_column(ForeignKey('organization.name'), nullable=False)
    # lifetime: Mapped[int] = mapped_column(nullable=False)  # Lifetime in seconds -> solved at application level
    
    # Relationships
    subject: Mapped["Subject"] = relationship()
    organization: Mapped["Organization"] = relationship()
    # keys: Mapped[list["KeyStore"]] = relationship() -> We don't need, since we are generating symmetric keys for each message and the other key is the public key of the subject within that organization, which is already stored in the key_store table
    session_roles: Mapped[list["Role"]] = relationship(secondary=SessionRoles)
    
    def __repr__(self):
        return f"<Session(id={self.id}, subject_username={self.subject_username}, organization_name={self.organization_name})>"