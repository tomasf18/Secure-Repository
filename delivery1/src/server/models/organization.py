from sqlalchemy import Column, ForeignKey, Table, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from base import Base
from acl import ACL
from subject import Subject
from document import Document

OrganizationSubjects = Table(
    "organization_subjects",
    Base.metadata,
    Column("org_name", ForeignKey("organization.name"), primary_key=True),
    Column("username", ForeignKey("subject.username"), primary_key=True),
    Column("pub_key_id", ForeignKey("key_store.id")),
    UniqueConstraint("username", "pub_key_id", name="uq_username_pub_key_id"),
)

class Organization(Base):
    __tablename__ = 'organization'
    
    name: Mapped[str] = mapped_column(primary_key=True)
    
    # Relationships
    documents: Mapped[list["Document"]] = relationship(back_populates="organization") # nullable is False by default
    acl: Mapped["OrganizationACL"] = relationship(back_populates="organization")
    subjects: Mapped[list["Subject"]] = relationship(secondary=OrganizationSubjects)
    
    def __repr__(self):
        return f"<Organization(name={self.name})>"
    
class OrganizationACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'organization_acl',  # Specific identity
    }
    
    org_name: Mapped[str] = mapped_column(ForeignKey('organization.name'), unique=True)
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="acl")
    
    def __repr__(self):
        return f"<OrganizationACL(org_name={self.org_name})>"