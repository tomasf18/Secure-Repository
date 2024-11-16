from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from .base import Base
from .acl import ACL
from .organization import Organization
from .subject import Subject

class Document(Base):
    __tablename__ = 'document'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_handle: Mapped[str] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    create_date: Mapped[datetime] = mapped_column(nullable=False)
    file_handle: Mapped[str] = mapped_column(nullable=True)
    
    # Foreign Key Relationships
    creator_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=False)
    deleter_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=True)
    
    org_name: Mapped[str] = mapped_column(ForeignKey("organization.name"))
    
    # Relationships
    creator: Mapped["Subject"] = relationship(foreign_keys=[creator_username])
    acl: Mapped["DocumentACL"] = relationship(back_populates="document")
    deleter: Mapped["Subject"] = relationship(foreign_keys=[deleter_username])
    restricted_metadata: Mapped["RestrictedMetadata"] = relationship(back_populates="document")
    organization: Mapped["Organization"] = relationship(back_populates="documents")
    
    def __repr__(self):
        return f"<Document(document_handle={self.document_handle}, name={self.name}, create_date={self.create_date}, file_handle={self.file_handle}, creator_username={self.creator_username}, deleter_username={self.deleter_username}, org_name={self.org_name})>"

class RestrictedMetadata(Base):
    __tablename__ = 'restrict_metadata'
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), primary_key=True)
    alg: Mapped[str] = mapped_column(nullable=False)
    key: Mapped[str] = mapped_column(nullable=False)
    
    # Relationship
    document: Mapped["Document"] = relationship(back_populates="restricted_metadata")
    
    def __repr__(self):
        return f"<RestrictedMetadata(document_id={self.document_id}, alg={self.alg}, key={self.key})>"
    
    
class DocumentACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'document_acl',  # Specific identity
    }
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), unique=True)
    
    # Relationships
    document: Mapped["Document"] = relationship(back_populates="acl")
    
    def __repr__(self):
        return f"<DocumentACL(document_id={self.document_id})>"
