from sqlalchemy import ForeignKey, Table, Column, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase
from datetime import datetime

class Base(DeclarativeBase):
    pass

OrganizationSubjects = Table(
    "organization_subjects",
    Base.metadata,
    Column("org_name", ForeignKey("organization.name"), primary_key=True),
    Column("username", ForeignKey("subject.username"), primary_key=True),
    Column("pub_key_id", ForeignKey("key_store.id")),
    UniqueConstraint("username", "pub_key_id", name="uq_username_pub_key_id"),
)

RoleSubjects = Table(
    "role_subjects",
    Base.metadata,
    Column("role_id", ForeignKey("role.id"), primary_key=True),
    Column("username", ForeignKey("subject.username"), primary_key=True),
)

RolePermissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("role.id"), primary_key=True),
    Column("permission_name", ForeignKey("permission.name"), primary_key=True),
)

SessionRoles = Table(
    "session_roles",
    Base.metadata,
    Column("session_id", ForeignKey("session.id"), primary_key=True),
    Column("role_id", ForeignKey("role.id"), primary_key=True),
)

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

class RestrictedMetadata(Base):
    __tablename__ = 'restrict_metadata'
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), primary_key=True)
    alg: Mapped[str] = mapped_column(nullable=False)
    key: Mapped[str] = mapped_column(nullable=False)
    
    # Relationship
    document: Mapped["Document"] = relationship(back_populates="restricted_metadata")

class ACL(Base):
    __tablename__ = 'acl'
    __mapper_args__ = {
        'polymorphic_identity': 'acl',  # Base identity
        'polymorphic_on': 'type'       # Discriminator column
    }
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(nullable=False)  # Discriminator column
    
    # Relationships
    roles: Mapped[list["Role"]] = relationship("Role", back_populates="acl")
    
class DocumentACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'document_acl',  # Specific identity
    }
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), unique=True)
    
    # Relationships
    document: Mapped["Document"] = relationship(back_populates="acl")

class Organization(Base):
    __tablename__ = 'organization'
    
    name: Mapped[str] = mapped_column(primary_key=True)
    
    # Relationships
    documents: Mapped[list["Document"]] = relationship(back_populates="organization")
    acl: Mapped["OrganizationACL"] = relationship(back_populates="organization")
    subjects: Mapped[list["Subject"]] = relationship(secondary=OrganizationSubjects)
    
class OrganizationACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'organization_acl',  # Specific identity
    }
    
    org_name: Mapped[str] = mapped_column(ForeignKey('organization.name'), unique=True)
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="acl")


class Subject(Base):
    __tablename__ = 'subject'
    
    username: Mapped[str] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False)
    
class KeyStore(Base):
    __tablename__ = 'key_store'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(nullable=False)
    type: Mapped[str] = mapped_column(nullable=False)

class Role(Base):
    __tablename__ = 'role'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(nullable=False)
    acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'))
    
    # Relationships
    acl: Mapped["ACL"] = relationship(back_populates="roles")
    permissions: Mapped[list["Permission"]] = relationship(secondary=RolePermissions)
    subjects: Mapped[list["Subject"]] = relationship(secondary=RoleSubjects)


class Permission(Base):
    __tablename__ = 'permission'

    name: Mapped[str] = mapped_column(primary_key=True)

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