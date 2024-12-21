from datetime import datetime
from models.status import Status

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Column, ForeignKey, String, Table, UniqueConstraint

class Base(DeclarativeBase):
    pass


# ------------ Association Tables ------------ #

OrganizationSubjects = Table(
    "organization_subjects",
    Base.metadata,
    Column("org_name", ForeignKey("organization.name"), primary_key=True),
    Column("username", ForeignKey("subject.username"), primary_key=True),
    Column("pub_key_id", ForeignKey("key_store.id"), nullable=True),
    Column("status", String, nullable=False, default=Status.ACTIVE.value),
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


# ------------ Tables ------------ #

class Repository(Base):
    __tablename__ = 'repository'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    public_key_id: Mapped[int] = mapped_column(ForeignKey('key_store.id'), nullable=False)  
    private_key_id: Mapped[int] = mapped_column(ForeignKey('key_store.id'), nullable=False) 
    
    # Relationships
    public_key: Mapped["KeyStore"] = relationship(foreign_keys=[public_key_id])
    private_key: Mapped["KeyStore"] = relationship(foreign_keys=[private_key_id])
    
    # A repository must have a unique pair of public and private keys
    __table_args__ = (
        UniqueConstraint("id", "public_key_id", name="uq_repo_pub_key_id"),
        UniqueConstraint("id", "private_key_id", name="uq_repo_priv_key_id"),
    )
    
    def __repr__(self):
        return f"<Repository(id={self.id}, public_key={self.public_key}, private_key={self.private_key})>"

# ----------------------------------------------------------------------------------------------- #

class Document(Base):
    __tablename__ = 'document'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_handle: Mapped[str] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    create_date: Mapped[datetime] = mapped_column(nullable=False)
    file_handle: Mapped[str] = mapped_column(nullable=True)
    
    # Foreign Key Relationships
    creator_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=False)
    deleter_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=True, default=None)
    
    org_name: Mapped[str] = mapped_column(ForeignKey("organization.name"), nullable=False)
    
    # Relationships
    creator: Mapped["Subject"] = relationship(foreign_keys=[creator_username])
    acl: Mapped["DocumentACL"] = relationship(back_populates="document")
    deleter: Mapped["Subject"] = relationship(foreign_keys=[deleter_username])
    restricted_metadata: Mapped["RestrictedMetadata"] = relationship(back_populates="document")
    organization: Mapped["Organization"] = relationship(back_populates="documents")
    
    # A document name and a document handle must be unique within an organization
    __table_args__ = (
        UniqueConstraint("name", "org_name", name="uq_document_name_org_name"),
        UniqueConstraint("document_handle", "org_name", name="uq_document_handle_org_name"),
        UniqueConstraint("file_handle", "org_name", name="uq_file_handle_org_name"),
    )
    
    def __repr__(self):
        return f"<Document(document_handle={self.document_handle}, name={self.name}, create_date={self.create_date}, file_handle={self.file_handle}, creator_username={self.creator_username}, deleter_username={self.deleter_username}, org_name={self.org_name})>"

# ----------------------------------------------------------------------------------------------- #

class RestrictedMetadata(Base):
    __tablename__ = 'restrict_metadata'
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), primary_key=True)
    alg: Mapped[str] = mapped_column(nullable=False)
    mode: Mapped[str] = mapped_column(nullable=True)
    key_id: Mapped[int] = mapped_column(ForeignKey('key_store.id'), nullable=False)  # Foreign key column
    iv: Mapped[bytes] = mapped_column(nullable=True)
    
    # Salt used to derive the key used to encrypt the metadata key
    salt: Mapped[bytes] = mapped_column(nullable=False)
    # IV used to encrypt the encryption file key
    iv_encrypted_key: Mapped[bytes] = mapped_column(nullable=False)
    
    # Relationship
    document: Mapped["Document"] = relationship(back_populates="restricted_metadata")
    key: Mapped["KeyStore"] = relationship()  # Relationship to KeyStore
    
    def __repr__(self):
        return f"<RestrictedMetadata(document_id={self.document_id}, alg={self.alg}, key={self.key})>"

# ----------------------------------------------------------------------------------------------- #

class Organization(Base):
    __tablename__ = 'organization'
    
    name: Mapped[str] = mapped_column(primary_key=True)
    
    # Relationships
    documents: Mapped[list["Document"]] = relationship(back_populates="organization") # nullable is False by default
    acl: Mapped["OrganizationACL"] = relationship(back_populates="organization")
    subjects: Mapped[list["Subject"]] = relationship(secondary=OrganizationSubjects)
    
    def __repr__(self):
        return f"<Organization(name={self.name})>"
    
# ----------------------------------------------------------------------------------------------- #

class ACL(Base):
    __tablename__ = 'acl'
    __mapper_args__ = {
        'polymorphic_identity': 'acl',  # Base identity
        'polymorphic_on': 'type'       # Discriminator column
    }
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(nullable=False)  # Discriminator column
    
    def __repr__(self):
        return f"<ACL(type={self.type})>"

# ----------------------------------------------------------------------------------------------- #

class OrganizationACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'organization_acl',  # Specific identity
    }
    
    org_name: Mapped[str] = mapped_column(ForeignKey('organization.name'), unique=True, nullable=True)
    
    # Relationships
    roles: Mapped[list["Role"]] = relationship("Role", back_populates="acl")
    organization: Mapped["Organization"] = relationship(back_populates="acl")
    
    def __repr__(self):
        return f"<OrganizationACL(org_name={self.org_name})>"
    
# ----------------------------------------------------------------------------------------------- #    

class DocumentACL(ACL):
    __mapper_args__ = {
        'polymorphic_identity': 'document_acl',  # Specific identity
    }
    
    document_id: Mapped[str] = mapped_column(ForeignKey('document.id'), unique=True, nullable=True)
    
    # Relationships
    document: Mapped["Document"] = relationship(back_populates="acl")
    permissions: Mapped[list["DocumentRolePermission"]] = relationship(back_populates="document_acl")
    
    def __repr__(self):
        return f"<DocumentACL(document_id={self.document_id})>"
    
# ----------------------------------------------------------------------------------------------- #

class DocumentRolePermission(Base):
    __tablename__ = "document_role_permission"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey('role.id'), nullable=False)
    permission_name: Mapped[str] = mapped_column(ForeignKey('permission.name'), nullable=False)
    
    # Relationships
    role: Mapped["Role"] = relationship()
    permission: Mapped["Permission"] = relationship()
    document_acl: Mapped["DocumentACL"] = relationship(back_populates="permissions")
    
    __table_args__ = (
        UniqueConstraint("document_acl_id", "role_id", "permission_name", name="uq_doc_acl_role_permission"),
    )
    
    def __repr__(self):
        return f"<DocumentRolePermission(document_acl_id={self.document_acl_id}, role_id={self.role_id}, permission_name={self.permission_name})>"

# ----------------------------------------------------------------------------------------------- #

class Subject(Base):
    __tablename__ = 'subject'
    
    username: Mapped[str] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    
    def __repr__(self):
        return f"<Subject(username={self.username}, full_name={self.full_name}, email={self.email})>"
    
# ----------------------------------------------------------------------------------------------- #
    
class Role(Base):
    __tablename__ = 'role'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(nullable=False)
    acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'), nullable=False)
    status: Mapped[str] = mapped_column(nullable=False, default=Status.ACTIVE.value)
    
    # Relationships
    acl: Mapped["OrganizationACL"] = relationship(back_populates="roles")
    permissions: Mapped[list["Permission"]] = relationship(secondary=RolePermissions)
    subjects: Mapped[list["Subject"]] = relationship(secondary=RoleSubjects)
    
    # One role must have a unique name within an ACL
    __table_args__ = (
        UniqueConstraint("name", "acl_id", name="uq_role_name_acl_id"),
    )
    
    def __repr__(self):
        return f"<Role(name={self.name}, acl_id={self.acl_id})>"
    
# ----------------------------------------------------------------------------------------------- #

class Permission(Base):
    __tablename__ = 'permission'

    name: Mapped[str] = mapped_column(primary_key=True)
    
    def __repr__(self):
        return f"<Permission(name={self.name})>"

# ----------------------------------------------------------------------------------------------- #

class KeyStore(Base):
    __tablename__ = 'key_store'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[bytes] = mapped_column(nullable=False)
    type: Mapped[str] = mapped_column(nullable=False) # public/private/symmetric
    
    def __repr__(self):
        return f"<KeyStore(id={self.id}, key={self.key}, type={self.type})>"
    
# ----------------------------------------------------------------------------------------------- #
    
class Session(Base):
    __tablename__ = 'session'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    subject_username: Mapped[str] = mapped_column(ForeignKey('subject.username'), nullable=False)
    organization_name: Mapped[str] = mapped_column(ForeignKey('organization.name'), nullable=False)
    key_id: Mapped[int] = mapped_column(ForeignKey('key_store.id'), nullable=False)  # Foreign key column
    key_salt: Mapped[bytes] = mapped_column(nullable=False)
    key_iv: Mapped[bytes] = mapped_column(nullable=False)

    nonce: Mapped[str] = mapped_column(nullable=True)
    counter: Mapped[int] = mapped_column(nullable=True)
    
    last_interaction: Mapped[datetime] = mapped_column(nullable=False, default=lambda: datetime.now())
    
    # Relationships
    subject: Mapped["Subject"] = relationship()
    organization: Mapped["Organization"] = relationship()
    session_roles: Mapped[list["Role"]] = relationship(secondary=SessionRoles)
    key: Mapped["KeyStore"] = relationship()  # Relationship to KeyStore
    
    def __repr__(self):
        return f"<Session(id={self.id}, subject_username={self.subject_username}, organization_name={self.organization_name}, key_id={self.key_id})>"

# ----------------------------------------------------------------------------------------------- #