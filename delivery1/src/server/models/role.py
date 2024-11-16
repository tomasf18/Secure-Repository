from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship
from base import Base
from acl import ACL
from permission import Permission
from subject import Subject

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

class Role(Base):
    __tablename__ = 'role'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(nullable=False)
    acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'))
    
    # Relationships
    acl: Mapped["ACL"] = relationship(back_populates="roles")
    permissions: Mapped[list["Permission"]] = relationship(secondary=RolePermissions)
    subjects: Mapped[list["Subject"]] = relationship(secondary=RoleSubjects)
    
    def __repr__(self):
        return f"<Role(name={self.name}, acl_id={self.acl_id})>"
