from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError

from models.database_orm import DocumentRolePermission, Document, Organization, Role
from .OrganizationDAO import OrganizationDAO
from .RoleDAO import RoleDAO

class DocumentRolePermissionDAO(BaseDAO):
    """DAO for managing DocumentRolePermission entities."""
    
    def __init__(self, session):
        super().__init__(session)
        self.organization_dao = OrganizationDAO(session)
        self.role_dao = RoleDAO(session)
        
    def create(self, document_acl_id: int, role_id: int, permission_name: str) -> DocumentRolePermission:
        """ Create a new DocumentRolePermission entry. """
        try:
            new_document_role_permission = DocumentRolePermission(
                document_acl_id=document_acl_id,
                role_id=role_id,
                permission_name=permission_name
            )
            self.session.add(new_document_role_permission)
            self.session.commit()
            return new_document_role_permission
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"DocumentRolePermission associated with document_acl_id '{document_acl_id}', role_id '{role_id}', permission_name '{permission_name}' already exists.")
    
    def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name) -> "DocumentRolePermission":
        # Must be a single result
        try:
            doc_role_perm = self.session.query(DocumentRolePermission).filter(DocumentRolePermission.document_acl_id == document_acl_id, DocumentRolePermission.role_id == role_id, DocumentRolePermission.permission_name == permission_name).one()
            return doc_role_perm
        except Exception:
            raise ValueError(f"DocumentRolePermission associated with document_acl_id '{document_acl_id}', role_id '{role_id}', permission_name '{permission_name}' not found.")
    
    def delete_by_id(self, document_role_permission_id):
        self.session.query(DocumentRolePermission).filter(DocumentRolePermission.id == document_role_permission_id).delete()
        self.session.commit()
        
        
#class DocumentRolePermission(Base):
    # __tablename__ = "document_role_permission"
    
    # id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # document_acl_id: Mapped[int] = mapped_column(ForeignKey('acl.id'), nullable=False)
    # role_id: Mapped[int] = mapped_column(ForeignKey('role.id'), nullable=False)
    # permission_name: Mapped[str] = mapped_column(ForeignKey('permission.name'), nullable=False)
    
    # # Relationships
    # role: Mapped["Role"] = relationship()
    # permission: Mapped["Permission"] = relationship()
    # document_acl: Mapped["DocumentACL"] = relationship(back_populates="permissions")
    
    # __table_args__ = (
    #     UniqueConstraint("document_acl_id", "role_id", "permission_name", name="uq_doc_acl_role_permission"),
    # )
    
    # def __repr__(self):
    #     return f"<DocumentRolePermission(document_acl_id={self.document_acl_id}, role_id={self.role_id}, permission_name={self.permission_name})>"

    def get_document_roles_by_permission_and_org(self, permission_name, org_name) -> dict[str, list[str]]:
        # For each organization document, get the roles that have the specified permission
        doc_roles_by_permission = {} # Dict of type {document_name: [role_name, ...]}
        org = self.organization_dao.get_by_name(org_name)
        for doc in org.documents:
            doc_acl_id = doc.acl.id
            doc_roles_by_permission[doc.name] = []
            document_role_permission_by_doc_acl_id_and_permission = self.get_by_document_acl_id_and_permission_name(doc_acl_id, permission_name)
            for doc_role_perm in document_role_permission_by_doc_acl_id_and_permission:
                doc_roles_by_permission[doc.name].append(doc_role_perm.role.__repr__())
                
        return doc_roles_by_permission
            
    def get_by_document_acl_id_and_permission_name(self, document_acl_id, permission_name) -> list["DocumentRolePermission"]:
        return self.session.query(DocumentRolePermission).filter(DocumentRolePermission.document_acl_id == document_acl_id, DocumentRolePermission.permission_name == permission_name).all()
        