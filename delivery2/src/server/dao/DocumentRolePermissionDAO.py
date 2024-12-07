from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError
from models.database_orm import DocumentRolePermission

class DocumentRolePermissionDAO(BaseDAO):
    """DAO for managing DocumentRolePermission entities."""
    
    def __init__(self, session):
        super().__init__(session)
        
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
