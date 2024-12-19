from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError

from .RoleDAO import RoleDAO
from .PermissionDAO import PermissionDAO
from .OrganizationDAO import OrganizationDAO

from models.database_orm import DocumentRolePermission, Role, Permission

class DocumentRolePermissionDAO(BaseDAO):
    """DAO for managing DocumentRolePermission entities."""
    
    def __init__(self, session):
        super().__init__(session)
        self.organization_dao = OrganizationDAO(session)
        self.role_dao = RoleDAO(session)
        self.permission_dao = PermissionDAO(session)
    
# -------------------------------
        
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
    
# -------------------------------
    
    def add_all_doc_permissions_to_role(self, document_acl_id: int, role_id: int):
        """ Add all document permissions to a role. """
        for permission_name in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
            permission_object = self.permission_dao.get_by_name(permission_name)
            self.create(document_acl_id, role_id, permission_object.name)

# -------------------------------

    def get_by_document_acl_id_and_role_id_and_permission_name(self, document_acl_id, role_id, permission_name) -> "DocumentRolePermission":
        # Must be a single result
        try:
            doc_role_perm = self.session.query(DocumentRolePermission).filter(DocumentRolePermission.document_acl_id == document_acl_id, DocumentRolePermission.role_id == role_id, DocumentRolePermission.permission_name == permission_name).one()
            return doc_role_perm
        except Exception:
            raise ValueError(f"DocumentRolePermission associated with document_acl_id '{document_acl_id}', role_id '{role_id}', permission_name '{permission_name}' not found.")
    
# -------------------------------

    def delete_by_id(self, document_role_permission_id):
        self.session.query(DocumentRolePermission).filter(DocumentRolePermission.id == document_role_permission_id).delete()
        self.session.commit()
        
# -------------------------------
        
    def get_roles_by_document_acl_id_and_permission_name(self, document_acl_id, permission_name) -> list["Role"]:
        """ Retrieve all roles associated with a given document ACL ID and permission name. """
        doc_role_perms = self.session.query(DocumentRolePermission).filter(DocumentRolePermission.document_acl_id == document_acl_id, DocumentRolePermission.permission_name == permission_name).all()        
        roles = [doc_role_perm.role for doc_role_perm in doc_role_perms]
        return roles
    
# -------------------------------

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
    
# -------------------------------
    
    def missing_doc_permissions(self, session_roles: list["Role"], document_acl_id: int, permissions: list[str]) -> list["Permission"]:
        """
        If all permissions are found in any of the session roles.
        """
        
        missing_permissions = []
        
        for permission in permissions:
            permission_object = self.permission_dao.get_by_name(permission)
            roles_with_permission = self.get_roles_by_document_acl_id_and_permission_name(document_acl_id, permission)
            if any(role in roles_with_permission for role in session_roles):
                continue
            missing_permissions.append(permission_object)
            
        return missing_permissions
        

        