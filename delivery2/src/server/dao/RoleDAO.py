from .BaseDAO import BaseDAO
from models.status import Status
from models.database_orm import Role, Subject
from sqlalchemy.exc import IntegrityError

class RoleDAO(BaseDAO):
    
    def __init__(self, session):
        super().__init__(session)
        
# -------------------------------
    
    def create(self, name: str, acl_id: int) -> "Role":
        """Create a new Role instance."""
        try:
            new_role = Role(name=name, acl_id=acl_id)
            self.session.add(new_role)
            self.session.commit()
            return new_role
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Role with name '{name}' already exists.")
    
# -------------------------------
        
    def get_by_name_and_acl_id(self, name: str, acl_id: int) -> "Role":
        """Retrieve a Role by name and ACL ID."""
        role = self.session.query(Role).filter_by(acl_id=acl_id, name=name).first()
        if not role:
            raise ValueError(f"Role with name '{name}' and ACL ID '{acl_id}' not found.")
        return role
    
# -------------------------------
    
    def get_by_username_and_acl_id(self, username: str, acl_id: int) -> list["Role"]:
        """Retrieve all Roles associated with a given username and ACL ID."""
        subject_roles = self.session.query(Role).filter_by(acl_id=acl_id).join(Role.subjects).filter_by(username=username).all()
        return subject_roles
    
# -------------------------------

    def get_role_subjects(self, role_name, acl_id) -> list["Subject"]:
        """Retrieve all Subjects associated with a given Role in a given Organization."""
        role = self.get_by_name_and_acl_id(role_name, acl_id)
        return role.subjects

# -------------------------------

    def get_by_acl_id_and_permission(self, acl_id: int, permission_name: str) -> list["Role"]:
        """Retrieve all Roles associated with a given ACL ID and permission."""
        roles = self.session.query(Role).filter_by(acl_id=acl_id).join(Role.permissions).filter_by(name=permission_name).all()
        return roles
    
# -------------------------------
    
    def update_role_status(self, role_name, acl_id, new_status) -> "Role":
        """Update the status of a Role."""
        role = self.get_by_name_and_acl_id(role_name, acl_id)
        role.status = new_status
        self.session.commit()
        return role
