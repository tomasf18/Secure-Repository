from models.orm import Role
from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError

class RoleDAO(BaseDAO):
    
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
    
    def get_by_id(self, role_id: int) -> "Role":
        """Retrieve a Role by ID."""
        role = self.session.query(Role).filter_by(id=role_id).first()
        if not role:
            raise ValueError(f"Role with ID '{role_id}' not found.")
        return role
    
    def get_by_name(self, name: str) -> "Role":
        """Retrieve a Role by name."""
        role = self.session.query(Role).filter_by(name=name).first()
        if not role:
            raise ValueError(f"Role with name '{name}' not found.")
        return role
    
    def get_all(self) -> list["Role"]:
        """Retrieve all Roles."""
        return self.session.query(Role).all()
    
    def update(self, role_id: int, name: str = None, acl_id: int = None) -> "Role":
        """Update an existing Role's details."""
        role = self.get_by_id(role_id)
        if name:
            role.name = name
        if acl_id:
            role.acl_id = acl_id
        self.session.commit()
        return role
    
    def delete(self, role_id: int) -> None:
        """Delete a Role by ID."""
        role = self.get_by_id(role_id)
        self.session.delete(role)
        self.session.commit()
