from .BaseDAO import BaseDAO
from models.database_orm import Permission

class PermissionDAO(BaseDAO):
    
    def __init__(self, session):
        super().__init__(session)
    
# -------------------------------

    def get_by_name(self, name: str) -> "Permission":
        """Retrieve a Permission by name."""
        permission = self.session.query(Permission).filter_by(name=name).first()
        if not permission:
            raise ValueError(f"Permission with name '{name}' not found.")
        return permission
    
    def get_all(self) -> list["Permission"]:
        """Retrieve all Permissions."""
        return self.session.query(Permission).all()