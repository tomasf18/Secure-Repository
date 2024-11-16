from BaseDAO import BaseDAO
from server.models.role import Role

class RoleDAO(BaseDAO):    
     
    def get_by_name(self, name: str) -> "Role":
        return self.session.query(Role).filter(Role.name == name).first()
