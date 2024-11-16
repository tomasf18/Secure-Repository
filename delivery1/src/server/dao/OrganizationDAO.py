from BaseDAO import BaseDAO
from server.models.organization import Organization

class OrganizationDAO(BaseDAO):  
    
    def get_by_name(self, name: str) -> "Organization":
        return self.session.query(Organization).filter(Organization.name == name).first()
