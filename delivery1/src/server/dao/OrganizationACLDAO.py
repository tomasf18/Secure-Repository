from BaseDAO import BaseDAO
from server.models.organization import OrganizationACL

class OrganizationACLDAO(BaseDAO):      
    
    def get_by_org_name(self, org_name: str) -> "OrganizationACL":
        return self.session.query(OrganizationACL).filter(OrganizationACL.org_name == org_name).first()
