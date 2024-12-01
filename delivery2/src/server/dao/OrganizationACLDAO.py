from .ACLDAO import ACLDAO
from models.database_orm import OrganizationACL
from sqlalchemy.exc import IntegrityError

class OrganizationACLDAO(ACLDAO):      
    
    def create(self,  org_name: str, acl_type: str = "organization_acl") -> "OrganizationACL":
        """Create a new ACL instance."""
        try:
            new_org_acl = OrganizationACL(type=acl_type, org_name=org_name)
            self.session.add(new_org_acl)
            self.session.commit()
            return new_org_acl
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"ACL with type '{acl_type}' already exists.")
