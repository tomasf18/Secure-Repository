from .ACLDAO import ACLDAO
from models.orm import DocumentACL
from sqlalchemy.exc import IntegrityError

class DocumentACLDAO(ACLDAO):  
    
    def create(self,  document_id: str, acl_type: str = "document_acl") -> "DocumentACL":
        """Create a new ACL instance."""
        try:
            new_org_acl = DocumentACL(type=acl_type, document_id=document_id)
            self.session.add(new_org_acl)
            self.session.commit()
            return new_org_acl
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"ACL with type '{acl_type}' already exists.")
