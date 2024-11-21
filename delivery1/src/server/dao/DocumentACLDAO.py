from .ACLDAO import ACLDAO
from models.orm import DocumentACL
from sqlalchemy.exc import IntegrityError

class DocumentACLDAO(ACLDAO):  
    
    def create(self,  document_id: str, acl_type: str = "document_acl") -> "DocumentACL":
        """Create a new ACL instance."""
        try:
            print("BEFORE")
            new_doc_acl = DocumentACL(type=acl_type, document_id=document_id)
            print("AFTER")
            self.session.add(new_doc_acl)
            self.session.commit()
            return new_doc_acl
        except IntegrityError as e:
            self.session.rollback()
            print(f'ERRRRORRRRR:::: {e}')
            return None
