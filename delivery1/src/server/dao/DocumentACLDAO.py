from BaseDAO import BaseDAO
from server.models.document import DocumentACL

class DocumentACLDAO(BaseDAO):  
    
    def get_by_document_id(self, document_id: int) -> "DocumentACL":
        return self.session.query(DocumentACL).filter(DocumentACL.document_id == document_id).first()
