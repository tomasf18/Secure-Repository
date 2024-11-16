from BaseDAO import BaseDAO
from server.models.document import Document

class DocumentDAO(BaseDAO): 
    def get_by_name(self, name: str) -> list["Document"]:
        return self.session.query(Document).filter(Document.name == name).all()
    
    def get_by_creator(self, creator_username: str) -> list["Document"]:
        return self.session.query(Document).filter(Document.creator_username == creator_username).all()
