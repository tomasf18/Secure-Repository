from BaseDAO import BaseDAO
from server.models.acl import ACL

class ACLDAO(BaseDAO):
      
    def get_by_type(self, acl_type: str) -> list["ACL"]:
        return self.session.query(ACL).filter(ACL.type == acl_type).all()
