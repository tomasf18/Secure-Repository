from .BaseDAO import BaseDAO
from models.database_orm import ACL

class ACLDAO(BaseDAO):
    """DAO for managing ACL entities."""

    def get_by_id(self, acl_id: int) -> "ACL":
        """Retrieve an ACL by its ID."""
        acl = self.session.query(ACL).filter_by(id=acl_id).first()
        if not acl:
            raise ValueError(f"ACL with ID '{acl_id}' not found.")
        return acl

    def get_by_type(self, acl_type: str) -> list["ACL"]:
        """Retrieve all ACLs of a given type."""
        return self.session.query(ACL).filter_by(type=acl_type).all()

    def delete(self, acl_id: int) -> None:
        """Delete an ACL by its ID."""
        acl = self.get_by_id(acl_id)
        self.session.delete(acl)
        self.session.commit()
