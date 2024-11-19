from .BaseDAO import BaseDAO
from models.orm import Repository

class RepositoryDAO(BaseDAO):
    """DAO for accessing Repository data."""
    
    def get_private_key(self) -> str:
        """Get the public key for the given repository."""
        repo = self.session.query(Repository).first()
        return repo.private_key.key