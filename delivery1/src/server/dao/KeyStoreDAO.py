from .BaseDAO import BaseDAO
from models.orm import KeyStore
from sqlalchemy.exc import IntegrityError

class KeyStoreDAO(BaseDAO):
    
    def create(self, key: str, type: str) -> "KeyStore":
        """Create a new KeyStore entry."""
        try:
            new_key = KeyStore(key=key, type=type)
            self.session.add(new_key)
            self.session.commit()
            return new_key
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"Key '{key}' already registered.")