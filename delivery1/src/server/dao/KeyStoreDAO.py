from BaseDAO import BaseDAO
from server.models.keystore import KeyStore

class KeyStoreDAO(BaseDAO):
    
    def get_by_key(self, key: str) -> "KeyStore":
        return self.session.query(KeyStore).filter(KeyStore.key == key).first()
