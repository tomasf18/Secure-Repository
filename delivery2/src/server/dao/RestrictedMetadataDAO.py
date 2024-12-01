from .BaseDAO import BaseDAO
from sqlalchemy.exc import IntegrityError
from models.database_orm import RestrictedMetadata, Document


class RestrictedMetadataDAO(BaseDAO):
    """DAO for managing RestrictedMetadata entities."""

    def create(self, document: Document, algorithm: str, mode: str, encrypted_metadata_key_id: int, iv: str, iv_encrypted_key: str) -> RestrictedMetadata:
        """ Create a new RestrictedMetadata entry. """
        try:
            metadata = RestrictedMetadata(
                document=document,
                alg=algorithm,
                mode=mode,
                key_id=encrypted_metadata_key_id,
                iv=iv,
                iv_encrypted_key=iv_encrypted_key
            )
            self.session.add(metadata)
            self.session.commit()
            return metadata
        except IntegrityError:
            self.session.rollback()
            raise ValueError(f"RestrictedMetadata for document '{document.name}' already exists.")