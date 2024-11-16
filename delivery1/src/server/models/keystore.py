from sqlalchemy.orm import Mapped, mapped_column
from base import Base

class KeyStore(Base):
    __tablename__ = 'key_store'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(nullable=False)
    type: Mapped[str] = mapped_column(nullable=False)
    
    def __repr__(self):
        return f"<KeyStore(id={self.id}, key={self.key}, type={self.type})>"