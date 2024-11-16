from sqlalchemy.orm import Mapped, mapped_column, relationship
from base import Base
from role import Role

class ACL(Base):
    __tablename__ = 'acl'
    __mapper_args__ = {
        'polymorphic_identity': 'acl',  # Base identity
        'polymorphic_on': 'type'       # Discriminator column
    }
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(nullable=False)  # Discriminator column
    
    # Relationships
    roles: Mapped[list["Role"]] = relationship("Role", back_populates="acl")
    
    def __repr__(self):
        return f"<ACL(type={self.type})>"