from sqlalchemy.orm import Session

class BaseDAO:
    
    def __init__(self, session: Session):
        self.session = session