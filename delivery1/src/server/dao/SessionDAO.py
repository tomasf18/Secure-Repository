from .BaseDAO import BaseDAO
from models.orm import Session

class SessionDAO(BaseDAO): 
     
    def get_by_subject_and_org(self, subject_username: str, org_name: str) -> "Session":
        return self.session.query(Session).filter(Session.subject_username == subject_username, Session.organization_name == org_name).first()
