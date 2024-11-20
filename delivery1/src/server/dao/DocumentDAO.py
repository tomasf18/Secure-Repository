from sqlalchemy.orm import Session
from sqlalchemy import func
from models.orm import Document
from datetime import datetime
from .BaseDAO import BaseDAO
from .OrganizationDAO import SessionDAO


class DocumentDAO(BaseDAO):
    """DAO for managing Document entities."""

    def get(self, sessionId: int, creator_username: str = None, date_filter: str = None, date: datetime = None) -> list[Document]:
        """
        Fetches documents based on the organization, optional creator, and date filter.

        :param session: SQLAlchemy session object.
        :param organization_name: Name of the organization.
        :param creator_username: (Optional) Username of the creator to filter by.
        :param date_filter: (Optional) 'lt', 'gt', or 'eq' for filtering by date.
        :param date: (Optional) Date for filtering.
        :return: List of matching Document objects.
        """
        print(sessionId)
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        print(session)
        organization_name = session.organization_name
        
        query = self.session.query(Document).filter(Document.org_name == organization_name)

        if creator_username:
            query = query.filter(Document.creator_username == creator_username)

        if date and date_filter:
            if date_filter == "nt":
                query = query.filter(Document.create_date > date)
            elif date_filter == "ot":
                query = query.filter(Document.create_date < date)
            elif date_filter == "et":
                query = query.filter(func.date(Document.create_date) == date)

        return query.all()