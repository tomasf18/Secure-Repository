from sqlalchemy import func
from server.models.database_orm import Document
from datetime import datetime
from .BaseDAO import BaseDAO
from .OrganizationDAO import SessionDAO


class DocumentDAO(BaseDAO):
    """DAO for managing Document entities."""

    def get(self, sessionId: int, creator_username: str = None, date_filter: str = None, date: datetime = None) -> list[Document]:
        """
        Fetches documents based on the organization, optional creator, and date filter.

        :param sessionId: ID of the session.
        :param creator_username: (Optional) Username of the creator to filter by.
        :param date_filter: (Optional) 'lt', 'gt', or 'eq' for filtering by date.
        :param date: (Optional) Date for filtering.
        :return: List of matching Document objects.
        :raises ValueError: If the session is invalid or date_filter is invalid.
        """
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        if not session:
            raise ValueError(f"Session with ID {sessionId} not found.")
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
    
    def get_metadata(self, sessionId: int, document_name: str) -> Document:
        """
        Fetches metadata for a document.

        :param sessionId: ID of the session.
        :param document_name: Name of the document.
        :return: Document object.
        :raises ValueError: If the session is invalid or the document is not found.
        """
        # Ensure session is valid
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        if not session:
            raise ValueError(f"Session with ID {sessionId} not found.")
        organization_name = session.organization_name

        # Fetch document metadata
        query = self.session.query(Document).filter(Document.org_name == organization_name, Document.name == document_name)
        document = query.first()

        if not document:
            raise ValueError(f"Document '{document_name}' not found in organization '{organization_name}'.")
        
        return document
    
    # def get_doc_file_handle(self, sessionId: int, document_name: str) -> str:
    #     """
    #     Fetches the file handle for a document.

    #     :param sessionId: ID of the session.
    #     :param document_name: Name of the document.
    #     :return: File handle.
    #     :raises ValueError: If the document is not found.
    #     """
    #     document = self.get_metadata(sessionId, document_name)
    #     if not document.file_handle:
    #         raise ValueError(f"Document '{document_name}' does not have an associated file handle.")
    #     return document.file_handle
    
    def delete(self, sessionId: int, document_name: str) -> str:
        """
        Clears the file_handle in the metadata of a document with a given name
        in the organization associated with the current session. Returns the
        file_handle that was cleared.

        :param sessionId: ID of the session.
        :param document_name: Name of the document.
        :return: The cleared file_handle.
        :raises ValueError: If the session or document is invalid or the file_handle is already None.
        """
        # Fetch document metadata
        document = self.get_metadata(sessionId, document_name)

        # Check if file_handle is already None
        if document.file_handle is None:
            raise ValueError(f"Document '{document_name}' already has no file handle.")

        # Clear file_handle
        ceasing_file_handle = document.file_handle
        document.file_handle = None
        
        # Assign deleter
        session_dao = SessionDAO(self.session)
        session = session_dao.get_by_id(sessionId)
        document.deleter_username = session.subject_username
        
        self.session.commit()

        return ceasing_file_handle