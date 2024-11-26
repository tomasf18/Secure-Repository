# from sqlalchemy.orm import Session

# from .DocumentDAO import DocumentDAO
# from .SubjectDAO import SubjectDAO
# from .OrganizationDAO import OrganizationDAO
# from .RoleDAO import RoleDAO
# from .KeyStoreDAO import KeyStoreDAO
# from .SessionDAO import SessionDAO
# from .ACLDAO import ACLDAO
# from .DocumentACLDAO import DocumentACLDAO
# from .OrganizationACLDAO import OrganizationACLDAO

# class DAOFactory:
#     def __init__(self, session: Session):
#         self.session = session

#     def get_document_dao(self) -> DocumentDAO:
#         return DocumentDAO(self.session)

#     def get_subject_dao(self) -> SubjectDAO:
#         return SubjectDAO(self.session)

#     def get_organization_dao(self) -> OrganizationDAO:
#         return OrganizationDAO(self.session)

#     def get_role_dao(self) -> RoleDAO:
#         return RoleDAO(self.session)

#     def get_keystore_dao(self) -> KeyStoreDAO:
#         return KeyStoreDAO(self.session)

#     def get_session_dao(self) -> SessionDAO:
#         return SessionDAO(self.session)

#     def get_acl_dao(self) -> ACLDAO:
#         return ACLDAO(self.session)

#     def get_document_acl_dao(self) -> DocumentACLDAO:
#         return DocumentACLDAO(self.session)

#     def get_organization_acl_dao(self) -> OrganizationACLDAO:
#         return OrganizationACLDAO(self.session)
