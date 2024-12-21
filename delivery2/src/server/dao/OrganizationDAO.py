from dotenv import load_dotenv

from .BaseDAO import BaseDAO
from .RoleDAO import RoleDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .OrganizationACLDAO import OrganizationACLDAO

from models.database_orm import Organization, Subject, OrganizationSubjects, Permission, Role, KeyStore

from sqlalchemy.exc import IntegrityError


load_dotenv()

class OrganizationDAO(BaseDAO):
    """DAO for managing Organization entities."""
    
    def __init__(self, session):
        super().__init__(session)
        self.subject_dao = SubjectDAO(session)
        self.key_store_dao = KeyStoreDAO(session)
        self.organization_acl_dao = OrganizationACLDAO(session)
        self.role_dao = RoleDAO(session)

# -------------------------------

    def create(self, org_name: str, subject_username: str, subject_full_name: str, subject_email: str, subject_pub_key: bytes) -> Organization:
        """Create a new organization with the subject as the creator and include their public key."""
        
        try:
            # Step 1: Create an Organization
            new_org = Organization(name=org_name)
            self.session.add(new_org)
            
            # Step 2: Retrieve or create the Subject
            try:
                subject = self.subject_dao.get_by_username(subject_username)
            except ValueError:
                subject = self.subject_dao.create(subject_username, subject_full_name, subject_email)
            
            # Step 3: Create the public Key in Key Store
            key = self.key_store_dao.create(subject_pub_key, "public")
            
            # Step 4: Associate Subject with the organization along with their public key
            self.add_subject_with_key(new_org, subject, key)

            # Step 5: Create new OrganizationACL for this Organization
            org_acl = self.organization_acl_dao.create(org_name)

            # Step 6: Create new Role "Manager" for this OrganizationACL
            manager_role = self.role_dao.create("Manager", org_acl.id)
            
            # Step 7: Add the creator Subject to the "Manager" Role
            manager_role.subjects.append(subject)  # add the subject to the role

            # Step 8: Add all Organization Permissions for Manager (except DOC_ACL, DOC_READ, DOC_DELETE, which are for Document)
            permissions = self.session.query(Permission).filter(Permission.name.in_([
                "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
            ])).all()

            for permission in permissions:
                manager_role.permissions.append(permission)

            # Commit all changes in one go
            self.session.commit()

            print(f"Organization '{org_name}' created successfully with 'Manager' (id: {manager_role.id}) role for {subject_username}.")
            
            return new_org
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the organization or associating the subject and key.")

# -------------------------------

    def get_all(self) -> list["Organization"]:
        """Retrieve all Organizations."""
        return self.session.query(Organization).all()

# -------------------------------
    
    def get_subjects(self, name: str) -> list[Subject]:
        """Retrieve all Subjects associated with an Organization."""
        organization = self.get_by_name(name)
        return [subject for subject in organization.subjects]
        
# -------------------------------
    
    def get_subject_by_username(self, org_name: str, username: str) -> Subject:
        """Retrieve a Subject by username associated with an Organization."""
        organization = self.get_by_name(org_name)
        subject = self.subject_dao.get_by_username(username)
        if not subject:
            raise ValueError(f"Subject with username '{username}' not found.")
        if subject not in organization.subjects:
            raise ValueError(f"Subject '{username}' is not associated with the organization '{org_name}'.")
        return subject
    
# -------------------------------
    
    # Auxiliar function to add a Subject to an Organization with their public key
    def add_subject_with_key(self, org: Organization, subject: Subject, key: KeyStore):
        """ Add a Subject to an Organization with their public key. """
        org.subjects.append(subject)
        self.session.commit()
        
        if key and key.id:
            # Update the public key for the subject in the organization
            stmt = OrganizationSubjects.update().where(
                (OrganizationSubjects.c.org_name == org.name) &
                (OrganizationSubjects.c.username == subject.username)
            ).values(pub_key_id=key.id)
            self.session.execute(stmt)
            self.session.commit()
            print(f"Public key {key.id} associated with subject '{subject.username}' in organization '{org.name}'.")
        else:
            print(f"Error: Public key not available for subject '{subject.username}'.")
        
        self.session.refresh(org)
        org_subject = self.session.query(OrganizationSubjects).filter_by(
            org_name=org.name, username=subject.username
        ).first()
        
        if org_subject:
            print(f"Subject '{subject.username}' added to organization '{org.name}'.")
        else:
            print(f"Error: Could not add Subject '{subject.username}' to the organization '{org.name}'.")

            
    def add_subject_to_organization(self, org_name: str, subject_username: str, subject_full_name: str, subject_email: str, subject_pub_key: bytes) -> Subject:
        """Add a Subject to an Organization."""
        org = self.get_by_name(org_name)
        
        try:
            new_subject = self.subject_dao.get_by_username(subject_username)
        except ValueError:
            new_subject = self.subject_dao.create(subject_username, subject_full_name, subject_email)

        if new_subject in org.subjects:
            raise ValueError(
                f"Subject with username '{subject_username}' or email '{subject_email}' already exists."
            )
        
        key = self.key_store_dao.create(subject_pub_key, "public")
        self.add_subject_with_key(org, new_subject, key)
        
# -------------------------------
            
    def get_by_name(self, name: str) -> "Organization":
        """Retrieve an Organization by name."""
        organization = self.session.query(Organization).filter_by(name=name).first()
        if not organization:
            raise ValueError(f"Organization with name '{name}' not found.")
        return organization
    
# -------------------------------
    
    def get_org_subj_association(self, org_name: str, username: str):
        """Retrieve the Organization-Subject association."""
        org_subject = self.session.query(OrganizationSubjects).filter_by(org_name=org_name, username=username).first()
        if not org_subject:
            raise ValueError(f"Subject '{username}' is not associated with the organization '{org_name}'.")
        return org_subject
    
# -------------------------------
    
    def update_org_subj_association_status(self, org_name: str, username: str, new_status: str):
        """Update the Organization-Subject association."""
        stmt = OrganizationSubjects.update().where(
            (OrganizationSubjects.c.org_name == org_name) &
            (OrganizationSubjects.c.username == username)
        ).values(status=new_status)
        self.session.execute(stmt)
        self.session.commit()
        
        return self.get_org_subj_association(org_name, username)

# -------------------------------

    def subject_has_role(self, org_name: str, username: str, role_name: str) -> bool:
        """Check if a Subject has a Role in an Organization."""
        organization = self.get_by_name(org_name)
        subject = self.subject_dao.get_by_username(username)
        role = self.role_dao.get_by_name_and_acl_id(role_name, organization.acl.id)
        
        return subject in role.subjects