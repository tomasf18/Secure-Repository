from .BaseDAO import BaseDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .RoleDAO import RoleDAO
from .OrganizationACLDAO import OrganizationACLDAO
from models.orm import Organization, Subject, OrganizationSubjects, Permission, Role, KeyStore
from sqlalchemy.exc import IntegrityError

class OrganizationDAO(BaseDAO):
    """DAO for managing Organization entities."""

    def create(self, org_name: str, subject_username: str, subject_full_name: str, subject_email: str, pub_key: str) -> Organization:
        """Create a new organization with the subject as the creator and include their public key."""
        subject_dao = SubjectDAO(self.session)
        key_store_dao = KeyStoreDAO(self.session)
        organization_acl_dao = OrganizationACLDAO(self.session)
        role_dao = RoleDAO(self.session)
        
        try:
            # Step 1: Create an Organization
            new_org = Organization(name=org_name)
            self.session.add(new_org)
            
            # Step 2: Retrieve or create the Subject
            try:
                subject = subject_dao.get_by_username(subject_username)
            except ValueError:
                subject = subject_dao.create(subject_username, subject_full_name, subject_email)
            
            # Step 3: Create the public Key in Key Store
            key = key_store_dao.create(pub_key, "public")
            
            # Step 4: Associate Subject with the organization along with their public key
            self.add_subject_with_key(new_org, subject, key)

            # Step 5: Create new OrganizationACL for this Organization
            org_acl = organization_acl_dao.create(org_name)

            # Step 6: Create new Role "Manager" for this OrganizationACL
            manager_role = role_dao.create("Manager", org_acl.id)
            
            # Step 7: Add the creator Subject to the "Manager" Role
            manager_role.subjects.append(subject)  # add the subject to the role

            # Step 8: Add all Permissions for Manager
            permissions = self.session.query(Permission).filter(Permission.name.in_([
                "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", 
                "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", 
                "ROLE_UP", "ROLE_MOD"
            ])).all()

            for permission in permissions:
                manager_role.permissions.append(permission)

            # Commit all changes in one go
            self.session.commit()

            print(f"Organization '{org_name}' created successfully with 'Manager' role for {subject_username}.")
            
            return new_org
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the organization or associating the subject and key.")
        
    def add_subject_with_key(self, org: Organization, subject: Subject, key: KeyStore):
        org.subjects.append(subject)
        self.session.commit()
        print(f"Subject '{subject.username}' added to organization '{org.name}'.")
        
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
            print(f"Organization: {org_subject.org_name}, Subject: {org_subject.username}, Key: {org_subject.pub_key_id}")
        else:
            print(f"Error: Subject '{subject.username}' not found in the organization '{org.name}' after update.")
            
    def get_by_name(self, name: str) -> "Organization":
        """Retrieve an Organization by name."""
        organization = self.session.query(Organization).filter_by(name=name).first()
        if not organization:
            raise ValueError(f"Organization with name '{name}' not found.")
        return organization

    def get_all(self) -> list["Organization"]:
        """Retrieve all Organizations."""
        return self.session.query(Organization).all()
    
    # =========================== Retrieve Subjects associated with an Organization =========================== #
    
    def get_subjects(self, name: str) -> list[Subject]:
        """Retrieve all Subjects associated with an Organization."""
        organization = self.get_by_name(name)
        return [subject for subject in organization.subjects]
    
    def get_subject_by_username(self, org_name: str, username: str) -> Subject:
        """Retrieve a Subject by username associated with an Organization."""
        subject_dao = SubjectDAO(self.session)
        organization = self.get_by_name(org_name)
        subject = subject_dao.get_by_username(username)
        if not subject:
            raise ValueError(f"Subject with username '{username}' not found.")
        if subject not in organization.subjects:
            raise ValueError(f"Subject '{username}' is not associated with the organization '{org_name}'.")
        return subject
    
    # ========================================================================================================= #

    def update(self, name: str, new_name: str = None) -> "Organization":
        """Update an existing Organization's name."""
        organization = self.get_by_name(name)
        if new_name:
            organization.name = new_name
        self.session.commit()
        return organization

    def delete(self, name: str) -> None:
        """Delete an Organization by name."""
        organization = self.get_by_name(name)
        self.session.delete(organization)
        self.session.commit()
        
        
    def verify_creation(self, org_name: str, subject_username: str, pub_key: str):
        # Verify the organization exists
        org = self.session.query(Organization).filter_by(name=org_name).first()
        if not org:
            print("Organization not found!")
            return False
        
        # Verify the subject is associated with the organization
        subject = self.session.query(Subject).filter_by(username=subject_username).first()
        if not subject:
            print("Subject not found!")
            return False

        org_subject = self.session.query(OrganizationSubjects).filter_by(
            org_name=org_name, username=subject_username
        ).first()
        if not org_subject:
            print("Subject is not associated with the organization!")
            return False

        # Verify the public key is associated with the subject
        key_store = self.session.query(KeyStore).filter_by(id=org_subject.pub_key_id).first()
        if not key_store or key_store.key != pub_key:
            print("Public key not found or mismatch!")
            return False

        # Verify the "Manager" role exists and the subject is assigned to it
        role = self.session.query(Role).filter_by(name="Manager", acl_id=org.acl.id).first()
        if not role:
            print("Manager role not found!")
            return False

        if subject not in role.subjects:
            print("Subject not added to Manager role!")
            return False

        # Verify permissions are assigned to the "Manager" role
        permissions = self.session.query(Permission).filter(
            Permission.name.in_([
                "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", 
                "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", 
                "ROLE_UP", "ROLE_MOD"
            ])
        ).all()

        for permission in permissions:
            if permission not in role.permissions:
                print(f"Permission '{permission.name}' not assigned to Manager role!")
                return False

        print("Organization creation and verifications passed!")
        return True
