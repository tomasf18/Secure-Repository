from .BaseDAO import BaseDAO
from .SubjectDAO import SubjectDAO
from .KeyStoreDAO import KeyStoreDAO
from .RoleDAO import RoleDAO
from .OrganizationACLDAO import OrganizationACLDAO
from models.orm import Organization, Subject, OrganizationSubjects, RolePermissions, Permission, RoleSubjects
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
            self.session.commit()
            
            # Step 2: Retrieve or create the Subject
            subject = self.session.query(Subject).filter_by(username=subject_username).first()
            if not subject:
                subject_dao.create(subject_username, subject_full_name, subject_email)
            
            # Step 3: Create the public Key in Key store
            key = key_store_dao.create(pub_key, "public")
            
            # Step 4: Associate Subject with the organization along with their public key
            new_org.subjects.append(subject)  # add the subject to the organization

            # Insert into OrganizationSubjects table
            self.session.execute(
                OrganizationSubjects.insert().values(
                    org_name=org_name,
                    username=subject_username,
                    pub_key_id=key.id
                )
            )
            self.session.commit()

            # Step 5: Create new OrganizationACL for this Organization
            org_acl = organization_acl_dao.create(org_name)
            self.session.commit()

            # Step 6: Create new Role "Manager" for this OrganizationACL
            manager_role = role_dao.create("Manager", org_acl.id)

            # Step 7: Add the creator Subject to the "Manager" Role
            self.session.execute(
                RoleSubjects.insert().values(
                    role_id=manager_role.id,
                    username=subject_username
                )
            )
            self.session.commit()

            # Step 8: Add all Permissions for Manager
            permissions = self.session.query(Permission).filter(Permission.name.in_([
                "DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", 
                "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", 
                "ROLE_UP", "ROLE_MOD"
            ])).all()

            for permission in permissions:
                self.session.execute(
                    RolePermissions.insert().values(
                        role_id=manager_role.id,
                        permission_name=permission.name
                    )
                )
            self.session.commit()

            print(f"Organization '{org_name}' created successfully with 'Manager' role for {subject_username}.")
            
            return new_org
        except IntegrityError:
            self.session.rollback()
            raise ValueError("Error while creating the organization or associating the subject and key.")

    def get_by_name(self, name: str) -> "Organization":
        """Retrieve an Organization by name."""
        organization = self.session.query(Organization).filter_by(name=name).first()
        if not organization:
            raise ValueError(f"Organization with name '{name}' not found.")
        return organization

    def get_all(self) -> list["Organization"]:
        """Retrieve all Organizations."""
        return self.session.query(Organization).all()

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
