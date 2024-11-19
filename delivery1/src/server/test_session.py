import secrets
from dao.Database import Database
from dao.SubjectDAO import SubjectDAO
from dao.SessionDAO import SessionDAO
from dao.OrganizationDAO import OrganizationDAO


def main():
    # Initialize the database and session
    db = Database()
    db.create_session()
    session = db.get_session()

    # DAOs for testing
    subject_dao = SubjectDAO(session)
    organization_dao = OrganizationDAO(session)
    session_dao = SessionDAO(session)

    # Test data
    org_name = "TestOrg"
    subject_username = "test_user"
    subject_full_name = "Test User"
    subject_email = "testuser@example.com"
    pub_key = "public_key_example_string"

    # Step 1: Create organization and verify creation
    print("Creating organization...")
    organization_dao.create(org_name, subject_username, subject_full_name, subject_email, pub_key)
    organization_dao.verify_creation(org_name, subject_username, pub_key)

    # Step 2: Create session
    print("Creating session...")
    new_session = session_dao.create(subject_username, org_name, secrets.token_hex(64))

    # Step 3: Verify relationships
    print("Verifying session relationships...")
    print("Subject associated with session:", new_session.subject)  # Subject object
    print("Organization associated with session:", new_session.organization)  # Organization object
    print("Key associated with session:", new_session.key.key)  # Role objects (if any)
    print("Roles associated with session:", new_session.session_roles)  # Role objects (if any)

    # Clean-up logic (optional) or test assertions could go here
    print("Test completed.")


if __name__ == "__main__":
    main()
