import secrets
from dao.Database import Database
from dao.SubjectDAO import SubjectDAO
from dao.SessionDAO import SessionDAO
from dao.OrganizationDAO import OrganizationDAO


def main():
    db = Database()
    db.create_session()
    session = db.get_session()
    organization_dao = OrganizationDAO(session)
    session_dao = SessionDAO(session)
    
    org_name = "TestOrg"
    subject_username = "test_user"
    subject_full_name = "Test User"
    subject_email = "testuser@example.com"
    pub_key = "public_key_example_string"
    
    organization_dao.create(org_name, subject_username, subject_full_name, subject_email, pub_key)
    organization_dao.verify_creation(org_name, subject_username, pub_key)
    
    new_session = session_dao.create(subject_username, org_name, secrets.token_hex(64))
    
    print(new_session.subject)  # Subject object corresponding to 'johndoe'
    print(new_session.organization)  # Organization object corresponding to 'ExampleOrg'
    print(new_session.session_roles) # List of Role objects associated with the session
    
    

if __name__ == "__main__":
    main()
