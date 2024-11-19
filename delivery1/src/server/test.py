import secrets
from dao.Database import Database
from dao.SubjectDAO import SubjectDAO
from dao.OrganizationDAO import OrganizationDAO


def main():
    db = Database()
    db.create_session()
    session = db.get_session()
    organization_dao = OrganizationDAO(session)
    
    org_name = "TestOrg"
    subject_username = "test_user"
    subject_full_name = "Test User"
    subject_email = "testuser@example.com"
    pub_key = "public_key_example_string"
    
    organization_dao.create(org_name, subject_username, subject_full_name, subject_email, pub_key)
    organization_dao.verify_creation(org_name, subject_username, pub_key)
    
    
    

if __name__ == "__main__":
    main()
