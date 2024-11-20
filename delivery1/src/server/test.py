import secrets
from dao.Database import Database
from dao.SubjectDAO import SubjectDAO
from dao.OrganizationDAO import SessionDAO
from dao.OrganizationDAO import OrganizationDAO
from models.status import Status


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
    
    session_key = "12345678"
    
    new_session = session_dao.create(subject_username, org_name, session_key, 0, 20)
    org_subject = organization_dao.get_org_subj_association(org_name, subject_username)
    print()
    print(new_session.subject)  # Subject object corresponding to 'johndoe'
    print(new_session.organization)  # Organization object corresponding to 'ExampleOrg'
    print(new_session.session_roles) # List of Role objects associated with the session
    print(org_subject.status)  # Status of the Organization-Subject association
    
    # Update status
    org_subject = organization_dao.update_org_subj_association_status(org_name, subject_username, Status.SUSPENDED.value)
    
    print(org_subject.status)  # Updated status of the Organization-Subject association
    print()
    
    print("SESSION ENCR KEY: ", session_dao.get_encrypted_key(new_session.id))    
    print("SESSION ENCR KEY: ", session_dao.get_decrypted_key(new_session.id))    
    
    

if __name__ == "__main__":
    main()
