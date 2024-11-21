import secrets
from dao.Database import Database
# from dao.SubjectDAO import SubjectDAO
from dao.DocumentDAO import DocumentDAO
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
    
    doc_name = "test_document"
    sessionId = new_session.id
    encrypted_data = "encrypted_data".encode()
    alg = "AES-CBC"
    metadata_file_key = "passphrase"
    metadata_iv = secrets.token_hex(16)
    document = organization_dao.create_document(doc_name, sessionId, encrypted_data, alg, metadata_file_key, metadata_iv)
                                     
    print()

    print("ENCR METAD KEY: ", organization_dao.get_encrypted_key(document.id).hex())
    print("DECR METAD IV: ", organization_dao.get_decrypted_key(document.id))

if __name__ == "__main__":
    main()
