import secrets
from dao.Database import Database
from dao.SubjectDAO import SubjectDAO


def main():
    db = Database()
    session = db.get_session()
    subject_dao = SubjectDAO(session)
        
    # Clean up
    db.__clear_database__()
    
    subject_dao.create("user1", "User One", "userone@one.one")
    public_key = secrets.token_hex(32)
    

if __name__ == "__main__":
    main()
