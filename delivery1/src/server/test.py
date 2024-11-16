from dao.Database import Database
from dao.SubjectDAO import SubjectDAO


def main():
    db = Database()
    session = db.get_session()
    subject_dao = SubjectDAO(session)
    
    subject_dao.create("test", "Test User", "testuser@test.com")
    
    print(subject_dao.get_by_username("test"))
    
    

if __name__ == "__main__":
    main()
