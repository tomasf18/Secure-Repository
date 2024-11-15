from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from orm import Base, Subject  # Import only necessary schema classes

# Setup the database engine (SQLite in-memory for testing purposes)
engine = create_engine("sqlite:///:memory:")

# Create all tables
Base.metadata.create_all(engine)

def main():
    with Session(engine) as session:
        # Create a Subject
        new_subject = Subject(username="user1", full_name="John Doe", email="john.doe@example.com")
        session.add(new_subject)
        
        # Commit changes to the database
        session.commit()
        
        # Query and print the created Subject
        created_subject = session.query(Subject).filter_by(username="user1").first()
        if created_subject:
            print("\nCreated Subject:")
            print(f" - Username: {created_subject.username}")
            print(f" - Full Name: {created_subject.full_name}")
            print(f" - Email: {created_subject.email}")
        else:
            print("Subject creation failed.")

    # Cleanup (dropping all tables)
    Base.metadata.drop_all(engine)

if __name__ == "__main__":
    main()
