from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from delivery1.src.server.orm.ORM import Base, Subject  # Import only necessary schema classes

DATABASE_PATH = '../dao/database/repo.db' 
engine = create_engine(f"sqlite:///{DATABASE_PATH}")

# Now you can interact with the database via SQLAlchemy

# Create all tables (if they don't already exist)
Base.metadata.create_all(engine)

def main():
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create a Subject
    # new_subject = Subject(username="user2", full_name="Ole Doe", email="ole.doe@example.com")
    # session.add(new_subject)
    
    # # Commit changes to the database
    # session.commit()
    
    # Query and print the created Subject
    created_subject = session.query(Subject).filter_by(username="user2").first()
    if created_subject:
        print("\nCreated Subject:")
        print(f" - Username: {created_subject.username}")
        print(f" - Full Name: {created_subject.full_name}")
        print(f" - Email: {created_subject.email}")
    else:
        print("Subject creation failed.")

    # Cleanup (dropping all tables)
    # Base.metadata.drop_all(engine)
    session.close()

if __name__ == "__main__":
    main()
