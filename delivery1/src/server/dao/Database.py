from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from models.orm import Base, Permission
from dotenv import load_dotenv
import os


# Load environment variables from .env file
load_dotenv()
DATABASE_PATH = os.getenv("DATABASE_PATH")


# Define the list of permissions
PERMISSIONS = [
    "DOC_ACL",      # Modify the Access Control List
    "DOC_READ",     # Read the file content
    "DOC_DELETE",   # Delete the associated file content
    "ROLE_ACL",     # Modify the ACL
    "SUBJECT_NEW",  # Add a new subject
    "SUBJECT_DOWN", # Suspend a subject
    "SUBJECT_UP",   # Reactivate a subject
    "DOC_NEW",      # Add a new document
    "ROLE_NEW",     # Add a new role
    "ROLE_DOWN",    # Suspend a role
    "ROLE_UP",      # Reactivate a role
    "ROLE_MOD"      # Update a role
]


class Database:
    def __init__(self):
        self.engine = create_engine(f"sqlite:///{DATABASE_PATH}")
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.session = SessionLocal()
        
        Base.metadata.create_all(bind=self.engine)
        self.initialize_permissions()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()
        
    def __clear_database__(self):
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        
    def get_session(self):
        return self.session

    def initialize_permissions(self):
        """
        Initializes all permissions in the database. If a permission already exists, it is not added again.
        """
        existing_permissions = {
            permission.name
            for permission in self.session.scalars(select(Permission)).all()
        }

        new_permissions = [
            Permission(name=permission) 
            for permission in PERMISSIONS 
            if permission not in existing_permissions
        ]
        
        if new_permissions:
            self.session.add_all(new_permissions)
            self.session.commit()
            print(f"Added {len(new_permissions)} new permissions to the database.")
        else:
            print("No new permissions to add; database was already initialized.")

