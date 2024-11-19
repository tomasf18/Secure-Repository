from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from models.orm import Base, Permission, Repository
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
        self.session = None

        self.reset()

    def __enter__(self):
        return self

    def close_session(self):
        self.session.close()
        
    def reset(self):
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)    
        self.create_session()
        self.initialize_repository()
        self.initialize_permissions()
        self.close_session()
    
    def create_session(self):
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.session = SessionLocal()
    
    def get_session(self):
        return self.session
    
    def initialize_repository(self):
        # Create a new repository com as chaves
        private_key = open(os.getenv("REP_PRIV_KEY_FILE")).read()
        public_key = open(os.getenv("REP_PUB_KEY_FILE")).read()

        existing_permissions = {
            permission.name
            for permission in self.session.scalars(select(Repository)).all()
        }

        if len(existing_permissions) == 0:
            repository = Repository(private_key=private_key, public_key=public_key)
            self.session.add(repository)
            self.session.commit()
            print("Added repository keys")
        else:
            print("Database already has keys")
        

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

