import os
from dotenv import load_dotenv

from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .KeyStoreDAO import KeyStoreDAO
from models.database_orm import Base, Permission, Repository


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
    def __init__(self, reset: bool = False):
        self.engine = create_engine(f"sqlite:///{DATABASE_PATH}")
        self.session = None

        if reset:
            self.reset()
        else:
            self.startup()

    def __enter__(self):
        return self

    def close_session(self):
        self.session.close()
        
    def startup(self):
        Base.metadata.create_all(bind=self.engine)    
        self.create_session()
        self.initialize_repository()
        self.initialize_permissions()
        self.close_session()

    def reset(self):
        Base.metadata.drop_all(bind=self.engine)
        self.startup()

    def create_session(self):
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.session = SessionLocal()
    
    def get_session(self):
        return self.session
    
    def initialize_repository(self):
        # Create a new repository with the keys
        key_store_dao = KeyStoreDAO(self.session)
        
        private_key = open(os.getenv("REP_PRIV_KEY_FILE")).read()
        public_key = open(os.getenv("REP_PUB_KEY_FILE")).read()
        
        rep_pub_key = key_store_dao.create(public_key.encode(), "public")
        rep_encrypted_priv_key = key_store_dao.create(private_key.encode(), "repository_private") # Already encrypted by the password

        repository = Repository(public_key_id=rep_pub_key.id, private_key_id=rep_encrypted_priv_key.id)
        self.session.add(repository)
        self.session.commit()

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

