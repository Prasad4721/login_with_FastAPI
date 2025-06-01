from sqlalchemy import create_engine, text
from sqlalchemy_utils import database_exists, create_database
from db.db import engine, Base, DATABASE_URL
from model.user import User

def init_database():
    try:
        # Create database if it doesn't exist
        if not database_exists(DATABASE_URL):
            create_database(DATABASE_URL)
            print(f"Database created successfully!")

        # Create all tables
        Base.metadata.drop_all(bind=engine)  # Drop existing tables
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully!")
        
    except Exception as e:
        print(f"Error during database initialization: {e}")

if __name__ == "__main__":
    init_database()
