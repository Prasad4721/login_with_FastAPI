from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()

# Get MySQL connection details from environment variables
username = os.getenv("MYSQL_USERNAME", "root")
password = os.getenv("MYSQL_PASSWORD", "prasad")
host = os.getenv("MYSQL_HOST", "localhost")
port = os.getenv("MYSQL_PORT", "3306")
database = os.getenv("MYSQL_DATABASE", "test")

# Create MySQL URL
DATABASE_URL = f"mysql+pymysql://{username}:{password}@{host}:{port}/{database}"

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,  # Enables automatic reconnection
    pool_recycle=3600,   # Recycle connections after 1 hour
)

# Create declarative base
Base = declarative_base()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

   