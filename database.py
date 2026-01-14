import os
from dotenv import load_dotenv # New Import
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker


#load the environment variable
load_dotenv()

# 2. GET THE DATABASE URL
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("No DATABASE_URL found in .env file")

# THE ENGINE-> its used for creatung connection with the datavase
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# 4. THE SESSION MAKER
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 5. THE BASE
# al other models(users,clubs) inherit from this base class
#it contains all the imfromation about the table including the metadata and relationship between them.
Base = declarative_base()

# 6. THE DEPENDENCY
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()