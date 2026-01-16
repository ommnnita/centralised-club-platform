from fastapi import FastAPI
from database import engine, Base
import models # We import models so SQLAlchemy "sees" them

# 1. CREATE TABLES
# This line says: "Look at all classes in models.py and create tables for them in the DB"
# If the tables already exist, it does nothing.
Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "The Backend is running!"}