from fastapi import FastAPI,Depends, HTTPException, status
from database import engine, Base, get_db
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm#to accept teh form_data
from jose import JWTError, jwt
import models # We import models so SQLAlchemy "sees" them
import schemas
import auth

# 1. CREATE TABLES
# This line says: "Look at all classes in models.py and create tables for them in the DB"
# If the tables already exist, it does nothing.
Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "The Backend is running!"}

# going to define the signup logic : Signup: Accept JSON → Hash Password → Save to DB.
@app.post("/signup", response_model=schemas.UserOut)#setting the responsemodel so that the server doesnt send any
#confidential data to the frontend.
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    # this will  first try to look whether a person with the provoded email already exist or not?
    if db_user:
        # If found, stop everything and throw a 400 Error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )
        # hashing the password before storing it in the db
    hashed_pw = auth.get_password_hash(user.password)
    #creating the row for the User table in the databse
    new_user = models.User(
    email=user.email,
    password_hash=hashed_pw, # Storing the hash, NOT the password
    full_name=user.full_name,
    system_role=models.SystemRole.STUDENT
    )

    db.add(new_user)
    db.commit()      # Save permanently
    db.refresh(new_user) # Refreshing to get the generated ID
    return new_user

# defining the login ENdpoint:Accept JSON → Verify Password → Generate Token.
@app.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    
    # NOTICE: The "Authorize" button sends the email inside a field called 'username'
    user = db.query(models.User).filter(models.User.email == form_data.username).first()

    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(
        data={"sub": str(user.id), "role": user.system_role.value}
    )

    return {"access_token": access_token, "token_type": "bearer"}

#setting the flow for the club and actity
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
#this extract the token from the http request


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    #dependece provide control acess to oauth2_schema
    #depndece control lifecycly of get_db
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token using the Secret Key
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])

        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    # Check if this user actually exists in the DB
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

#the club creation endpoint

@app.post("/clubs", response_model=schemas.ClubOut)
def create_club(
    club: schemas.ClubCreate, 
    # v-- THE DEPENDENCY: Validates token & gives us the User object
    current_user: models.User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # 1. Check if Club Name exists (Unique Constraint)
    db_club = db.query(models.Club).filter(models.Club.name == club.name).first()
    if db_club:
        raise HTTPException(status_code=400, detail="Club name already taken")

    # 2. Create the Club
    new_club = models.Club(
        name=club.name,
        description=club.description
    )
    db.add(new_club)
    db.commit()      # We commit to generate the Club ID
    db.refresh(new_club)

    # 3. THE CHAIN REACTION (Assign Admin)
    # We automatically create a Membership for the Creator with role='admin'
    admin_membership = models.Membership(
        user_id=current_user.id,
        club_id=new_club.id,
        role=models.ClubRole.ADMIN
    )
    db.add(admin_membership)
    db.commit() # Save the membership

    return new_club