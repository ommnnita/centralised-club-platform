from pydantic import BaseModel,EmailStr
from datetime import datetime
from typing import Optional, List
import models

#defining the schema for user related operations(like signup,login etc)
#schema for signiup the new user:
class UserBase(BaseModel):
    email:EmailStr
    full_name:str
#schema for creating the user
class UserCreate(UserBase):
    password: str

#schma for storing the user details once he is signed in
class UserOut(UserBase):
    id:int
    system_role:models.SystemRole
    class Config:
        from_attributes = True # to tell pydantic that the data will come from an ORM model
        #alternatively we can use orm_mode = True

#schema for login
class UserLogin(BaseModel):
    email:EmailStr
    password:str

class Token(BaseModel):
    access_token:str
    token_type:str

## defing the schemas for the club
class ClubBase(BaseModel):
    name: str
    description: Optional[str] = None
class ClubCreate(ClubBase):
    pass