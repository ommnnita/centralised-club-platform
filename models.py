from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from database import Base

#DEFINING THE ENUMS(CONSTRAIANED CHOICES) -> SystemRole,ClubRole,ActivityStatus
class SystemRole(str,enum.Enum):
    STUDENT="student"
    SUPER_ADMIN="super_admin"

class ClubRole(str,enum.Enum):
    MEMBER="member"
    ADMIN="admin"

class ActivityState(str,enum.Enum):
    CREATED="created"
    APPROVED="approved"
    COMPLETED="completed"

#The tables for the databse->User,clubs,membership,activity,attendence
#columns in users:id(primary key),full_name,email,password_hash,system_role
class User(Base):
    __tablename__="users"
    id=Column(Integer,primary_key=True,index=True)
    full_name=Column(String,nullable=False)
    email=Column(String,unique=True,index=True,nullable=False)
    password_hash=Column(String,nullable=False)

    #to know about how many clubs does a user is a part of , we define relationship
    memberships=relationship("Membership",back_populates="student")

    # to know the attendace record of the user for all the activites that has been conducted yet.
    attendance_records=relationship("Attendance",back_populates="student")

# columns:id, name ,description
class Club(Base):
    __tablename__ = "clubs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True,nullable=False)
    description = Column(String)

    #to know about all the members of the club
    membership=relationship("Membership",back_populates="club")

    #to know about all the activities of the club:
    activities = relationship("Activity", back_populates="club")

#columns for membership:id(primary),user_id(foreign id),club_id(foreign_id),role,joined_at
class Membership(Base):
    """
    The Association Object.
    This table links Users to Clubs AND stores their rank.
    """
    __tablename__ = "memberships"

    id = Column(Integer, primary_key=True, index=True)
    #foriegn key establish connection between tables in database
    user_id = Column(Integer, ForeignKey("users.id"))
    club_id = Column(Integer, ForeignKey("clubs.id"))

    role = Column(Enum(ClubRole), default=ClubRole.MEMBER)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())


    # Relationships
    student = relationship("User", back_populates="memberships")
    club = relationship("Club", back_populates="membership")

    #columns for activity:id,title,description,club_id,is_public,state,event_time
class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String)
    club_id = Column(Integer, ForeignKey("clubs.id"))

    # to incorporate internal sessions ->
    is_public = Column(Boolean, default=False) 

    state = Column(Enum(ActivityState), default=ActivityState.CREATED)
    event_time = Column(DateTime(timezone=True))

    # Relationships
    club = relationship("Club", back_populates="activities")

    #to know the attendance log of an activity we have
    attendance_logs = relationship("Attendance", back_populates="activity")

#id , user_id,activity_id,scan_time,status
class Attendance(Base):
    __tablename__ = "attendance"


    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    activity_id = Column(Integer, ForeignKey("activities.id"))


    scan_time = Column(DateTime(timezone=True), server_default=func.now())

    
    # Relationships
    student = relationship("User", back_populates="attendance_records")
    activity = relationship("Activity", back_populates="attendance_logs")