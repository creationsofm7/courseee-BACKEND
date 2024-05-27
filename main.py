from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from pymongo import MongoClient
from typing import List, Annotated, Union
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
from mangum import Mangum
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Annotated, Union
from pymongo.errors import DuplicateKeyError

import jwt
from jwt.exceptions import InvalidTokenError


SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")




def document_to_dict(document):
    # Convert ObjectId to str
    document['_id'] = str(document['_id'])
    return document


app = FastAPI()
handler = Mangum(app)


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# MongoDB connection details (replace with your credentials)
MONGO_URI = os.getenv('URI')
MONGO_DATABASE = "syllabus_creator"
MONGO_COLLECTION = "courses"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[MONGO_DATABASE]
syllabus_collection = db[MONGO_COLLECTION]  # Assuming your collection is named "courses"
users_collection = db['users'] 
# ADD cant add two same name courses option okay?





# Define Pydantic models for data validation
class Instructor(BaseModel):
    name: str
    email: str
    office_hours: str

class Resource(BaseModel):
    type: str
    title: str
    link: str  # assuming link for online resources

class Assignment(BaseModel):
    type: str
    title: str
    due_date: str
    description: str

class Topic(BaseModel):
    topic_name: str
    description: str
    resources: List[Resource] | None = None  # Optional resources field
    assignments: List[Assignment] | None = None  # Optional assignments field

class Course(BaseModel):
    course_name: str
    course_code: str
    instructor: Instructor | None = None  # Optional instructor field
    description: str
    learning_objectives: List[str]
    topics: List[Topic]









SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str




class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    disabled: bool = False
    users_collection.create_index("username", unique=True)


def get_password_hash(password: str):
    return pwd_context.hash(password)

def create_user(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    new_user = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "disabled": user.disabled,
    }
    users_collection.insert_one(new_user)
  











def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user_dict = users_collection.find_one({"username": username})
    if user_dict:
        return UserInDB(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(user_id: str, expires_delta: Union[timedelta, None] = None):
    to_encode = {"sub": user_id}
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user = get_user(user_id)
        if user is None:
            raise credentials_exception
        token_data = TokenData(username=user.username)
    except InvalidTokenError:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



















@app.post("/users/", response_model=UserInDB)
def create_new_user(user: UserCreate):
    try:
        create_user(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Username already in use")
    return UserInDB(**user.dict(), hashed_password=get_password_hash(user.password))



@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        user_id=user.username, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]





























# Function to connect to MongoDB on each request (optional, can use connection pool)
def get_db():
    return syllabus_collection



#STAY AWAY FROM THESE


    
@app.post("/courses/")
def create_course(token: Annotated[str, Depends(oauth2_scheme)], course: Course, db: MongoClient = Depends(get_db)):
    # Insert course data into the collection
    db.insert_one(course.dict())
    return {"message": "Course created successfully!"}


@app.get("/courses/{course_code}")
def get_course(course_code: str, db: MongoClient = Depends(get_db)):
    # Find course by course_code
    course = db.find_one({"course_code": course_code})
    if course:
        return document_to_dict(course)
    else:
        return {"message": "Course not found"}
    
@app.get("/courses/{course_code}/topics")
def get_topics(course_code: str, db: MongoClient = Depends(get_db)):
    # Find course by course_code
    course = db.find_one
    topics = db.find_one({"course_code": course_code}, {"topics": 1})
    if topics:
        return document_to_dict(topics)
    else:
        return {"message": "Topics not found"}
    

@app.get("/courses/{course_code}/topics/{topic_name}/resources")
def get_resources(course_code: str, topic_name: str, db: MongoClient = Depends(get_db)):
    # Find course by course_code
    course = db.find_one
    resources = db.find_one({"course_code": course_code, "topics.topic_name": topic_name}, {"topics.resources": 1})
    if resources:
        return document_to_dict(resources)
    else:
        return {"message": "Resources not found"}
    

@app.put("/courses/{course_code}")
def update_course(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, course: Course, db: MongoClient = Depends(get_db)):
    # Update course data in the collection
    db.update_one({"course_code": course_code}, {"$set": course.dict()})
    return {"message": "Course updated successfully!"}

@app.put("/courses/{course_code}/topics")
def add_topic(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, topic: Topic, db: MongoClient = Depends(get_db)):
        # Add a new topic to the course
    db.update_one({"course_code": course_code}, {"$push": {"topics": topic.dict()}})
    return {"message": "Topic added successfully!"}

@app.put("/courses/{course_code}/topics/{topic_name}/resources")
def add_resource(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, topic_name: str, resource: Resource, db: MongoClient = Depends(get_db)):
        # Add a new resource to a specific topic in the course
    db.update_one({"course_code": course_code, "topics.topic_name": topic_name}, {"$push": {"topics.$.resources": resource.dict()}})
    return {"message": "Resource added successfully!"}

@app.put("/courses/{course_code}/topics/{topic_name}/assignments")
def add_assignment(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, topic_name: str, assignment: Assignment, db: MongoClient = Depends(get_db)):
        # Add a new assignment to a specific topic in the course
    db.update_one({"course_code": course_code, "topics.topic_name": topic_name}, {"$push": {"topics.$.assignments": assignment.dict()}})
    return {"message": "Assignment added successfully!"}

@app.delete("/courses/{course_code}/topics/{topic_name}/")
def delete_topic(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, topic_name: str, db: MongoClient = Depends(get_db)):
    # Delete a topic from the course
    db.update_one({"course_code": course_code}, {"$pull": {"topics": {"topic_name": topic_name}}})
    return {"message": "Topic deleted successfully!"}

@app.delete("/courses/{course_code}/topics/{topic_name}/resources/{resource_title}")
def delete_resource(token: Annotated[str, Depends(oauth2_scheme)],course_code: str, topic_name: str, resource_title: str, db: MongoClient = Depends(get_db)):
    # Delete a resource from a specific topic in the course
    db.update_one({"course_code": course_code, "topics.topic_name": topic_name}, {"$pull": {"topics.$.resources": {"title": resource_title}}})
    return {"message": "Resource deleted successfully!"}



@app.get("/course/")
def get_all_courses(db: MongoClient = Depends(get_db)):
    # Get all courses from the collection
    courses = db.find({})
    return [document_to_dict(course) for course in courses]





# Add API endpoints for updating, deleting courses, managing instructors etc. (refer to FastAPI documentation)

