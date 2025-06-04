from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from utils.logger import info_logger, error_logger, auth_logger, db_logger
from db.db import Base, engine, get_db
from model.user import User
from schema.user import UserCreate, UserResponse, Token
from typing import Annotated
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, Field

# Security configurations
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key-keep-it-secret"  # In production, use a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password and token functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        error_logger.error(f"Password verification error: {str(e)}")
        auth_logger.error(f"Failed password verification attempt")
        return False

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            auth_logger.warning("Token payload missing email")
            error_logger.warning("JWT token missing email claim")
            raise credentials_exception
    except JWTError as e:
        auth_logger.error(f"JWT validation error: {str(e)}")
        error_logger.error(f"JWT validation failed: {str(e)}")
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

Base.metadata.create_all(bind=engine)
app = FastAPI()

# Templates
templates = Jinja2Templates(directory="templates")

class LoginRequest(BaseModel):
    username: str = Field(..., example="user@example.com", description="Your email address")
    password: str = Field(..., example="yourpassword", description="Your password")

@app.post("/users/", response_model=UserResponse)
def create_user(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
) -> User:
    info_logger.info(f"Attempting to create new user: {email}")
    auth_logger.info(f"New user registration attempt: {email}")
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        auth_logger.warning(f"Attempt to create duplicate user: {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    # Hash the password before saving
    hashed_password = get_password_hash(password)
    db_user = User(name=name, email=email, password=hashed_password)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        info_logger.info(f"Successfully created new user: {email}")
        db_logger.info(f"User added to database: {email}")
        return db_user
    except Exception as e:
        db.rollback()
        error_logger.error(f"Error creating user {email}: {str(e)}")
        db_logger.error(f"Database error while creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user"
        )

@app.post("/token", response_model=Token)
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
) -> dict:
    auth_logger.info(f"Login attempt for user: {username}")
    user = db.query(User).filter(User.email == username).first()
    if not user or not verify_password(password, user.password):
        auth_logger.warning(f"Failed login attempt for user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    auth_logger.info(f"Successful login for user: {username}")
    return {"access_token": access_token, "token_type": "bearer"}
