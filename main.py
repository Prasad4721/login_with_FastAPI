from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import logging
from datetime import datetime

# Import loggers
from utils.logger import info_logger, error_logger, auth_logger, db_logger
from db.db import Base, engine, get_db
from model.user import User
from schema.user import UserCreate, UserResponse, UserLogin, Token
from typing import Annotated, List
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt

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

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/thank-you")
async def thank_you_page(request: Request):
    return templates.TemplateResponse("thank_you.html", {
        "request": request
    })

@app.get("/dashboard")
async def dashboard_page(request: Request, current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user
    })

@app.get("/users/", response_model=List[UserResponse])
def get_users(
    db: Annotated[Session, Depends(get_db)]
) -> List[User]:
    users = db.query(User).all()
    return users

@app.post("/users/", response_model=UserResponse)
def create_user(
    user: UserCreate,
    db: Annotated[Session, Depends(get_db)]
) -> User:
    info_logger.info(f"Attempting to create new user: {user.email}")
    auth_logger.info(f"New user registration attempt: {user.email}")
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        auth_logger.warning(f"Attempt to create duplicate user: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    # Hash the password before saving
    hashed_password = get_password_hash(user.password)
    db_user = User(name=user.name, email=user.email, password=hashed_password)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        info_logger.info(f"Successfully created new user: {user.email}")
        db_logger.info(f"User added to database: {user.email}")
        return db_user
    except Exception as e:
        db.rollback()
        error_logger.error(f"Error creating user {user.email}: {str(e)}")
        db_logger.error(f"Database error while creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user"
        )

@app.post("/token", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)]
) -> dict:
    auth_logger.info(f"Login attempt for user: {form_data.username}")
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        auth_logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    auth_logger.info(f"Successful login for user: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    auth_logger.info(f"User data accessed: {current_user.email}")
    return current_user
