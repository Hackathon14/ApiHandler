from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import KeyGenerator as keygen
import uvicorn
import jwt
import datetime
from passlib.context import CryptContext

app = FastAPI()
key = keygen.KeyGenerator()

DATABASE_URL = "mysql+pymysql://username:password@127.0.0.1/dbname"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# JWT settings
SECRET_KEY = key.get_symmetric_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password: str
    email: str | None = None
    ville: str
    
class Scan(BaseModel):
    producname: str
    emprunt_carborne: str
    packagin: str
    image: str

def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# routes

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)): # type: ignore
    user = db.execute(text("SELECT * FROM users WHERE username = :username"), {"username": form_data.username}).fetchone()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", response_model=Token)
async def register(user: User, db: SessionLocal = Depends(get_db)): #type: ignore
    hashed_password = get_password_hash(user.password)
    db.execute(text("INSERT INTO users (username, password, email, ville) VALUES (:username, :password, :email, :ville)"), {"username": user.username, "password": hashed_password, "email": user.email, "ville": user.ville})
    db.commit()
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{username}", response_model=User)
async def get_user(username: str, db: SessionLocal = Depends(get_db)):#type: ignore
    user = db.execute(text("SELECT username, email, ville FROM users WHERE username = :username"), {"username": username}).fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"username": user.username, "email": user.email, "ville": user.ville}

@app.post("/scans", response_model=Scan)
async def create_scan(scan: Scan, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)): # type: ignore
    db.execute(text("INSERT INTO scans (producname, emprunt_carborne, packagin, image) VALUES (:producname, :emprunt_carborne, :packagin, :image)"), 
                {"producname": scan.producname, "emprunt_carborne": scan.emprunt_carborne, "packagin": scan.packagin, "image": scan.image})
    db.commit()
    return scan

@app.get("/data")
async def read_data(token: str = Depends(oauth2_scheme)):
    # Dummy data passthrough, replace with actual data fetching logic
    with engine.connect() as connection:
        result = connection.execute(text("SELECT * FROM your_table"))
        data = result.fetchall()
    return {"data": data}

