import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import jwt
import datetime
from passlib.context import CryptContext
from mangum import Mangum  # Pour GCF
import uvicorn

# --- Configuration de l'application ---
app = FastAPI()

DATABASE_URL = "mysql+pymysql://lophias:EqHVe0`VFEA32zsC@/cloudsql/hackeco-recycli:europe-west9-a:hackeco-recycli/recycli"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# JWT settings
SECRET_KEY = "mysecretkey"  # Remplacez par une clé sécurisée (via variable d'environnement si possible)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Modèles Pydantic ---
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    id: int
    nom: str
    prenom: str
    email: str
    role: str

class RegisterUser(BaseModel):
    nom: str
    prenom: str
    email: str
    password: str
    commune_id: int

# --- JWT Helper ---
def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- Routes FastAPI ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = db.execute(
        text("SELECT * FROM utilisateurs WHERE email = :email"),
        {"email": form_data.username}
    ).fetchone()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
async def register_user(user: RegisterUser, db: SessionLocal = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db.execute(
        text("INSERT INTO utilisateurs (nom, prenom, email, password, commune_id, role) VALUES (:nom, :prenom, :email, :password, :commune_id, :role)"),
        {"nom": user.nom, "prenom": user.prenom, "email": user.email, "password": hashed_password, "commune_id": user.commune_id, "role": "user"}
    )
    db.commit()
    return {"message": "User registered successfully"}

@app.get("/users/{id}", response_model=User)
async def get_user_by_id(id: int, db: SessionLocal = Depends(get_db)):
    user = db.execute(
        text("SELECT id, nom, prenom, email, role FROM utilisateurs WHERE id = :id"),
        {"id": id}
    ).fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"id": user.id, "nom": user.nom, "prenom": user.prenom, "email": user.email, "role": user.role}

@app.get("/communes")
async def get_communes(db: SessionLocal = Depends(get_db)):
    communes = db.execute(text("SELECT * FROM commune")).fetchall()
    return {"communes": [dict(row) for row in communes]}

@app.get("/scans/{user_id}")
async def get_scans_for_user(user_id: int, db: SessionLocal = Depends(get_db)):
    scans = db.execute(
        text("SELECT * FROM scans WHERE utilisateur_id = :user_id"),
        {"user_id": user_id}
    ).fetchall()
    return {"scans": [dict(row) for row in scans]}

# --- Point d'entrée pour GCF ---
handler = Mangum(app)