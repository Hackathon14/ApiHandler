from fastapi import FastAPI, Depends, HTTPException, Path, status
from fastapi.responses import HTMLResponse
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

DATABASE_URL = "mysql://savrbsxwsm:96ZBvOnGP$FvZGVJ@fastapiresmarteco-server:3306/fastapiresmarteco-database"
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
    utilisateur_id: int
    username: str
    password: str
    email: str | None = None
    commune_id: str
    
class Scan(BaseModel):
    meta_data: str
    produit_nom: str
    produit_emprunt_co2: str
    

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
    db.execute(text("INSERT INTO users (username, password, email, commune_id) VALUES (:username, :password, :email, :commune_id)"), {"username": user.username, "password": hashed_password, "email": user.email, "commune_id": user.commune_id})
    db.commit()
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{username}", response_model=User)
async def get_user(username: str, db: SessionLocal = Depends(get_db)):#type: ignore
    user = db.execute(text("SELECT username, email, commune_id FROM users WHERE username = :username"), {"username": username}).fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"username": user.username, "email": user.email, "commune_id": user.commune_id}

@app.get("/scan/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str, db: SessionLocal = Depends(get_db)):#type: ignore
    scan = db.execute(text("SELECT produit_nom, produit_emprunt_co2, meta_data, utilisateur_id, code_barre FROM scans WHERE id = :scan_id"), {"scan_id": scan_id}).fetchone()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"produit_nom": scan.produit_nom, "produit_emprunt_co2": scan.produit_emprunt_co2, "meta_data": scan.meta_data, "utilisateur_id": scan.utilisateur_id, "code_barre": scan.code_barre}

@app.post("/scans", response_model=Scan)
async def create_scan(scan: Scan, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)): # type: ignore
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    user_id = db.execute(text("SELECT id FROM users WHERE username = :username"), {"username": username}).fetchone()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    db.execute(text("INSERT INTO scans (produit_nom, produit_emprunt_co2, meta_data, utilisateur_id, code_barre) VALUES (:produit_nom, :produit_emprunt_co2, :meta_data, :utilisateur_id, :code_barre)"), 
                {"produit_nom": scan.produit_nom, "produit_emprunt_co2": scan.produit_emprunt_co2, "meta_data": scan.meta_data, "utilisateur_id": scan.utilisateur_id, "code_barre": scan.code_barre})
    db.commit()
    return scan



@app.get("/", response_class=HTMLResponse)
async def read_html_file():
    # Lire le contenu du fichier HTML
    file_path = Path("templates/index.html")
    if file_path.exists():
        return HTMLResponse(content=file_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Fichier HTML non trouvé</h1>", status_code=404)