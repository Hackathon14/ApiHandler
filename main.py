from fastapi import FastAPI, Depends, HTTPException, Path, status, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
import KeyGenerator as keygen
import uvicorn
import jwt
import datetime
from passlib.context import CryptContext
from pathlib import Path

app = FastAPI()
key = keygen.KeyGenerator()

DATABASE_URL = "mysql+pymysql://u425187614_hackaton:Hackaton2025@srv516.hstgr.io:3306/u425187614_hackaton"
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600  # Recycle connections every hour
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
        print("DB connection successful")
    except Exception as e:
        print(f"DB connection error: {e}")
        raise
    finally:
        db.close()
        print("DB connection closed")

# JWT settings
SECRET_KEY = key.get_symmetric_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    nom: str
    prenom: str
    password: str
    email: str
    commune_id: str
    
class Scan(BaseModel):
    meta_data: str
    produit_nom: str
    produit_emprunt_co2: str
    code_barre: str
    utilisateur_id: int
    

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

class OAuth2PasswordRequestFormWithEmail(OAuth2PasswordRequestForm):
    def __init__(
        self,
        grant_type: str = Form(None, regex="password"),
        username: str = Form(None),  # Make username optional
        password: str = Form(...),
        scope: str = Form(""),
        client_id: str = Form(None),
        client_secret: str = Form(None),
        email: str = Form(...)
    ):
        super().__init__(grant_type=grant_type, username=username, password=password, scope=scope, client_id=client_id, client_secret=client_secret)
        self.email = email

# routes

@app.post("/login", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestFormWithEmail = Depends(), db: SessionLocal = Depends(get_db)): # type: ignore
    user = db.execute(text("SELECT * FROM utilisateurs WHERE email = :email"), {"email": form_data.email}).fetchone()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.email}, expires_delta=access_token_expires
    )
    request.session['session'] = access_token
    print(f"Session set: {request.session['session']}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", response_model=Token)
async def register(request: Request, user: User, db: SessionLocal = Depends(get_db)): #type: ignore
    hashed_password = get_password_hash(user.password)
    db.execute(text("INSERT INTO utilisateurs (nom, prenom, password, email, commune_id) VALUES (:nom, :prenom, :password, :email, :commune_id)"), {"nom": user.nom, "prenom": user.prenom,  "password": hashed_password, "email": user.email, "commune_id": user.commune_id})
    db.commit()
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    request.session['session'] = access_token
    print(f"Session set: {request.session['session']}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{id}", response_model=User)
async def get_user(id: str, db: SessionLocal = Depends(get_db)):#type: ignore
    user = db.execute(text("SELECT nom, prenom, email, commune_id FROM utilisateurs WHERE id = :id"), {"id": id}).fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"nom": user.nom, "prenom" : user.prenom, "email": user.email, "commune_id": user.commune_id, "id": id}

@app.get("/scan/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str, db: SessionLocal = Depends(get_db)):#type: ignore
    scan = db.execute(text("SELECT produit_nom, produit_emprunt_co2, meta_data, utilisateur_id, code_barre FROM scans WHERE id = :scan_id"), {"scan_id": scan_id}).fetchone()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"produit_nom": scan.produit_nom, "produit_emprunt_co2": scan.produit_emprunt_co2, "meta_data": scan.meta_data, "utilisateur_id": scan.utilisateur_id, "code_barre": scan.code_barre}

@app.get("/my_page")
async def get_my_page(request: Request, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):#type: ignore
    token = request.headers.get("Authorization")
    if token is None or not token.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    token = token[len("Bearer "):]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    email: str = payload.get("sub")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    user = db.execute(text("SELECT * FROM utilisateurs WHERE email = :email"), {"email": email}).fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"nom": user.nom, "prenom" : user.prenom, "email": user.email, "commune_id": user.commune_id, "id": user.id}
    

@app.post("/scans", response_model=Scan)
async def create_scan(request: Request,scan: Scan, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)): # type: ignore
    token = request.headers.get("Authorization")
    if token is None or not token.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    token = token[len("Bearer "):]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    user_id = db.execute(text("SELECT id FROM users WHERE email = :email "), {"email": email}).fetchone()
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