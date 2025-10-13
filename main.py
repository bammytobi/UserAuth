from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
from datetime import datetime, timedelta

# --- JWT Settings ---
SECRET_KEY = "mysecretkey"   # 👉 Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- 🔐 Password Hashing (Switched to Argon2) ---
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# --- OAuth2 ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="🔐 FastAPI MySQL Auth API")

# ✅ --- Enable CORS ---
origins = [
    "http://localhost:3000",  # React local dev
    "http://127.0.0.1:3000",
    "http://localhost:5173",  # Vite local dev
    "https://userauth-yea1.onrender.com",
    "*"  # ⚠️ Allow all origins (use specific domains in production)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,        # domains that can access the API
    allow_credentials=True,
    allow_methods=["*"],          # allow all HTTP methods
    allow_headers=["*"],          # allow all headers
)

# --- MySQL Connection ---
def get_db():
    return mysql.connector.connect(
        host="b9u0st.h.filess.io",
        user="TestApp_valleytrip",
        password="e55af5244a52e89bbbab11b4cff71935fc6b2a45",
        database="TestApp_valleytrip",
        port=61030,
        charset='utf8mb4',
        collation='utf8mb4_general_ci'
    )

# --- Utility functions ---
def verify_password(plain, hashed):
    """Verify a plain password against the stored hash."""
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    """Hash a password securely using Argon2 (no 72 char limit)."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create a signed JWT token with expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- 1️⃣ Register User ---
@app.post("/register")
def register(username: str, password: str):
    db = get_db()
    cursor = db.cursor()

    # Check if username already exists
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "User created successfully ✅"}

# --- 2️⃣ Login ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Generate JWT token
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3️⃣ Protected Route ---
@app.get("/me")
def get_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
# --- 🔐 Helper to get current user from JWT ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- 🧪 4. Sample Authorized Route ---
@app.get("/dashboard")
def read_dashboard(current_user: str = Depends(get_current_user)):
    return {
        "message": f"🎉 Welcome {current_user}, you have access to the dashboard!",
        "tips": "You can now create more secure endpoints for authorized users."
    }
