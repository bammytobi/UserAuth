from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import mysql.connector
from datetime import datetime, timedelta

# --- JWT Settings ---
SECRET_KEY = "mysecretkey"   # 👉 change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- OAuth2 ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

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
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


MAX_PASSWORD_LENGTH = 72
# --- 1️⃣ Create Account Endpoint ---
"""@app.post("/register")
def register(username: str, password: str):
    db = get_db()
    cursor = db.cursor()

    # Check if username exists
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
    db.commit()
    cursor.close()
    db.close()
    return {"message": "User created successfully ✅"}"""
@app.post("/register")
def register(username: str, password: str):
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password too long — must be ≤ {MAX_PASSWORD_LENGTH} characters"
        )

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
    db.commit()
    cursor.close()
    db.close()
    return {"code":"00","message": "User created successfully ✅"}


# --- 2️⃣ Login Endpoint ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create Token
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- 3️⃣ Protected Endpoint ---
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
