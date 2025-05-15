from datetime import timedelta
import time

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:1420"],  # or ["*"] during dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Secret key and algorithm
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Fake user "database"
fake_users_db = {
    "cam": {
        "id": 1,
        "email": "cam",
        "password": "1234" # TODO: hash this
    },
    "chris": {
        "id": 2,
        "email": "chris",
        "password": "1234" # TODO: hash this
    },
    "dad": {
        "id": 3,
        "email": "dad",
        "password": "1234" # TODO: hash this
    }
}

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    username: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = int(time.time()) + expires_delta.total_seconds()
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    user = fake_users_db.get(req.email)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_token({"sub": str(user["id"]), "username": user["email"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": str(user["id"]), "username": user["email"]}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {
        "username": user["email"],
        "access_token": access_token,
        "refresh_token": refresh_token,
    }

@app.post("/refresh")
def refresh_token(req: RefreshTokenRequest):
    token = req.refresh_token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        username = payload.get("username")
        exp = payload.get("exp")
        if exp is None or exp < int(time.time()):
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        access_token = create_token({"sub": str(user_id)}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        refresh_token = create_token({"sub": str(user_id)}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

        return {
            "username": username,
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
