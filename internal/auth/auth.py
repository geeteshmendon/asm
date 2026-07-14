from datetime import datetime, timedelta
import hashlib
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from internal.db.database import get_db
from internal.models.models import User, ApiKey

security = HTTPBearer()
import os
SECRET_KEY = os.environ.get("ASM_SECRET_KEY", "change-me-in-production")


def hash_password(password: str) -> str:
    return hashlib.sha256(f"{password}:{SECRET_KEY}".encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    key = f"asm_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash


def verify_api_key(key: str) -> bool:
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    db = next(get_db())
    try:
        api_key = db.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        ).first()
        if api_key:
            api_key.last_used_at = datetime.utcnow()
            db.commit()
            return True
        return False
    finally:
        db.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User | None:
    token = credentials.credentials
    user_id = verify_session_token(token)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def verify_session_token(token: str) -> int | None:
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None
        user_id_str, expiry_str, sig = parts
        user_id = int(user_id_str)
        expiry = datetime.fromisoformat(expiry_str)
        if datetime.utcnow() > expiry:
            return None
        expected = hashlib.sha256(f"{user_id}:{expiry_str}:{SECRET_KEY}".encode()).hexdigest()
        if sig == expected:
            return user_id
        return None
    except Exception:
        return None


def create_session_token(user_id: int) -> str:
    expiry = datetime.utcnow() + timedelta(days=7)
    expiry_str = expiry.isoformat()
    sig = hashlib.sha256(f"{user_id}:{expiry_str}:{SECRET_KEY}".encode()).hexdigest()
    return f"{user_id}:{expiry_str}:{sig}"
