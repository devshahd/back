import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .database import get_db
from .models import SecurityEvent, SessionToken, User

SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = "HS256"
ACCESS_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "30"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "10"))

if os.getenv("NODE_ENV", os.getenv("ENVIRONMENT", "development")).lower() == "production":
    if len(SECRET_KEY) < 32:
        raise RuntimeError("SECRET_KEY must be set and at least 32 characters in production.")
elif not SECRET_KEY:
    # Development-only fallback. Never use this value in production.
    SECRET_KEY = secrets.token_urlsafe(48)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bool(password and hashed and pwd_context.verify(password, hashed))
    except Exception:
        return False


def _now():
    return datetime.now(timezone.utc)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user: User, session_id: str) -> str:
    now = _now()
    payload = {
        "sub": str(user.id),
        "sid": session_id,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user: User, session_id: str, token_version: int) -> str:
    now = _now()
    payload = {
        "sub": str(user.id),
        "sid": session_id,
        "tv": token_version,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=REFRESH_DAYS)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _unauthorized(message="Invalid or expired credentials"):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        if not user_id or not session_id:
            raise _unauthorized()
    except JWTError:
        raise _unauthorized()

    session = (
        db.query(SessionToken)
        .filter(
            SessionToken.id == session_id,
            SessionToken.user_id == int(user_id),
            SessionToken.revoked_at.is_(None),
            SessionToken.expires_at > datetime.utcnow(),
        )
        .first()
    )
    if not session:
        raise _unauthorized("Session is no longer active.")

    user = db.query(User).filter(User.id == int(user_id), User.active.is_(True)).first()
    if not user:
        raise _unauthorized("Account is inactive.")

    # Keep authorization server-side; never trust the role carried by the browser.
    session.last_active_at = datetime.utcnow()
    return user


def require_admin(user: User = Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def require_roles(*roles):
    allowed = {r.lower() for r in roles}

    def dependency(user: User = Depends(current_user)):
        if user.role.lower() not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return dependency


def record_security_event(db: Session, event_type: str, severity: str, message: str,
                          user_id: int | None = None, metadata: dict | None = None):
    db.add(SecurityEvent(
        type=event_type,
        severity=severity,
        message=message[:500],
        user_id=user_id,
        event_metadata=metadata or {},
        created_at=datetime.utcnow(),
    ))
