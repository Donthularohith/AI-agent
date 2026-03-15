"""
JWT Authentication Middleware — Human Operator Auth

Validates JWT tokens for human operators accessing the governance API.
Agent-to-platform auth uses Vault credentials, not JWT.
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict

from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-this-to-a-secure-random-string-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))

security_scheme = HTTPBearer(auto_error=False)


def create_access_token(
    data: Dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token for a human operator."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXPIRATION))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
) -> Optional[Dict]:
    """
    FastAPI dependency for JWT authentication.
    Returns None if no token provided (for endpoints that allow unauthenticated access).
    """
    if not credentials:
        return None

    return verify_token(credentials.credentials)


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
) -> Dict:
    """
    Strict authentication dependency — requires valid JWT.
    Use for admin endpoints.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    return verify_token(credentials.credentials)
