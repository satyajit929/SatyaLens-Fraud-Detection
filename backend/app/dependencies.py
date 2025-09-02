from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
import redis
import time
from datetime import datetime

from .database import get_db, User, UserSession
from .auth.jwt_handler import jwt_handler
from .config import settings

# Security scheme
security = HTTPBearer()

# Redis client for rate limiting
redis_client = redis.from_url(settings.redis_url)

class RateLimiter:
    """Rate limiting dependency"""
    
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
    
    def __call__(self, request: Request):
        # Get client IP
        client_ip = request.client.host
        key = f"rate_limit:{client_ip}"
        
        # Get current count
        current = redis_client.get(key)
        
        if current is None:
            # First request
            redis_client.setex(key, self.period, 1)
            return True
        
        if int(current) >= self.calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later."
            )
        
        # Increment counter
        redis_client.incr(key)
        return True

# Rate limiter instances
api_rate_limiter = RateLimiter(
    calls=settings.api_rate_limit_per_minute,
    period=60
)

otp_rate_limiter = RateLimiter(
    calls=settings.otp_rate_limit_per_hour,
    period=3600
)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify JWT token
        payload = jwt_handler.verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception
        
        user_id: int = payload.get("user_id")
        token_type: str = payload.get("type")
        
        if user_id is None or token_type != "access":
            raise credentials_exception
            
    except Exception:
        raise credentials_exception
    
    # Check if token exists in database and is active
    token_hash = jwt_handler.hash_token(credentials.credentials)
    session = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.jwt_token_hash == token_hash,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    ).first()
    
    if not session:
        raise credentials_exception
    
    # Get user
    user = db.query(User).filter(
        User.id == user_id,
        User.is_active == True
    ).first()
    
    if user is None:
        raise credentials_exception
    
    # Update last used time
    session.last_used_at = datetime.utcnow()
    db.commit()
    
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user"""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not verified"
        )
    return current_user

def get_client_ip(request: Request) -> str:
    """Extract client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

def get_device_info(request: Request) -> dict:
    """Extract device information from request"""
    user_agent = request.headers.get("User-Agent", "")
    return {
        "user_agent": user_agent,
        "ip_address": get_client_ip(request),
        "timestamp": datetime.utcnow().isoformat()
    }

class OptionalAuth:
    """Optional authentication dependency"""
    
    def __init__(self):
        self.security = HTTPBearer(auto_error=False)
    
    async def __call__(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        db: Session = Depends(get_db)
    ) -> Optional[User]:
        """Get current user if authenticated, None otherwise"""
        
        if not credentials:
            return None
        
        try:
            payload = jwt_handler.verify_token(credentials.credentials)
            if payload is None:
                return None
            
            user_id: int = payload.get("user_id")
            if user_id is None:
                return None
            
            # Check session
            token_hash = jwt_handler.hash_token(credentials.credentials)
            session = db.query(UserSession).filter(
                UserSession.user_id == user_id,
                UserSession.jwt_token_hash == token_hash,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).first()
            
            if not session:
                return None
            
            # Get user
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True
            ).first()
            
            return user
            
        except Exception:
            return None

# Optional auth instance
optional_auth = OptionalAuth()

def validate_mobile_format(mobile: str) -> str:
    """Validate and format mobile number"""
    import re
    
    # Remove spaces and dashes
    clean_mobile = mobile.replace(' ', '').replace('-', '')
    
    # Indian mobile number validation
    pattern = r'^(\+91|91)?[6-9]\d{9}$'
    if not re.match(pattern, clean_mobile):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Indian mobile number format"
        )
    
    # Ensure +91 prefix
    if not clean_mobile.startswith('+91'):
        if clean_mobile.startswith('91'):
            clean_mobile = '+' + clean_mobile
        else:
            clean_mobile = '+91' + clean_mobile
    
    return clean_mobile

def validate_app_type(app_type: str) -> str:
    """Validate app type"""
    allowed_apps = ['whatsapp', 'messages', 'email', 'telegram', 'instagram', 'gallery']
    if app_type not in allowed_apps:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"App type must be one of: {', '.join(allowed_apps)}"
        )
    return app_type