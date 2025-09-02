from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
import time
import redis
import json
import logging
from datetime import datetime, timedelta

from ..database import get_db, User, UserSession
from ..config import settings
from ..exceptions import (
    InvalidTokenError,
    SessionExpiredError,
    RateLimitError,
    AuthenticationError
)
from .jwt_handler import jwt_handler
from .utils import (
    validate_indian_mobile,
    format_indian_mobile,
    extract_device_info,
    is_suspicious_activity
)

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

# Redis client for rate limiting
redis_client = redis.from_url(settings.redis_url)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token"""
    
    token = credentials.credentials
    
    # Verify token
    payload = jwt_handler.verify_token(token)
    if not payload:
        raise InvalidTokenError()
    
    user_id = payload.get("user_id")
    if not user_id:
        raise InvalidTokenError()
    
    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise AuthenticationError("User not found")
    
    # Check if session exists and is active
    token_hash = jwt_handler.hash_token(token)
    session = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.jwt_token_hash == token_hash,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    ).first()
    
    if not session:
        raise SessionExpiredError()
    
    # Update session last used time
    session.last_used_at = datetime.utcnow()
    db.commit()
    
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (must be verified and active)"""
    
    if not current_user.is_active:
        raise AuthenticationError("Account is deactivated")
    
    if not current_user.is_verified:
        raise AuthenticationError("Account is not verified")
    
    return current_user

def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user if token is provided, otherwise return None"""
    
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]
        payload = jwt_handler.verify_token(token)
        
        if not payload:
            return None
        
        user_id = payload.get("user_id")
        if not user_id:
            return None
        
        user = db.query(User).filter(
            User.id == user_id,
            User.is_active == True
        ).first()
        
        return user
        
    except Exception as e:
        logger.debug(f"Optional auth failed: {e}")
        return None

def api_rate_limiter(request: Request) -> bool:
    """Rate limiter for API endpoints"""
    
    client_ip = get_client_ip(request)
    endpoint = request.url.path
    
    # Different limits for different endpoints
    if "/auth/" in endpoint:
        limit = settings.auth_rate_limit_per_minute
        window = 60
    else:
        limit = settings.api_rate_limit_per_minute
        window = 60
    
    key = f"rate_limit:{client_ip}:{endpoint}"
    
    try:
        current = redis_client.get(key)
        
        if current is None:
            # First request
            redis_client.setex(key, window, 1)
            return True
        
        current_count = int(current)
        
        if current_count >= limit:
            logger.warning(f"Rate limit exceeded for {client_ip} on {endpoint}")
            raise RateLimitError(f"Rate limit exceeded. Try again in {window} seconds.")
        
        # Increment counter
        redis_client.incr(key)
        return True
        
    except redis.RedisError as e:
        logger.error(f"Redis error in rate limiter: {e}")
        # Allow request if Redis is down
        return True

def otp_rate_limiter(request: Request) -> bool:
    """Specific rate limiter for OTP requests"""
    
    client_ip = get_client_ip(request)
    key = f"otp_rate_limit:{client_ip}"
    
    # Allow 3 OTP requests per 5 minutes
    limit = 3
    window = 300
    
    try:
        current = redis_client.get(key)
        
        if current is None:
            redis_client.setex(key, window, 1)
            return True
        
        current_count = int(current)
        
        if current_count >= limit:
            logger.warning(f"OTP rate limit exceeded for {client_ip}")
            raise RateLimitError("Too many OTP requests. Please try again later.")
        
        redis_client.incr(key)
        return True
        
    except redis.RedisError as e:
        logger.error(f"Redis error in OTP rate limiter: {e}")
        return True

def mobile_rate_limiter(mobile: str) -> bool:
    """Rate limiter per mobile number for OTP"""
    
    key = f"mobile_otp_limit:{mobile}"
    
    # Allow 5 OTP requests per mobile per hour
    limit = 5
    window = 3600
    
    try:
        current = redis_client.get(key)
        
        if current is None:
            redis_client.setex(key, window, 1)
            return True
        
        current_count = int(current)
        
        if current_count >= limit:
            logger.warning(f"Mobile OTP rate limit exceeded for {mobile}")
            raise RateLimitError("Too many OTP requests for this mobile number.")
        
        redis_client.incr(key)
        return True
        
    except redis.RedisError as e:
        logger.error(f"Redis error in mobile rate limiter: {e}")
        return True

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    
    # Check for forwarded headers (when behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client IP
    return request.client.host if request.client else "unknown"

def get_device_info(request: Request) -> Dict[str, Any]:
    """Extract device information from request"""
    
    user_agent = request.headers.get("User-Agent", "")
    client_ip = get_client_ip(request)
    
    device_info = extract_device_info(user_agent)
    device_info.update({
        "ip_address": client_ip,
        "user_agent": user_agent,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return device_info

def validate_mobile_format(mobile: str) -> str:
    """Validate and format mobile number"""
    
    try:
        if not validate_indian_mobile(mobile):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid mobile number format"
            )
        
        return format_indian_mobile(mobile)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

def check_suspicious_activity(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Check for suspicious login activity"""
    
    client_ip = get_client_ip(request)
    device_info = get_device_info(request)
    
    # Get previous sessions
    previous_sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.created_at > datetime.utcnow() - timedelta(days=30)
    ).order_by(UserSession.created_at.desc()).limit(10).all()
    
    session_data = []
    for session in previous_sessions:
        session_data.append({
            "ip_address": session.ip_address,
            "device_info": session.device_info,
            "created_at": session.created_at
        })
    
    return is_suspicious_activity(user_id, client_ip, device_info, session_data)

def require_admin(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Require admin privileges"""
    
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user

def require_verified_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Require verified user"""
    
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account verification required"
        )
    
    return current_user

def log_security_event(
    event_type: str,
    user_id: Optional[int],
    request: Request,
    details: Dict[str, Any] = None
):
    """Log security-related events"""
    
    event_data = {
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent", ""),
        "endpoint": request.url.path,
        "method": request.method,
        "timestamp": datetime.utcnow().isoformat(),
        "details": details or {}
    }
    
    # Log to file/database/external service
    logger.info(f"Security Event: {json.dumps(event_data)}")
    
    # Store in Redis for real-time monitoring
    try:
        key = f"security_events:{datetime.utcnow().strftime('%Y-%m-%d')}"
        redis_client.lpush(key, json.dumps(event_data))
        redis_client.expire(key, 86400 * 7)  # Keep for 7 days
    except redis.RedisError as e:
        logger.error(f"Failed to store security event: {e}")

def validate_session_security(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> bool:
    """Validate session security (IP consistency, etc.)"""
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return False
    
    token = auth_header.split(" ")[1]
    token_hash = jwt_handler.hash_token(token)
    current_ip = get_client_ip(request)
    
    # Get current session
    session = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.jwt_token_hash == token_hash,
        UserSession.is_active == True
    ).first()
    
    if not session:
        return False
    
    # Check IP consistency (optional - can be disabled for mobile users)
    if settings.enforce_ip_consistency and session.ip_address != current_ip:
        logger.warning(
            f"IP mismatch for user {current_user.id}: "
            f"session={session.ip_address}, current={current_ip}"
        )
        
        # Log security event
        log_security_event(
            "ip_mismatch",
            current_user.id,
            request,
            {
                "session_ip": session.ip_address,
                "current_ip": current_ip
            }
        )
        
        # Optionally invalidate session
        if settings.invalidate_on_ip_change:
            session.is_active = False
            db.commit()
            raise SessionExpiredError()
    
    return True

def cleanup_expired_sessions(db: Session = Depends(get_db)):
    """Cleanup expired sessions (can be called periodically)"""
    
    try:
        expired_count = db.query(UserSession).filter(
            UserSession.expires_at < datetime.utcnow(),
            UserSession.is_active == True
        ).update({"is_active": False})
        
        if expired_count > 0:
            db.commit()
            logger.info(f"Cleaned up {expired_count} expired sessions")
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired sessions: {e}")
        db.rollback()

def get_user_permissions(
    current_user: User = Depends(get_current_active_user)
) -> Dict[str, bool]:
    """Get user permissions"""
    
    permissions = {
        "can_read": True,
        "can_write": current_user.is_verified,
        "can_delete": current_user.is_verified,
        "can_admin": current_user.is_admin,
        "can_connect_apps": current_user.is_verified,
        "can_view_analytics": current_user.is_verified,
        "can_export_data": current_user.is_verified
    }
    
    return permissions



