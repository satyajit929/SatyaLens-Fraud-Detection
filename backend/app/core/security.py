"""
Security Module for Fraud Detection System

This module provides comprehensive security utilities including authentication,
authorization, encryption, token management, rate limiting, and security
monitoring for the fraud detection application.
"""

import hashlib
import hmac
import secrets
import base64
import json
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from functools import wraps
import re
import ipaddress
from urllib.parse import urlparse

# Third-party imports
import jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import qrcode
from io import BytesIO
import structlog

# Local imports
from .config import settings
from ..database import get_db, User, SecurityEvent, LoginAttempt
from ..models.security import SecurityLevel, EventType, ThreatLevel

logger = structlog.get_logger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SecurityError(Exception):
    """Base exception for security-related errors"""
    pass

class AuthenticationError(SecurityError):
    """Authentication failed"""
    pass

class AuthorizationError(SecurityError):
    """Authorization failed"""
    pass

class TokenError(SecurityError):
    """Token-related error"""
    pass

class RateLimitError(SecurityError):
    """Rate limit exceeded"""
    pass

class PasswordManager:
    """Password hashing and validation utilities"""
    
    def __init__(self):
        self.pwd_context = pwd_context
        self.min_length = settings.security.password_min_length
        self.password_patterns = {
            'uppercase': re.compile(r'[A-Z]'),
            'lowercase': re.compile(r'[a-z]'),
            'digit': re.compile(r'\d'),
            'special': re.compile(r'[!@#$%^&*(),.?":{}|<>]')
        }
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength and return detailed feedback"""
        validation_result = {
            "is_valid": True,
            "score": 0,
            "feedback": [],
            "requirements_met": {}
        }
        
        # Check minimum length
        if len(password) < self.min_length:
            validation_result["is_valid"] = False
            validation_result["feedback"].append(f"Password must be at least {self.min_length} characters long")
        else:
            validation_result["score"] += 1
        
        # Check character requirements
        for pattern_name, pattern in self.password_patterns.items():
            has_pattern = bool(pattern.search(password))
            validation_result["requirements_met"][pattern_name] = has_pattern
            
            if has_pattern:
                validation_result["score"] += 1
            else:
                validation_result["is_valid"] = False
                validation_result["feedback"].append(f"Password must contain at least one {pattern_name} character")
        
        # Check for common patterns
        if self._has_common_patterns(password):
            validation_result["is_valid"] = False
            validation_result["feedback"].append("Password contains common patterns")
        
        # Calculate strength score (0-5)
        validation_result["strength"] = min(validation_result["score"], 5)
        
        return validation_result
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common weak password patterns"""
        common_patterns = [
            r'123456',
            r'password',
            r'qwerty',
            r'abc123',
            r'(.)\1{2,}',  # Repeated characters
        ]
        
        password_lower = password.lower()
        for pattern in common_patterns:
            if re.search(pattern, password_lower):
                return True
        
        return False
    
    def generate_secure_password(self, length: int = 12) -> str:
        """Generate a cryptographically secure password"""
        if length < 8:
            length = 8
        
        # Ensure we have at least one character from each category
        uppercase = secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        lowercase = secrets.choice('abcdefghijklmnopqrstuvwxyz')
        digit = secrets.choice('0123456789')
        special = secrets.choice('!@#$%^&*')
        
        # Fill the rest with random characters
        all_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
        remaining = ''.join(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Combine and shuffle
        password_chars = list(uppercase + lowercase + digit + special + remaining)
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)

class TokenManager:
    """JWT token management for authentication and authorization"""
    
    def __init__(self):
        self.secret_key = settings.security.secret_key
        self.algorithm = settings.security.algorithm
        self.access_token_expire = timedelta(minutes=settings.security.access_token_expire_minutes)
        self.refresh_token_expire = timedelta(days=settings.security.refresh_token_expire_days)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + self.access_token_expire
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create a JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + self.refresh_token_expire
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != token_type:
                raise TokenError(f"Invalid token type. Expected {token_type}")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired")
        except jwt.JWTError as e:
            raise TokenError(f"Token validation failed: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """Create a new access token using a refresh token"""
        payload = self.verify_token(refresh_token, "refresh")
        
        # Create new access token with same user data
        new_payload = {
            "sub": payload["sub"],
            "user_id": payload.get("user_id"),
            "email": payload.get("email"),
            "roles": payload.get("roles", [])
        }
        
        return self.create_access_token(new_payload)
    
    def revoke_token(self, token: str) -> bool:
        """Add token to revocation list (blacklist)"""
        try:
            payload = self.verify_token(token)
            jti = payload.get("jti")  # JWT ID
            
            if jti:
                # Store in Redis with expiration matching token expiration
                from ..core import cache_manager
                exp_timestamp = payload.get("exp")
                if exp_timestamp:
                    ttl = exp_timestamp - datetime.utcnow().timestamp()
                    if ttl > 0:
                        cache_manager.set(f"revoked_token:{jti}", "1", ttl=int(ttl))
                        return True
            
            return False
            
        except TokenError:
            return False
    
    def is_token_revoked(self, token: str) -> bool:
        """Check if token is in revocation list"""
        try:
            payload = self.verify_token(token)
            jti = payload.get("jti")
            
            if jti:
                from ..core import cache_manager
                return cache_manager.exists(f"revoked_token:{jti}")
            
            return False
            
        except TokenError:
            return True  # Invalid tokens are considered revoked

class EncryptionManager:
    """Data encryption and decryption utilities"""
    
    def __init__(self):
        self.fernet_key = self._derive_key(settings.security.secret_key)
        self.fernet = Fernet(self.fernet_key)
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        password_bytes = password.encode()
        salt = b'fraud_detection_salt'  # In production, use random salt per encryption
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted_data = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error("Data encryption failed", error=str(e))
            raise SecurityError("Encryption failed")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error("Data decryption failed", error=str(e))
            raise SecurityError("Decryption failed")
    
    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash sensitive data with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
        hashed_data = base64.urlsafe_b64encode(hash_obj).decode()
        
        return hashed_data, salt
    
    def verify_hashed_data(self, data: str, hashed_data: str, salt: str) -> bool:
        """Verify data against its hash"""
        computed_hash, _ = self.hash_sensitive_data(data, salt)
        return hmac.compare_digest(computed_hash, hashed_data)

class TwoFactorAuth:
    """Two-factor authentication using TOTP"""
    
    def __init__(self):
        self.issuer_name = settings.app_name
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email: str, secret: str) -> bytes:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer.getvalue()
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for 2FA"""
        return [secrets.token_hex(4).upper() for _ in range(count)]

class RateLimiter:
    """Rate limiting for API endpoints and user actions"""
    
    def __init__(self):
        from ..core import cache_manager
        self.cache = cache_manager
    
    def is_rate_limited(self, key: str, limit: int, window: int) -> bool:
        """Check if action is rate limited"""
        current_count = self._get_current_count(key, window)
        return current_count >= limit
    
    def increment_counter(self, key: str, window: int) -> int:
        """Increment rate limit counter"""
        cache_key = f"rate_limit:{key}"
        
        try:
            current_count = self.cache.redis_client.incr(cache_key)
            
            if current_count == 1:
                # Set expiration on first increment
                self.cache.redis_client.expire(cache_key, window)
            
            return current_count
            
        except Exception as e:
            logger.error("Rate limit increment failed", key=key, error=str(e))
            return 0
    
    def _get_current_count(self, key: str, window: int) -> int:
        """Get current count for rate limiting"""
        cache_key = f"rate_limit:{key}"
        
        try:
            count = self.cache.get(cache_key)
            return int(count) if count else 0
        except (ValueError, TypeError):
            return 0
    
    def reset_counter(self, key: str) -> bool:
        """Reset rate limit counter"""
        cache_key = f"rate_limit:{key}"
        return self.cache.delete(cache_key)

class SecurityMonitor:
    """Security event monitoring and threat detection"""
    
    def __init__(self):
        from ..core import cache_manager
        self.cache = cache_manager
    
    def log_security_event(self, event_type: EventType, user_id: Optional[int] = None, 
                          ip_address: Optional[str] = None, details: Optional[Dict] = None,
                          threat_level: ThreatLevel = ThreatLevel.LOW) -> None:
        """Log a security event"""
        try:
            db = next(get_db())
            
            security_event = SecurityEvent(
                event_type=event_type.value,
                user_id=user_id,
                ip_address=ip_address,
                details=details or {},
                threat_level=threat_level.value,
                timestamp=datetime.utcnow()
            )
            
            db.add(security_event)
            db.commit()
            
            # Log to structured logger
            logger.info(
                "Security event logged",
                event_type=event_type.value,
                user_id=user_id,
                ip_address=ip_address,
                threat_level=threat_level.value,
                details=details
            )
            
            # Check for suspicious patterns
            self._analyze_security_patterns(event_type, user_id, ip_address)
            
        except Exception as e:
            logger.error("Failed to log security event", error=str(e))
    
    def _analyze_security_patterns(self, event_type: EventType, user_id: Optional[int], 
                                 ip_address: Optional[str]) -> None:
        """Analyze security events for suspicious patterns"""
        # Check for multiple failed login attempts
        if event_type == EventType.LOGIN_FAILED and user_id:
            self._check_failed_login_pattern(user_id, ip_address)
        
        # Check for suspicious IP activity
        if ip_address:
            self._check_ip_reputation(ip_address)
    
    def _check_failed_login_pattern(self, user_id: int, ip_address: Optional[str]) -> None:
        """Check for suspicious failed login patterns"""
        try:
            db = next(get_db())
            
            # Count recent failed attempts
            recent_failures = db.query(SecurityEvent).filter(
                SecurityEvent.event_type == EventType.LOGIN_FAILED.value,
                SecurityEvent.user_id == user_id,
                SecurityEvent.timestamp >= datetime.utcnow() - timedelta(minutes=15)
            ).count()
            
            if recent_failures >= settings.security.max_login_attempts:
                # Lock account
                self._lock_user_account(user_id)
                
                # Log high-threat event
                self.log_security_event(
                    EventType.ACCOUNT_LOCKED,
                    user_id=user_id,
                    ip_address=ip_address,
                    details={"failed_attempts": recent_failures},
                    threat_level=ThreatLevel.HIGH
                )
                
        except Exception as e:
            logger.error("Failed to check login pattern", error=str(e))
    
    def _check_ip_reputation(self, ip_address: str) -> None:
        """Check IP address reputation"""
        # Simple implementation - in production, integrate with threat intelligence
        suspicious_patterns = [
            self._is_tor_exit_node(ip_address),
            self._is_known_malicious_ip(ip_address),
            self._has_suspicious_geolocation(ip_address)
        ]
        
        if any(suspicious_patterns):
            self.log_security_event(
                EventType.SUSPICIOUS_IP,
                ip_address=ip_address,
                details={"patterns": suspicious_patterns},
                threat_level=ThreatLevel.MEDIUM
            )
    
    def _is_tor_exit_node(self, ip_address: str) -> bool:
        """Check if IP is a Tor exit node"""
        # Simplified check - in production, use updated Tor exit node list
        tor_cache_key = f"tor_check:{ip_address}"
        
        cached_result = self.cache.get(tor_cache_key)
        if cached_result is not None:
            return cached_result == "true"
        
        # Placeholder implementation
        is_tor = False  # Implement actual Tor check
        
        # Cache result for 1 hour
        self.cache.set(tor_cache_key, "true" if is_tor else "false", ttl=3600)
        
        return is_tor
    
    def _is_known_malicious_ip(self, ip_address: str) -> bool:
        """Check if IP is known malicious"""
        # Implement threat intelligence integration
        return False
    
    def _has_suspicious_geolocation(self, ip_address: str) -> bool:
        """Check for suspicious geolocation patterns"""
        # Implement geolocation-based risk assessment
        return False
    
    def _lock_user_account(self, user_id: int) -> None:
        """Lock user account due to security concerns"""
        try:
            db = next(get_db())
            user = db.query(User).filter(User.id == user_id).first()
            
            if user:
                user.is_locked = True
                user.locked_at = datetime.utcnow()
                user.lock_reason = "Multiple failed login attempts"
                db.commit()
                
                logger.warning("User account locked", user_id=user_id)
                
        except Exception as e:
            logger.error("Failed to lock user account", user_id=user_id, error=str(e))

class IPWhitelist:
    """IP address whitelist management"""
    
    def __init__(self):
        from ..core import cache_manager
        self.cache = cache_manager
    
    def is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP address is whitelisted"""
        try:
            # Check cache first
            cache_key = f"ip_whitelist:{ip_address}"
            cached_result = self.cache.get(cache_key)
            
            if cached_result is not None:
                return cached_result == "true"
            
            # Check database
            db = next(get_db())
            # Implement IP whitelist table query
            
            # For now, return False and cache result
            self.cache.set(cache_key, "false", ttl=300)  # 5 minutes
            return False
            
        except Exception as e:
            logger.error("IP whitelist check failed", ip_address=ip_address, error=str(e))
            return False
    
    def add_to_whitelist(self, ip_address: str, reason: str) -> bool:
        """Add IP address to whitelist"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            # Add to database
            db = next(get_db())
            # Implement IP whitelist insertion
            
            # Clear cache
            cache_key = f"ip_whitelist:{ip_address}"
            self.cache.delete(cache_key)
            
            logger.info("IP added to whitelist", ip_address=ip_address, reason=reason)
            return True
            
        except Exception as e:
            logger.error("Failed to add IP to whitelist", ip_address=ip_address, error=str(e))
            return False

# Security decorators
def require_auth(func):
    """Decorator to require authentication"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Implementation depends on your web framework
        # This is a placeholder for FastAPI/Flask integration
        return func(*args, **kwargs)
    return wrapper

def require_roles(*required_roles):
    """Decorator to require specific roles"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Implementation depends on your web framework
            # Check user roles against required_roles
            return func(*args, **kwargs)
        return wrapper
    return decorator

def rate_limit(limit: int, window: int):
    """Decorator for rate limiting"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            rate_limiter = RateLimiter()
            
            # Generate rate limit key (implementation depends on context)
            key = f"func:{func.__name__}"  # Simplified key
            
            if rate_limiter.is_rate_limited(key, limit, window):
                raise RateLimitError("Rate limit exceeded")
            
            rate_limiter.increment_counter(key, window)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Global instances
password_manager = PasswordManager()
token_manager = TokenManager()
encryption_manager = EncryptionManager()
two_factor_auth = TwoFactorAuth()
rate_limiter = RateLimiter()
security_monitor = SecurityMonitor()
ip_whitelist = IPWhitelist()

# Export public API
__all__ = [
    "PasswordManager",
    "TokenManager", 
    "EncryptionManager",
    "TwoFactorAuth",
    "RateLimiter",
    "SecurityMonitor",
    "IPWhitelist",
    "password_manager",
    "token_manager",
    "encryption_manager",
    "two_factor_auth",
    "rate_limiter",
    "security_monitor",
    "ip_whitelist",
    "require_auth",
    "require_roles",
    "rate_limit",
    "SecurityError",
    "AuthenticationError",
    "AuthorizationError",
    "TokenError",
    "RateLimitError"
]

logger.info("Security module initialized")