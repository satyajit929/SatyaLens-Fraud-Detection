from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
import hashlib
import logging
from ..config import settings

logger = logging.getLogger(__name__)

class JWTHandler:
    """JWT token handler for authentication"""
    
    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.jwt_access_token_expire_minutes
        self.refresh_token_expire_days = settings.jwt_refresh_token_expire_days
    
    def create_access_token(self, user_id: int, additional_claims: Dict[str, Any] = None) -> str:
        """Create JWT access token"""
        
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        payload = {
            "user_id": user_id,
            "type": "access",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": "satyalens"
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Access token created for user {user_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to create access token: {e}")
            raise
    
    def create_refresh_token(self, user_id: int) -> str:
        """Create JWT refresh token"""
        
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        payload = {
            "user_id": user_id,
            "type": "refresh",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": "satyalens"
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Refresh token created for user {user_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer="satyalens"
            )
            
            # Check token type
            if payload.get("type") != "access":
                logger.warning("Invalid token type for access token verification")
                return None
            
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                logger.debug("Access token expired")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.debug("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT refresh token"""
        
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer="satyalens"
            )
            
            # Check token type
            if payload.get("type") != "refresh":
                logger.warning("Invalid token type for refresh token verification")
                return None
            
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                logger.debug("Refresh token expired")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.debug("Refresh token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {e}")
            return None
        except Exception as e:
            logger.error(f"Refresh token verification error: {e}")
            return None
    
    def decode_token_without_verification(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode token without verification (for debugging/logging)"""
        
        try:
            payload = jwt.decode(
                token, 
                options={"verify_signature": False, "verify_exp": False}
            )
            return payload
        except Exception as e:
            logger.error(f"Token decode error: {e}")
            return None
    
    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """Get token expiry time"""
        
        payload = self.decode_token_without_verification(token)
        if not payload:
            return None
        
        exp = payload.get("exp")
        if exp:
            return datetime.fromtimestamp(exp)
        
        return None
    
    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired"""
        
        expiry = self.get_token_expiry(token)
        if not expiry:
            return True
        
        return expiry < datetime.utcnow()
    
    def get_user_id_from_token(self, token: str) -> Optional[int]:
        """Extract user ID from token without full verification"""
        
        payload = self.decode_token_without_verification(token)
        if not payload:
            return None
        
        return payload.get("user_id")
    
    def hash_token(self, token: str) -> str:
        """Create hash of token for database storage"""
        
        return hashlib.sha256(token.encode()).hexdigest()
    
    def create_password_reset_token(self, user_id: int, email: str) -> str:
        """Create password reset token"""
        
        expire = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
        
        payload = {
            "user_id": user_id,
            "email": email,
            "type": "password_reset",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": "satyalens"
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Password reset token created for user {user_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to create password reset token: {e}")
            raise
    
    def verify_password_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify password reset token"""
        
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer="satyalens"
            )
            
            # Check token type
            if payload.get("type") != "password_reset":
                logger.warning("Invalid token type for password reset")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.debug("Password reset token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid password reset token: {e}")
            return None
        except Exception as e:
            logger.error(f"Password reset token verification error: {e}")
            return None
    
    def create_email_verification_token(self, user_id: int, email: str) -> str:
        """Create email verification token"""
        
        expire = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        
        payload = {
            "user_id": user_id,
            "email": email,
            "type": "email_verification",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": "satyalens"
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Email verification token created for user {user_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to create email verification token: {e}")
            raise
    
    def verify_email_verification_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify email verification token"""
        
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                issuer="satyalens"
            )
            
            # Check token type
            if payload.get("type") != "email_verification":
                logger.warning("Invalid token type for email verification")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.debug("Email verification token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid email verification token: {e}")
            return None
        except Exception as e:
            logger.error(f"Email verification token verification error: {e}")
            return None
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """Get comprehensive token information"""
        
        payload = self.decode_token_without_verification(token)
        if not payload:
            return {"valid": False, "error": "Invalid token format"}
        
        token_type = payload.get("type", "unknown")
        user_id = payload.get("user_id")
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        
        info = {
            "valid": False,
            "type": token_type,
            "user_id": user_id,
            "issued_at": datetime.fromtimestamp(issued_at) if issued_at else None,
            "expires_at": datetime.fromtimestamp(expires_at) if expires_at else None,
            "is_expired": self.is_token_expired(token)
        }
        
        # Verify signature
        try:
            if token_type == "access":
                verified_payload = self.verify_token(token)
            elif token_type == "refresh":
                verified_payload = self.verify_refresh_token(token)
            elif token_type == "password_reset":
                verified_payload = self.verify_password_reset_token(token)
            elif token_type == "email_verification":
                verified_payload = self.verify_email_verification_token(token)
            else:
                verified_payload = None
            
            info["valid"] = verified_payload is not None
            
        except Exception as e:
            info["error"] = str(e)
        
        return info

# Global JWT handler instance
jwt_handler = JWTHandler()