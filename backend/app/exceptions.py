from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from pydantic import ValidationError
import logging
from typing import Union

# Setup logging
logger = logging.getLogger(__name__)

class SatyaLensException(Exception):
    """Base exception class for SatyaLens application"""
    
    def __init__(self, message: str, status_code: int = 500, details: dict = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

class AuthenticationError(SatyaLensException):
    """Authentication related errors"""
    
    def __init__(self, message: str = "Authentication failed", details: dict = None):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED, details)

class AuthorizationError(SatyaLensException):
    """Authorization related errors"""
    
    def __init__(self, message: str = "Access denied", details: dict = None):
        super().__init__(message, status.HTTP_403_FORBIDDEN, details)

class ValidationError(SatyaLensException):
    """Validation related errors"""
    
    def __init__(self, message: str = "Validation failed", details: dict = None):
        super().__init__(message, status.HTTP_400_BAD_REQUEST, details)

class NotFoundError(SatyaLensException):
    """Resource not found errors"""
    
    def __init__(self, message: str = "Resource not found", details: dict = None):
        super().__init__(message, status.HTTP_404_NOT_FOUND, details)

class ConflictError(SatyaLensException):
    """Resource conflict errors"""
    
    def __init__(self, message: str = "Resource conflict", details: dict = None):
        super().__init__(message, status.HTTP_409_CONFLICT, details)

class RateLimitError(SatyaLensException):
    """Rate limiting errors"""
    
    def __init__(self, message: str = "Rate limit exceeded", details: dict = None):
        super().__init__(message, status.HTTP_429_TOO_MANY_REQUESTS, details)

class ExternalServiceError(SatyaLensException):
    """External service errors (SMS, etc.)"""
    
    def __init__(self, message: str = "External service error", details: dict = None):
        super().__init__(message, status.HTTP_503_SERVICE_UNAVAILABLE, details)

class DatabaseError(SatyaLensException):
    """Database related errors"""
    
    def __init__(self, message: str = "Database error", details: dict = None):
        super().__init__(message, status.HTTP_500_INTERNAL_SERVER_ERROR, details)

class FraudDetectionError(SatyaLensException):
    """Fraud detection engine errors"""
    
    def __init__(self, message: str = "Fraud detection error", details: dict = None):
        super().__init__(message, status.HTTP_500_INTERNAL_SERVER_ERROR, details)

# Specific business logic exceptions
class OTPExpiredError(ValidationError):
    """OTP has expired"""
    
    def __init__(self):
        super().__init__("OTP has expired. Please request a new one.")

class OTPInvalidError(ValidationError):
    """Invalid OTP provided"""
    
    def __init__(self):
        super().__init__("Invalid OTP provided.")

class OTPAlreadyUsedError(ValidationError):
    """OTP has already been used"""
    
    def __init__(self):
        super().__init__("OTP has already been used.")

class UserAlreadyExistsError(ConflictError):
    """User already exists"""
    
    def __init__(self, field: str = "email or mobile"):
        super().__init__(f"User with this {field} already exists.")

class UserNotFoundError(NotFoundError):
    """User not found"""
    
    def __init__(self):
        super().__init__("User not found.")

class AppAlreadyConnectedError(ConflictError):
    """App already connected"""
    
    def __init__(self, app_type: str):
        super().__init__(f"{app_type.title()} is already connected.")

class AppNotConnectedError(NotFoundError):
    """App not connected"""
    
    def __init__(self, app_type: str):
        super().__init__(f"{app_type.title()} is not connected.")

class InvalidTokenError(AuthenticationError):
    """Invalid or expired token"""
    
    def __init__(self):
        super().__init__("Invalid or expired token.")

class SessionExpiredError(AuthenticationError):
    """Session has expired"""
    
    def __init__(self):
        super().__init__("Session has expired. Please login again.")

# Exception handlers
async def satyalens_exception_handler(request: Request, exc: SatyaLensException):
    """Handle custom SatyaLens exceptions"""
    logger.error(f"SatyaLens Exception: {exc.message}", extra={
        "status_code": exc.status_code,
        "details": exc.details,
        "path": request.url.path,
        "method": request.method
    })
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "data": None,
            "errors": [exc.message],
            "details": exc.details
        }
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors"""
    errors = []
    for error in exc.errors():
        field = " -> ".join(str(loc) for loc in error["loc"])
        message = error["msg"]
        errors.append(f"{field}: {message}")
    
    logger.warning(f"Validation Error: {errors}", extra={
        "path": request.url.path,
        "method": request.method
    })
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "message": "Validation failed",
            "data": None,
            "errors": errors,
            "details": {"validation_errors": exc.errors()}
        }
    )

async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle FastAPI HTTP exceptions"""
    logger.warning(f"HTTP Exception: {exc.detail}", extra={
        "status_code": exc.status_code,
        "path": request.url.path,
        "method": request.method
    })
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "data": None,
            "errors": [exc.detail]
        }
    )

async def database_exception_handler(request: Request, exc: SQLAlchemyError):
    """Handle database exceptions"""
    logger.error(f"Database Error: {str(exc)}", extra={
        "path": request.url.path,
        "method": request.method
    })
    
    # Handle specific database errors
    if isinstance(exc, IntegrityError):
        if "duplicate key" in str(exc).lower():
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "success": False,
                    "message": "Resource already exists",
                    "data": None,
                    "errors": ["Duplicate entry found"]
                }
            )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Database error occurred",
            "data": None,
            "errors": ["Internal server error"]
        }
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    logger.error(f"Unhandled Exception: {str(exc)}", extra={
        "exception_type": type(exc).__name__,
        "path": request.url.path,
        "method": request.method
    }, exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Internal server error",
            "data": None,
            "errors": ["An unexpected error occurred"]
        }
    )

# Exception mapping for FastAPI app
EXCEPTION_HANDLERS = {
    SatyaLensException: satyalens_exception_handler,
    RequestValidationError: validation_exception_handler,
    HTTPException: http_exception_handler,
    SQLAlchemyError: database_exception_handler,
    Exception: general_exception_handler,
}
