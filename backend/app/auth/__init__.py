"""
Authentication Module

Handles user authentication, JWT tokens, OTP verification, and session management.
"""

from .jwt_handler import jwt_handler
from .otp_service import otp_service
from .routes import router

__all__ = [
    "jwt_handler",
    "otp_service", 
    "router"
]


