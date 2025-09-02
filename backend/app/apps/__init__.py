"""
Apps Module

Handles connected app management, permissions, and integration with various messaging platforms.
Supports WhatsApp, Messages, Email, Telegram, Instagram, and Gallery apps.
"""

from .manager import app_manager
from .routes import router
from .permissions import permission_manager
from .scanners import scanner_factory

__all__ = [
    "app_manager",
    "router", 
    "permission_manager",
    "scanner_factory"
]


