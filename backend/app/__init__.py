"""
SatyaLens Backend Application

AI-powered fraud detection and prevention platform.
"""

__version__ = "1.0.0"
__author__ = "SatyaLens Team"
__email__ = "support@satyalens.com"

from .config import settings
from .database import Base, engine, get_db

# Create database tables on import
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

# Application metadata
APP_INFO = {
    "title": "SatyaLens API",
    "description": "AI-powered fraud detection and prevention platform",
    "version": __version__,
    "contact": {
        "name": "SatyaLens Support",
        "email": __email__,
    },
    "license_info": {
        "name": "MIT License",
    },
}


