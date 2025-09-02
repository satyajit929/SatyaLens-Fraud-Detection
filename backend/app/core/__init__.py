"""
Core Module for Fraud Detection System

This module provides foundational components, utilities, and shared functionality
for the fraud detection application. It includes configuration management,
logging setup, database utilities, caching, security helpers, and common
data structures used throughout the application.
"""

import logging
import os
import sys
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from pathlib import Path
import json
import hashlib
import secrets
from functools import wraps
from contextlib import contextmanager

# Third-party imports
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseSettings, Field
import structlog

# Version information
__version__ = "1.0.0"
__author__ = "Fraud Detection Team"
__description__ = "Core utilities and components for fraud detection system"

# Module-level logger
logger = structlog.get_logger(__name__)

# Configuration Classes
class DatabaseConfig(BaseSettings):
    """Database configuration settings"""
    
    database_url: str = Field(..., env="DATABASE_URL")
    pool_size: int = Field(10, env="DB_POOL_SIZE")
    max_overflow: int = Field(20, env="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(30, env="DB_POOL_TIMEOUT")
    pool_recycle: int = Field(3600, env="DB_POOL_RECYCLE")
    echo: bool = Field(False, env="DB_ECHO")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class RedisConfig(BaseSettings):
    """Redis configuration settings"""
    
    redis_url: str = Field(..., env="REDIS_URL")
    redis_db: int = Field(0, env="REDIS_DB")
    redis_password: Optional[str] = Field(None, env="REDIS_PASSWORD")
    redis_timeout: int = Field(5, env="REDIS_TIMEOUT")
    redis_retry_on_timeout: bool = Field(True, env="REDIS_RETRY_ON_TIMEOUT")
    redis_max_connections: int = Field(50, env="REDIS_MAX_CONNECTIONS")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class SecurityConfig(BaseSettings):
    """Security configuration settings"""
    
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    password_min_length: int = Field(8, env="PASSWORD_MIN_LENGTH")
    max_login_attempts: int = Field(5, env="MAX_LOGIN_ATTEMPTS")
    lockout_duration_minutes: int = Field(15, env="LOCKOUT_DURATION_MINUTES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class FraudConfig(BaseSettings):
    """Fraud detection configuration settings"""
    
    default_risk_threshold: float = Field(0.7, env="DEFAULT_RISK_THRESHOLD")
    high_risk_threshold: float = Field(0.9, env="HIGH_RISK_THRESHOLD")
    velocity_window_minutes: int = Field(5, env="VELOCITY_WINDOW_MINUTES")
    velocity_threshold: int = Field(10, env="VELOCITY_THRESHOLD")
    amount_threshold: float = Field(10000.0, env="AMOUNT_THRESHOLD")
    ml_model_path: str = Field("models/", env="ML_MODEL_PATH")
    enable_real_time_scoring: bool = Field(True, env="ENABLE_REAL_TIME_SCORING")
    enable_pattern_detection: bool = Field(True, env="ENABLE_PATTERN_DETECTION")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Core Configuration Manager
class Settings(BaseSettings):
    """Main application settings"""
    
    # Application settings
    app_name: str = Field("Fraud Detection System", env="APP_NAME")
    app_version: str = Field(__version__, env="APP_VERSION")
    debug: bool = Field(False, env="DEBUG")
    environment: str = Field("production", env="ENVIRONMENT")
    
    # API settings
    api_v1_prefix: str = Field("/api/v1", env="API_V1_PREFIX")
    cors_origins: List[str] = Field(["*"], env="CORS_ORIGINS")
    
    # Logging settings
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_format: str = Field("json", env="LOG_FORMAT")
    
    # Component configurations
    database: DatabaseConfig = DatabaseConfig()
    redis: RedisConfig = RedisConfig()
    security: SecurityConfig = SecurityConfig()
    fraud: FraudConfig = FraudConfig()
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

# Logging Configuration
def setup_logging() -> None:
    """Configure structured logging for the application"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if settings.log_format == "json" 
            else structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level.upper())
    )

# Database Utilities
class DatabaseManager:
    """Database connection and session management"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = None
        self.SessionLocal = None
        self._initialize_engine()
    
    def _initialize_engine(self) -> None:
        """Initialize database engine with connection pooling"""
        self.engine = create_engine(
            self.config.database_url,
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_timeout=self.config.pool_timeout,
            pool_recycle=self.config.pool_recycle,
            echo=self.config.echo
        )
        
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
    
    def get_session(self) -> Session:
        """Get a database session"""
        return self.SessionLocal()
    
    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations"""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            with self.session_scope() as session:
                session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False

# Redis Cache Manager
class CacheManager:
    """Redis cache management with connection pooling"""
    
    def __init__(self, config: RedisConfig):
        self.config = config
        self.redis_client = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize Redis client with connection pooling"""
        self.redis_client = Redis.from_url(
            self.config.redis_url,
            db=self.config.redis_db,
            password=self.config.redis_password,
            socket_timeout=self.config.redis_timeout,
            retry_on_timeout=self.config.redis_retry_on_timeout,
            max_connections=self.config.redis_max_connections,
            decode_responses=True
        )
    
    def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        try:
            return self.redis_client.get(key)
        except Exception as e:
            logger.error("Cache get failed", key=key, error=str(e))
            return None
    
    def set(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL"""
        try:
            if ttl:
                return self.redis_client.setex(key, ttl, value)
            else:
                return self.redis_client.set(key, value)
        except Exception as e:
            logger.error("Cache set failed", key=key, error=str(e))
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            return bool(self.redis_client.delete(key))
        except Exception as e:
            logger.error("Cache delete failed", key=key, error=str(e))
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            return bool(self.redis_client.exists(key))
        except Exception as e:
            logger.error("Cache exists check failed", key=key, error=str(e))
            return False
    
    def health_check(self) -> bool:
        """Check Redis connectivity"""
        try:
            return self.redis_client.ping()
        except Exception as e:
            logger.error("Redis health check failed", error=str(e))
            return False

# Security Utilities
class SecurityUtils:
    """Security utilities for encryption, hashing, and token generation"""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        try:
            salt, password_hash = hashed_password.split(":")
            computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return computed_hash == password_hash
        except ValueError:
            return False
    
    @staticmethod
    def hash_data(data: str) -> str:
        """Create SHA-256 hash of data"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
        """Mask sensitive data showing only last few characters"""
        if len(data) <= visible_chars:
            return "*" * len(data)
        return "*" * (len(data) - visible_chars) + data[-visible_chars:]

# Performance Monitoring
class PerformanceMonitor:
    """Performance monitoring and metrics collection"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
    
    def record_metric(self, metric_name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a performance metric"""
        timestamp = datetime.utcnow().isoformat()
        metric_data = {
            "name": metric_name,
            "value": value,
            "timestamp": timestamp,
            "tags": tags or {}
        }
        
        # Store in Redis with TTL
        key = f"metric:{metric_name}:{timestamp}"
        self.cache.set(key, json.dumps(metric_data), ttl=86400)  # 24 hours
    
    def get_metrics(self, metric_name: str, hours: int = 1) -> List[Dict[str, Any]]:
        """Get metrics for the specified time period"""
        # This is a simplified implementation
        # In production, you'd use a proper time-series database
        metrics = []
        pattern = f"metric:{metric_name}:*"
        
        try:
            keys = self.cache.redis_client.keys(pattern)
            for key in keys:
                data = self.cache.get(key)
                if data:
                    metrics.append(json.loads(data))
        except Exception as e:
            logger.error("Failed to get metrics", metric_name=metric_name, error=str(e))
        
        return metrics

# Decorators
def timing_decorator(func):
    """Decorator to measure function execution time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = datetime.utcnow()
        try:
            result = func(*args, **kwargs)
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.info(
                "Function executed",
                function=func.__name__,
                execution_time_ms=execution_time
            )
            return result
        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.error(
                "Function failed",
                function=func.__name__,
                execution_time_ms=execution_time,
                error=str(e)
            )
            raise
    return wrapper

def retry_decorator(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry function execution on failure"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        logger.error(
                            "Function failed after retries",
                            function=func.__name__,
                            attempts=attempt + 1,
                            error=str(e)
                        )
                        raise
                    
                    logger.warning(
                        "Function failed, retrying",
                        function=func.__name__,
                        attempt=attempt + 1,
                        error=str(e)
                    )
                    
                    import time
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
        return wrapper
    return decorator

# Global Instances
db_manager = DatabaseManager(settings.database)
cache_manager = CacheManager(settings.redis)
performance_monitor = PerformanceMonitor(cache_manager)
security_utils = SecurityUtils()

# Health Check Function
def system_health_check() -> Dict[str, Any]:
    """Perform comprehensive system health check"""
    health_status = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "healthy",
        "components": {}
    }
    
    # Check database
    health_status["components"]["database"] = {
        "status": "healthy" if db_manager.health_check() else "unhealthy"
    }
    
    # Check Redis
    health_status["components"]["redis"] = {
        "status": "healthy" if cache_manager.health_check() else "unhealthy"
    }
    
    # Overall status
    if any(comp["status"] == "unhealthy" for comp in health_status["components"].values()):
        health_status["status"] = "unhealthy"
    
    return health_status

# Initialize logging on module import
setup_logging()

# Export public API
__all__ = [
    "settings",
    "db_manager",
    "cache_manager",
    "performance_monitor",
    "security_utils",
    "DatabaseManager",
    "CacheManager",
    "SecurityUtils",
    "PerformanceMonitor",
    "timing_decorator",
    "retry_decorator",
    "system_health_check",
    "setup_logging",
    "logger"
]

logger.info("Core module initialized", version=__version__, environment=settings.environment)



