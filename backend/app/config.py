from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    # Database
    database_url: str
    redis_url: str
    
    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 30
    
    # Twilio
    twilio_account_sid: str
    twilio_auth_token: str
    twilio_phone_number: str
    
    # Application
    app_name: str = "SatyaLens"
    app_version: str = "1.0.0"
    debug: bool = False
    cors_origins: List[str] = ["http://localhost:3000"]
    
    # Rate Limiting
    otp_rate_limit_per_hour: int = 3
    api_rate_limit_per_minute: int = 100
    
    # Fraud Detection
    fraud_detection_threshold: int = 80
    auto_block_threshold: int = 90
    scan_interval_seconds: int = 30
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()


