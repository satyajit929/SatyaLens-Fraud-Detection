from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, DECIMAL, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from .config import settings

# Database engine
engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    mobile = Column(String(15), unique=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    connected_apps = relationship("ConnectedApp", back_populates="user")
    fraud_logs = relationship("FraudLog", back_populates="user")
    sessions = relationship("UserSession", back_populates="user")

class ConnectedApp(Base):
    __tablename__ = "connected_apps"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_type = Column(String(50), nullable=False)  # whatsapp, messages, etc.
    app_name = Column(String(100))
    connection_status = Column(String(20), default="active")
    permissions = Column(JSONB, default={})
    connected_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime)
    total_messages_scanned = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    
    # Relationships
    user = relationship("User", back_populates="connected_apps")

class OTPCode(Base):
    __tablename__ = "otp_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    mobile = Column(String(15), nullable=False, index=True)
    otp_code = Column(String(6), nullable=False)
    purpose = Column(String(20), nullable=False)  # signup, signin, reset
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    used_at = Column(DateTime)

class FraudLog(Base):
    __tablename__ = "fraud_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_type = Column(String(50), nullable=False)
    content_type = Column(String(50))  # message, image, video, email, link
    content_preview = Column(Text)
    risk_score = Column(Integer, nullable=False)  # 0-100
    fraud_indicators = Column(JSONB, default=[])
    action_taken = Column(String(20), nullable=False)  # allowed, blocked, quarantined
    detection_method = Column(String(50))  # ai_model, rule_based, user_report
    detected_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)
    reviewer_action = Column(String(20))  # confirmed, false_positive, escalated
    
    # Relationships
    user = relationship("User", back_populates="fraud_logs")

class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    jwt_token_hash = Column(String(255), nullable=False)
    refresh_token_hash = Column(String(255))
    device_info = Column(JSONB, default={})
    ip_address = Column(String(45))
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")

# Database dependency
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables
def create_tables():
    Base.metadata.create_all(bind=engine)