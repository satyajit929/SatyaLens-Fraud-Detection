from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re

# Base schemas
class BaseResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None

# Auth schemas
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    
    @validator('name')
    def validate_name(cls, v):
        if len(v.strip()) < 2 or len(v.strip()) > 100:
            raise ValueError('Name must be between 2 and 100 characters')
        return v.strip()
    
    @validator('mobile')
    def validate_mobile(cls, v):
        # Indian mobile number validation
        pattern = r'^(\+91|91)?[6-9]\d{9}$'
        if not re.match(pattern, v.replace(' ', '').replace('-', '')):
            raise ValueError('Invalid Indian mobile number format')
        return v.replace(' ', '').replace('-', '')

class SigninRequest(BaseModel):
    mobile: str
    
    @validator('mobile')
    def validate_mobile(cls, v):
        pattern = r'^(\+91|91)?[6-9]\d{9}$'
        if not re.match(pattern, v.replace(' ', '').replace('-', '')):
            raise ValueError('Invalid Indian mobile number format')
        return v.replace(' ', '').replace('-', '')

class VerifyOTPRequest(BaseModel):
    mobile: str
    otp: str
    is_new_user: bool
    
    @validator('otp')
    def validate_otp(cls, v):
        if not v.isdigit() or len(v) != 6:
            raise ValueError('OTP must be 6 digits')
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    mobile: str
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v and (len(v.strip()) < 2 or len(v.strip()) > 100):
            raise ValueError('Name must be between 2 and 100 characters')
        return v.strip() if v else v

# App schemas
class ConnectAppRequest(BaseModel):
    app_type: str
    permissions: Optional[Dict[str, bool]] = {}
    
    @validator('app_type')
    def validate_app_type(cls, v):
        allowed_apps = ['whatsapp', 'messages', 'email', 'telegram', 'instagram', 'gallery']
        if v not in allowed_apps:
            raise ValueError(f'App type must be one of: {", ".join(allowed_apps)}')
        return v

class UpdateAppPermissionsRequest(BaseModel):
    permissions: Dict[str, bool]

class ConnectedAppResponse(BaseModel):
    id: int
    app_type: str
    app_name: Optional[str]
    connection_status: str
    permissions: Dict[str, Any]
    connected_at: datetime
    last_scan_at: Optional[datetime]
    total_messages_scanned: int
    threats_detected: int
    
    class Config:
        from_attributes = True

class AppStatsResponse(BaseModel):
    app_type: str
    total_scanned: int
    threats_detected: int
    last_scan: Optional[datetime]
    protection_rate: float

# Monitoring schemas
class FraudLogResponse(BaseModel):
    id: int
    app_type: str
    content_type: str
    content_preview: Optional[str]
    risk_score: int
    fraud_indicators: List[str]
    action_taken: str
    detection_method: str
    detected_at: datetime
    reviewed_at: Optional[datetime]
    reviewer_action: Optional[str]
    
    class Config:
        from_attributes = True

class DashboardStatsResponse(BaseModel):
    connected_apps: int
    messages_scanned: int
    threats_blocked: int
    protection_rate: float
    recent_activity: List[Dict[str, Any]]

class ActivityLogResponse(BaseModel):
    id: int
    timestamp: datetime
    app_type: str
    action: str
    description: str
    risk_score: int
    status: str
    
    class Config:
        from_attributes = True

class ThreatAnalysisResponse(BaseModel):
    threat_types: Dict[str, int]
    risk_distribution: Dict[str, int]
    blocked_vs_allowed: Dict[str, int]
    trends: List[Dict[str, Any]]

class ReviewFraudRequest(BaseModel):
    action: str  # confirmed, false_positive, escalated
    
    @validator('action')
    def validate_action(cls, v):
        allowed_actions = ['confirmed', 'false_positive', 'escalated']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v

# WebSocket schemas
class WebSocketMessage(BaseModel):
    type: str
    data: Dict[str, Any]
    timestamp: datetime = datetime.utcnow()

class RealTimeAlert(BaseModel):
    alert_id: str
    user_id: int
    app_type: str
    threat_type: str
    risk_score: int
    content_preview: str
    action_taken: str
    timestamp: datetime

class ConnectionStatus(BaseModel):
    user_id: int
    connected_apps: List[str]
    active_scans: int
    last_activity: datetime

# Fraud Detection schemas
class ContentAnalysisRequest(BaseModel):
    content: str
    content_type: str  # text, image, video, email, link
    app_type: str
    metadata: Optional[Dict[str, Any]] = {}

class ContentAnalysisResponse(BaseModel):
    risk_score: int
    fraud_indicators: List[str]
    recommended_action: str
    confidence: float
    analysis_details: Dict[str, Any]

class FraudPattern(BaseModel):
    pattern_id: str
    pattern_type: str
    description: str
    risk_weight: int
    is_active: bool

class ThreatIntelligence(BaseModel):
    threat_id: str
    threat_type: str
    indicators: List[str]
    severity: str
    source: str
    created_at: datetime

# Settings schemas
class UserPreferences(BaseModel):
    notifications_enabled: bool = True
    email_alerts: bool = True
    sms_alerts: bool = False
    auto_block_threshold: int = 90
    scan_frequency: str = "real_time"  # real_time, hourly, daily

class UpdatePreferencesRequest(BaseModel):
    notifications_enabled: Optional[bool] = None
    email_alerts: Optional[bool] = None
    sms_alerts: Optional[bool] = None
    auto_block_threshold: Optional[int] = None
    scan_frequency: Optional[str] = None
    
    @validator('auto_block_threshold')
    def validate_threshold(cls, v):
        if v is not None and (v < 0 or v > 100):
            raise ValueError('Auto block threshold must be between 0 and 100')
        return v
    
    @validator('scan_frequency')
    def validate_frequency(cls, v):
        if v is not None:
            allowed_frequencies = ['real_time', 'hourly', 'daily']
            if v not in allowed_frequencies:
                raise ValueError(f'Scan frequency must be one of: {", ".join(allowed_frequencies)}')
        return v

# Pagination schemas
class PaginationParams(BaseModel):
    page: int = 1
    limit: int = 20
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError('Page must be greater than 0')
        return v
    
    @validator('limit')
    def validate_limit(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Limit must be between 1 and 100')
        return v

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    limit: int
    pages: int
    has_next: bool
    has_prev: bool

# Filter schemas
class DateRangeFilter(BaseModel):
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class FraudLogFilter(BaseModel):
    app_type: Optional[str] = None
    content_type: Optional[str] = None
    min_risk_score: Optional[int] = None
    max_risk_score: Optional[int] = None
    action_taken: Optional[str] = None
    date_range: Optional[DateRangeFilter] = None

# Export schemas
class ExportRequest(BaseModel):
    export_type: str  # csv, json, pdf
    data_type: str    # fraud_logs, activity_logs, stats
    filters: Optional[Dict[str, Any]] = {}
    date_range: Optional[DateRangeFilter] = None
    
    @validator('export_type')
    def validate_export_type(cls, v):
        allowed_types = ['csv', 'json', 'pdf']
        if v not in allowed_types:
            raise ValueError(f'Export type must be one of: {", ".join(allowed_types)}')
        return v
    
    @validator('data_type')
    def validate_data_type(cls, v):
        allowed_types = ['fraud_logs', 'activity_logs', 'stats']
        if v not in allowed_types:
            raise ValueError(f'Data type must be one of: {", ".join(allowed_types)}')
        return v

# System schemas
class SystemHealth(BaseModel):
    status: str
    database: str
    redis: str
    fraud_engine: str
    background_tasks: str
    timestamp: datetime

class SystemMetrics(BaseModel):
    active_users: int
    connected_apps: int
    messages_processed: int
    threats_detected: int
    system_load: float
    memory_usage: float
    uptime: int
