from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import logging

from ..database import get_db, User, OTPCode, UserSession
from ..dependencies import (
    get_current_user, 
    get_current_active_user,
    api_rate_limiter,
    otp_rate_limiter,
    get_device_info,
    validate_mobile_format
)
from ..schemas import (
    SignupRequest,
    SigninRequest, 
    VerifyOTPRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    UpdateProfileRequest,
    BaseResponse
)
from ..exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    OTPExpiredError,
    OTPInvalidError,
    OTPAlreadyUsedError,
    InvalidTokenError,
    SessionExpiredError,
    RateLimitError
)
from .jwt_handler import jwt_handler
from .otp_service import otp_service

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/signup", response_model=BaseResponse)
async def signup(
    request: SignupRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """User signup - sends OTP for verification"""
    
    # Format mobile number
    mobile = validate_mobile_format(request.mobile)
    
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.email == request.email) | (User.mobile == mobile)
    ).first()
    
    if existing_user:
        if existing_user.email == request.email:
            raise UserAlreadyExistsError("email")
        else:
            raise UserAlreadyExistsError("mobile")
    
    # Send OTP
    try:
        await otp_service.send_otp(mobile, "signup", db)
        logger.info(f"Signup OTP sent to {mobile}")
    except Exception as e:
        logger.error(f"Failed to send signup OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to send OTP. Please try again."
        )
    
    return BaseResponse(
        success=True,
        message="OTP sent successfully. Please verify to complete signup.",
        data={
            "mobile": mobile,
            "expires_in": 300  # 5 minutes
        }
    )

@router.post("/signin", response_model=BaseResponse)
async def signin(
    request: SigninRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """User signin - sends OTP for verification"""
    
    # Format mobile number
    mobile = validate_mobile_format(request.mobile)
    
    # Check if user exists
    user = db.query(User).filter(User.mobile == mobile).first()
    if not user:
        raise UserNotFoundError()
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is deactivated. Please contact support."
        )
    
    # Send OTP
    try:
        await otp_service.send_otp(mobile, "signin", db)
        logger.info(f"Signin OTP sent to {mobile}")
    except Exception as e:
        logger.error(f"Failed to send signin OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to send OTP. Please try again."
        )
    
    return BaseResponse(
        success=True,
        message="OTP sent successfully. Please verify to sign in.",
        data={
            "mobile": mobile,
            "expires_in": 300  # 5 minutes
        }
    )

@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(
    request: VerifyOTPRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """Verify OTP and complete authentication"""
    
    # Format mobile number
    mobile = validate_mobile_format(request.mobile)
    
    # Verify OTP
    is_valid = await otp_service.verify_otp(mobile, request.otp, db)
    if not is_valid:
        raise OTPInvalidError()
    
    user = None
    
    if request.is_new_user:
        # This should not happen in normal flow, but handle gracefully
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request. Please use signup endpoint for new users."
        )
    else:
        # Get existing user
        user = db.query(User).filter(User.mobile == mobile).first()
        if not user:
            raise UserNotFoundError()
    
    # Update user verification and last login
    user.is_verified = True
    user.last_login = datetime.utcnow()
    
    # Generate tokens
    access_token = jwt_handler.create_access_token(user.id)
    refresh_token = jwt_handler.create_refresh_token(user.id)
    
    # Create session record
    device_info = get_device_info(http_request)
    session = UserSession(
        user_id=user.id,
        jwt_token_hash=jwt_handler.hash_token(access_token),
        refresh_token_hash=jwt_handler.hash_token(refresh_token),
        device_info=device_info,
        ip_address=device_info.get("ip_address"),
        expires_at=datetime.utcnow() + timedelta(minutes=jwt_handler.access_token_expire_minutes)
    )
    
    db.add(session)
    db.commit()
    
    logger.info(f"User {user.id} authenticated successfully")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=jwt_handler.access_token_expire_minutes * 60
    )

@router.post("/complete-signup", response_model=TokenResponse)
async def complete_signup(
    request: VerifyOTPRequest,
    signup_data: SignupRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """Complete signup after OTP verification"""
    
    # Format mobile number
    mobile = validate_mobile_format(request.mobile)
    
    # Verify OTP
    is_valid = await otp_service.verify_otp(mobile, request.otp, db)
    if not is_valid:
        raise OTPInvalidError()
    
    # Check if user already exists (race condition protection)
    existing_user = db.query(User).filter(
        (User.email == signup_data.email) | (User.mobile == mobile)
    ).first()
    
    if existing_user:
        raise UserAlreadyExistsError()
    
    # Create new user
    user = User(
        name=signup_data.name,
        email=signup_data.email,
        mobile=mobile,
        is_verified=True,
        is_active=True
    )
    
    db.add(user)
    db.flush()  # Get user ID
    
    # Generate tokens
    access_token = jwt_handler.create_access_token(user.id)
    refresh_token = jwt_handler.create_refresh_token(user.id)
    
    # Create session record
    device_info = get_device_info(http_request)
    session = UserSession(
        user_id=user.id,
        jwt_token_hash=jwt_handler.hash_token(access_token),
        refresh_token_hash=jwt_handler.hash_token(refresh_token),
        device_info=device_info,
        ip_address=device_info.get("ip_address"),
        expires_at=datetime.utcnow() + timedelta(minutes=jwt_handler.access_token_expire_minutes)
    )
    
    db.add(session)
    db.commit()
    
    logger.info(f"New user {user.id} registered successfully")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=jwt_handler.access_token_expire_minutes * 60
    )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """Refresh access token using refresh token"""
    
    # Verify refresh token
    payload = jwt_handler.verify_refresh_token(request.refresh_token)
    if not payload:
        raise InvalidTokenError()
    
    user_id = payload.get("user_id")
    
    # Check if refresh token exists in database
    token_hash = jwt_handler.hash_token(request.refresh_token)
    session = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.refresh_token_hash == token_hash,
        UserSession.is_active == True
    ).first()
    
    if not session:
        raise InvalidTokenError()
    
    # Get user
    user = db.query(User).filter(
        User.id == user_id,
        User.is_active == True
    ).first()
    
    if not user:
        raise UserNotFoundError()
    
    # Generate new tokens
    new_access_token = jwt_handler.create_access_token(user.id)
    new_refresh_token = jwt_handler.create_refresh_token(user.id)
    
    # Update session
    session.jwt_token_hash = jwt_handler.hash_token(new_access_token)
    session.refresh_token_hash = jwt_handler.hash_token(new_refresh_token)
    session.expires_at = datetime.utcnow() + timedelta(minutes=jwt_handler.access_token_expire_minutes)
    session.last_used_at = datetime.utcnow()
    
    db.commit()
    
    logger.info(f"Token refreshed for user {user.id}")
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=jwt_handler.access_token_expire_minutes * 60
    )

@router.post("/logout", response_model=BaseResponse)
async def logout(
    http_request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Logout user and invalidate session"""
    
    # Get authorization header
    auth_header = http_request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise InvalidTokenError()
    
    token = auth_header.split(" ")[1]
    token_hash = jwt_handler.hash_token(token)
    
    # Deactivate session
    session = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.jwt_token_hash == token_hash,
        UserSession.is_active == True
    ).first()
    
    if session:
        session.is_active = False
        db.commit()
    
    logger.info(f"User {current_user.id} logged out")
    
    return BaseResponse(
        success=True,
        message="Logged out successfully"
    )

@router.post("/logout-all", response_model=BaseResponse)
async def logout_all_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Logout from all sessions"""
    
    # Deactivate all user sessions
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active == True
    ).update({"is_active": False})
    
    db.commit()
    
    logger.info(f"All sessions logged out for user {current_user.id}")
    
    return BaseResponse(
        success=True,
        message="Logged out from all sessions successfully"
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user information"""
    return UserResponse.from_orm(current_user)

@router.put("/profile", response_model=UserResponse)
async def update_profile(
    request: UpdateProfileRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update user profile"""
    
    # Check if email is being changed and already exists
    if request.email and request.email != current_user.email:
        existing_user = db.query(User).filter(
            User.email == request.email,
            User.id != current_user.id
        ).first()
        
        if existing_user:
            raise UserAlreadyExistsError("email")
    
    # Update fields
    if request.name:
        current_user.name = request.name
    
    if request.email:
        current_user.email = request.email
        # If email changed, mark as unverified
        if request.email != current_user.email:
            current_user.is_verified = False
    
    current_user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(current_user)
    
    logger.info(f"Profile updated for user {current_user.id}")
    
    return UserResponse.from_orm(current_user)

@router.post("/resend-otp", response_model=BaseResponse)
async def resend_otp(
    mobile: str,
    purpose: str,  # signup, signin
    db: Session = Depends(get_db),
    _: bool = Depends(otp_rate_limiter)
):
    """Resend OTP"""
    
    # Format mobile number
    mobile = validate_mobile_format(mobile)
    
    # Validate purpose
    if purpose not in ["signup", "signin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Purpose must be 'signup' or 'signin'"
        )
    
    # For signin, check if user exists
    if purpose == "signin":
        user = db.query(User).filter(User.mobile == mobile).first()
        if not user:
            raise UserNotFoundError()
    
    # Send OTP
    try:
        await otp_service.send_otp(mobile, purpose, db)
        logger.info(f"OTP resent to {mobile} for {purpose}")
    except Exception as e:
        logger.error(f"Failed to resend OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to send OTP. Please try again."
        )
    
    return BaseResponse(
        success=True,
        message="OTP sent successfully",
        data={
            "mobile": mobile,
            "expires_in": 300
        }
    )

@router.get("/sessions", response_model=BaseResponse)
async def get_active_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's active sessions"""
    
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    ).all()
    
    session_data = []
    for session in sessions:
        session_data.append({
            "id": session.id,
            "device_info": session.device_info,
            "ip_address": session.ip_address,
            "created_at": session.created_at,
            "last_used_at": session.last_used_at,
            "expires_at": session.expires_at
        })
    
    return BaseResponse(
        success=True,
        message="Active sessions retrieved",
        data={
            "sessions": session_data,
            "total": len(session_data)
        }
    )

@router.delete("/sessions/{session_id}", response_model=BaseResponse)
async def revoke_session(
    session_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific session"""
    
    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == current_user.id,
        UserSession.is_active == True
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session.is_active = False
    db.commit()
    
    logger.info(f"Session {session_id} revoked for user {current_user.id}")
    
    return BaseResponse(
        success=True,
        message="Session revoked successfully"
    )