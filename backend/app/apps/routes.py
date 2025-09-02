from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
from datetime import datetime, timedelta

from ..database import get_db, User, ConnectedApp, AppScanLog
from ..dependencies import get_current_active_user, api_rate_limiter
from ..schemas import (
    ConnectAppRequest,
    UpdateAppPermissionsRequest,
    ConnectedAppResponse,
    AppStatsResponse,
    BaseResponse,
    PaginationParams,
    PaginatedResponse
)
from ..exceptions import (
    AppNotFoundError,
    AppAlreadyConnectedError,
    InvalidAppTypeError,
    PermissionDeniedError
)
from .manager import app_manager
from .permissions import permission_manager
from .scanners import scanner_factory

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/supported", response_model=BaseResponse)
async def get_supported_apps():
    """Get list of supported app types"""
    
    supported_apps = [
        {
            "type": "whatsapp",
            "name": "WhatsApp",
            "description": "Scan WhatsApp messages for fraud detection",
            "permissions": ["read_messages", "scan_media", "block_contacts"],
            "icon": "whatsapp-icon.svg"
        },
        {
            "type": "messages",
            "name": "SMS Messages", 
            "description": "Monitor SMS messages for phishing and fraud",
            "permissions": ["read_sms", "block_numbers", "auto_delete"],
            "icon": "messages-icon.svg"
        },
        {
            "type": "email",
            "name": "Email",
            "description": "Scan emails for phishing and malicious content",
            "permissions": ["read_emails", "quarantine", "block_senders"],
            "icon": "email-icon.svg"
        },
        {
            "type": "telegram",
            "name": "Telegram",
            "description": "Monitor Telegram messages and channels",
            "permissions": ["read_messages", "scan_channels", "block_users"],
            "icon": "telegram-icon.svg"
        },
        {
            "type": "instagram",
            "name": "Instagram",
            "description": "Scan Instagram DMs and detect fake accounts",
            "permissions": ["read_dms", "scan_profiles", "block_accounts"],
            "icon": "instagram-icon.svg"
        },
        {
            "type": "gallery",
            "name": "Gallery",
            "description": "Scan images for malicious QR codes and content",
            "permissions": ["read_images", "scan_qr_codes", "quarantine_files"],
            "icon": "gallery-icon.svg"
        }
    ]
    
    return BaseResponse(
        success=True,
        message="Supported apps retrieved successfully",
        data={"apps": supported_apps}
    )

@router.post("/connect", response_model=BaseResponse)
async def connect_app(
    request: ConnectAppRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    _: bool = Depends(api_rate_limiter)
):
    """Connect a new app for monitoring"""
    
    # Check if app type is supported
    if not app_manager.is_app_supported(request.app_type):
        raise InvalidAppTypeError(request.app_type)
    
    # Check if app is already connected
    existing_app = db.query(ConnectedApp).filter(
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.app_type == request.app_type,
        ConnectedApp.is_active == True
    ).first()
    
    if existing_app:
        raise AppAlreadyConnectedError(request.app_type)
    
    try:
        # Initialize app connection
        connection_result = await app_manager.connect_app(
            user_id=current_user.id,
            app_type=request.app_type,
            permissions=request.permissions,
            db=db
        )
        
        if not connection_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=connection_result["error"]
            )
        
        # Create connected app record
        connected_app = ConnectedApp(
            user_id=current_user.id,
            app_type=request.app_type,
            app_name=app_manager.get_app_name(request.app_type),
            connection_status="connected",
            permissions=request.permissions or {},
            connection_data=connection_result.get("connection_data", {}),
            connected_at=datetime.utcnow()
        )
        
        db.add(connected_app)
        db.commit()
        db.refresh(connected_app)
        
        logger.info(f"App {request.app_type} connected for user {current_user.id}")
        
        return BaseResponse(
            success=True,
            message=f"{app_manager.get_app_name(request.app_type)} connected successfully",
            data={
                "app_id": connected_app.id,
                "app_type": connected_app.app_type,
                "connection_status": connected_app.connection_status
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to connect app {request.app_type}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect app. Please try again."
        )

@router.get("/connected", response_model=List[ConnectedAppResponse])
async def get_connected_apps(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user's connected apps"""
    
    connected_apps = db.query(ConnectedApp).filter(
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).order_by(ConnectedApp.connected_at.desc()).all()
    
    return [ConnectedAppResponse.from_orm(app) for app in connected_apps]

@router.get("/connected/{app_id}", response_model=ConnectedAppResponse)
async def get_connected_app(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get specific connected app details"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    return ConnectedAppResponse.from_orm(connected_app)

@router.put("/connected/{app_id}/permissions", response_model=BaseResponse)
async def update_app_permissions(
    app_id: int,
    request: UpdateAppPermissionsRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update app permissions"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    # Validate permissions
    valid_permissions = permission_manager.get_valid_permissions(connected_app.app_type)
    for permission in request.permissions.keys():
        if permission not in valid_permissions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permission: {permission}"
            )
    
    try:
        # Update permissions in app manager
        update_result = await app_manager.update_permissions(
            app_id=app_id,
            permissions=request.permissions,
            db=db
        )
        
        if not update_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=update_result["error"]
            )
        
        # Update database
        connected_app.permissions = request.permissions
        connected_app.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Permissions updated for app {app_id}")
        
        return BaseResponse(
            success=True,
            message="Permissions updated successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to update permissions for app {app_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update permissions"
        )

@router.post("/connected/{app_id}/scan", response_model=BaseResponse)
async def trigger_manual_scan(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Trigger manual scan for connected app"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    if connected_app.connection_status != "connected":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="App is not properly connected"
        )
    
    try:
        # Get scanner for app type
        scanner = scanner_factory.get_scanner(connected_app.app_type)
        
        # Trigger scan
        scan_result = await scanner.scan_app(
            user_id=current_user.id,
            app_id=app_id,
            db=db
        )
        
        # Update last scan time
        connected_app.last_scan_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Manual scan triggered for app {app_id}")
        
        return BaseResponse(
            success=True,
            message="Scan initiated successfully",
            data={
                "scan_id": scan_result.get("scan_id"),
                "estimated_duration": scan_result.get("estimated_duration", "2-5 minutes")
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to trigger scan for app {app_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate scan"
        )

@router.delete("/connected/{app_id}", response_model=BaseResponse)
async def disconnect_app(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Disconnect an app"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    try:
        # Disconnect from app manager
        disconnect_result = await app_manager.disconnect_app(
            app_id=app_id,
            db=db
        )
        
        if not disconnect_result["success"]:
            logger.warning(f"App manager disconnect failed: {disconnect_result['error']}")
        
        # Update database
        connected_app.is_active = False
        connected_app.connection_status = "disconnected"
        connected_app.disconnected_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"App {app_id} disconnected for user {current_user.id}")
        
        return BaseResponse(
            success=True,
            message=f"{connected_app.app_name} disconnected successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to disconnect app {app_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disconnect app"
        )

@router.get("/connected/{app_id}/stats", response_model=AppStatsResponse)
async def get_app_stats(
    app_id: int,
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get app statistics"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get scan logs
    scan_logs = db.query(AppScanLog).filter(
        AppScanLog.app_id == app_id,
        AppScanLog.created_at >= start_date,
        AppScanLog.created_at <= end_date
    ).all()
    
    # Calculate stats
    total_scanned = sum(log.items_scanned for log in scan_logs)
    threats_detected = sum(log.threats_detected for log in scan_logs)
    last_scan = connected_app.last_scan_at
    
    protection_rate = 0.0
    if total_scanned > 0:
        protection_rate = (threats_detected / total_scanned) * 100
    
    return AppStatsResponse(
        app_type=connected_app.app_type,
        total_scanned=total_scanned,
        threats_detected=threats_detected,
        last_scan=last_scan,
        protection_rate=protection_rate
    )

@router.get("/connected/{app_id}/scan-history", response_model=PaginatedResponse)
async def get_scan_history(
    app_id: int,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scan history for connected app"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    # Get total count
    total = db.query(AppScanLog).filter(
        AppScanLog.app_id == app_id
    ).count()
    
    # Get paginated results
    scan_logs = db.query(AppScanLog).filter(
        AppScanLog.app_id == app_id
    ).order_by(
        AppScanLog.created_at.desc()
    ).offset(
        (pagination.page - 1) * pagination.limit
    ).limit(pagination.limit).all()
    
    # Format scan history
    scan_history = []
    for log in scan_logs:
        scan_history.append({
            "id": log.id,
            "scan_type": log.scan_type,
            "status": log.status,
            "items_scanned": log.items_scanned,
            "threats_detected": log.threats_detected,
            "scan_duration": log.scan_duration,
            "started_at": log.created_at,
            "completed_at": log.completed_at,
            "error_message": log.error_message
        })
    
    return PaginatedResponse(
        items=scan_history,
        total=total,
        page=pagination.page,
        limit=pagination.limit,
        pages=(total + pagination.limit - 1) // pagination.limit,
        has_next=pagination.page * pagination.limit < total,
        has_prev=pagination.page > 1
    )

@router.post("/connected/{app_id}/test-connection", response_model=BaseResponse)
async def test_app_connection(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test app connection status"""
    
    connected_app = db.query(ConnectedApp).filter(
        ConnectedApp.id == app_id,
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True
    ).first()
    
    if not connected_app:
        raise AppNotFoundError()
    
    try:
        # Test connection
        test_result = await app_manager.test_connection(
            app_id=app_id,
            db=db
        )
        
        # Update connection status
        if test_result["success"]:
            connected_app.connection_status = "connected"
            connected_app.last_health_check = datetime.utcnow()
        else:
            connected_app.connection_status = "error"
            connected_app.connection_error = test_result.get("error")
        
        db.commit()
        
        return BaseResponse(
            success=test_result["success"],
            message=test_result.get("message", "Connection test completed"),
            data={
                "connection_status": connected_app.connection_status,
                "last_check": connected_app.last_health_check,
                "details": test_result.get("details", {})
            }
        )
        
    except Exception as e:
        logger.error(f"Connection test failed for app {app_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Connection test failed"
        )

@router.get("/permissions/{app_type}", response_model=BaseResponse)
async def get_app_permissions(app_type: str):
    """Get available permissions for app type"""
    
    if not app_manager.is_app_supported(app_type):
        raise InvalidAppTypeError(app_type)
    
    permissions = permission_manager.get_permissions_info(app_type)
    
    return BaseResponse(
        success=True,
        message="Permissions retrieved successfully",
        data={"permissions": permissions}
    )

@router.post("/bulk-scan", response_model=BaseResponse)
async def trigger_bulk_scan(
    app_types: Optional[List[str]] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Trigger bulk scan across multiple apps"""
    
    # Get connected apps
    query = db.query(ConnectedApp).filter(
        ConnectedApp.user_id == current_user.id,
        ConnectedApp.is_active == True,
        ConnectedApp.connection_status == "connected"
    )
    
    if app_types:
        query = query.filter(ConnectedApp.app_type.in_(app_types))
    
    connected_apps = query.all()
    
    if not connected_apps:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No connected apps found for scanning"
        )
    
    scan_results = []
    
    for app in connected_apps:
        try:
            scanner = scanner_factory.get_scanner(app.app_type)
            result = await scanner.scan_app(
                user_id=current_user.id,
                app_id=app.id,
                db=db
            )
            
            scan_results.append({
                "app_type": app.app_type,
                "app_id": app.id,
                "success": True,
                "scan_id": result.get("scan_id")
            })
            
            # Update last scan time
            app.last_scan_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Bulk scan failed for app {app.id}: {e}")
            scan_results.append({
                "app_type": app.app_type,
                "app_id": app.id,
                "success": False,
                "error": str(e)
            })
    
    db.commit()
    
    successful_scans = sum(1 for result in scan_results if result["success"])
    
    return BaseResponse(
        success=True,
        message=f"Bulk scan initiated for {successful_scans}/{len(scan_results)} apps",
        data={
            "results": scan_results,
            "total_apps": len(scan_results),
            "successful_scans": successful_scans
        }
    )

