from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import asyncio
import json
import logging
from datetime import datetime, timedelta
from enum import Enum

from ..database import get_db, User, ConnectedApp, ThreatDetection, Alert, SystemMetric
from ..auth.dependencies import get_current_user
from .monitor import ThreatMonitor, SystemMonitor
from .alerts import AlertManager, AlertType, AlertSeverity
from .metrics import MetricsCollector, PerformanceTracker
from .realtime import RealtimeProcessor, EventProcessor, ConnectionManager
from .scheduler import MonitoringScheduler
from ..config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

# Initialize monitoring components
threat_monitor = ThreatMonitor()
system_monitor = SystemMonitor()
alert_manager = AlertManager()
metrics_collector = MetricsCollector()
performance_tracker = PerformanceTracker()
realtime_processor = RealtimeProcessor()
event_processor = EventProcessor()
connection_manager = ConnectionManager()
monitoring_scheduler = MonitoringScheduler()

class MonitoringStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class MonitorType(str, Enum):
    THREAT_DETECTION = "threat_detection"
    HEALTH_CHECK = "health_check"
    PERFORMANCE = "performance"
    SECURITY_SCAN = "security_scan"

class Priority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    URGENT = "urgent"

# Monitoring Status and Control Endpoints

@router.get("/status")
async def get_monitoring_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current monitoring system status"""
    try:
        # Get system status
        system_status = await system_monitor.get_status()
        
        # Get user's monitoring statistics
        user_stats = await get_user_monitoring_stats(current_user.id, db)
        
        # Get active monitors for user
        active_monitors = await threat_monitor.get_active_monitors(current_user.id)
        
        return {
            "success": True,
            "data": {
                "status": system_status["status"],
                "uptime": system_status["uptime"],
                "system_health": system_status["health"],
                "user_stats": user_stats,
                "active_monitors": len(active_monitors),
                "monitoring_enabled": system_status["monitoring_enabled"],
                "last_updated": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get monitoring status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get monitoring status")

@router.post("/start")
async def start_monitoring(
    request: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start monitoring for specific apps or all connected apps"""
    try:
        app_ids = request.get("app_ids", [])
        monitor_types = request.get("monitor_types", ["threat_detection"])
        priority = request.get("priority", "normal")
        
        # Validate app ownership
        if app_ids:
            user_apps = db.query(ConnectedApp).filter(
                ConnectedApp.user_id == current_user.id,
                ConnectedApp.id.in_(app_ids),
                ConnectedApp.is_active == True
            ).all()
            
            if len(user_apps) != len(app_ids):
                raise HTTPException(status_code=404, detail="Some apps not found or not owned by user")
        else:
            # Get all user's connected apps
            user_apps = db.query(ConnectedApp).filter(
                ConnectedApp.user_id == current_user.id,
                ConnectedApp.is_active == True
            ).all()
            app_ids = [app.id for app in user_apps]
        
        # Start monitoring tasks
        started_monitors = []
        for app_id in app_ids:
            for monitor_type in monitor_types:
                monitor_id = await threat_monitor.start_monitoring(
                    app_id=app_id,
                    monitor_type=monitor_type,
                    priority=priority,
                    user_id=current_user.id
                )
                started_monitors.append({
                    "monitor_id": monitor_id,
                    "app_id": app_id,
                    "type": monitor_type
                })
        
        # Log monitoring start event
        await event_processor.process_event({
            "type": "monitoring_started",
            "user_id": current_user.id,
            "app_ids": app_ids,
            "monitor_types": monitor_types,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "message": f"Started monitoring for {len(app_ids)} apps",
            "data": {
                "started_monitors": started_monitors,
                "total_monitors": len(started_monitors)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to start monitoring")

@router.post("/stop")
async def stop_monitoring(
    request: Dict[str, Any],
    current_user: User = Depends(get_current_user)
):
    """Stop monitoring for specific apps or all monitoring"""
    try:
        app_ids = request.get("app_ids", [])
        monitor_ids = request.get("monitor_ids", [])
        stop_all = request.get("stop_all", False)
        
        stopped_monitors = []
        
        if stop_all:
            # Stop all monitoring for user
            stopped_monitors = await threat_monitor.stop_all_monitoring(current_user.id)
        elif monitor_ids:
            # Stop specific monitors
            for monitor_id in monitor_ids:
                success = await threat_monitor.stop_monitoring(monitor_id, current_user.id)
                if success:
                    stopped_monitors.append(monitor_id)
        elif app_ids:
            # Stop monitoring for specific apps
            for app_id in app_ids:
                monitors = await threat_monitor.stop_app_monitoring(app_id, current_user.id)
                stopped_monitors.extend(monitors)
        
        return {
            "success": True,
            "message": f"Stopped {len(stopped_monitors)} monitors",
            "data": {
                "stopped_monitors": stopped_monitors
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop monitoring")

@router.get("/active")
async def get_active_monitors(
    current_user: User = Depends(get_current_user)
):
    """Get list of currently active monitoring tasks"""
    try:
        active_monitors = await threat_monitor.get_active_monitors(current_user.id)
        
        return {
            "success": True,
            "data": {
                "active_monitors": active_monitors,
                "total_active": len(active_monitors)
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get active monitors: {e}")
        raise HTTPException(status_code=500, detail="Failed to get active monitors")

# Alert Management Endpoints

@router.get("/alerts")
async def get_alerts(
    severity: Optional[AlertSeverity] = Query(None),
    status: Optional[str] = Query(None),
    alert_type: Optional[AlertType] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's alerts with filtering and pagination"""
    try:
        # Build query
        query = db.query(Alert).filter(Alert.user_id == current_user.id)
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if status:
            query = query.filter(Alert.status == status)
        
        if alert_type:
            query = query.filter(Alert.alert_type == alert_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        alerts = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
        
        # Format alerts
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "id": alert.id,
                "type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "message": alert.message,
                "status": alert.status,
                "created_at": alert.created_at.isoformat(),
                "read_at": alert.read_at.isoformat() if alert.read_at else None,
                "metadata": alert.metadata
            })
        
        return {
            "success": True,
            "data": {
                "alerts": formatted_alerts,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")

@router.put("/alerts/{alert_id}/read")
async def mark_alert_read(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark a specific alert as read"""
    try:
        alert = db.query(Alert).filter(
            Alert.id == alert_id,
            Alert.user_id == current_user.id
        ).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        alert.status = "read"
        alert.read_at = datetime.utcnow()
        db.commit()
        
        return {
            "success": True,
            "message": "Alert marked as read"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark alert as read: {e}")
        raise HTTPException(status_code=500, detail="Failed to update alert")

@router.put("/alerts/settings")
async def update_alert_settings(
    settings_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user's alert preferences and notification settings"""
    try:
        # Update user's alert settings
        success = await alert_manager.update_user_settings(
            user_id=current_user.id,
            settings=settings_data,
            db=db
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to update alert settings")
        
        return {
            "success": True,
            "message": "Alert settings updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update alert settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update alert settings")

# Metrics and Analytics Endpoints

@router.get("/metrics/system")
async def get_system_metrics(
    timeframe: str = Query("1h", regex="^(1h|6h|24h|7d|30d)$"),
    current_user: User = Depends(get_current_user)
):
    """Get system performance metrics and health indicators"""
    try:
        metrics = await metrics_collector.get_system_metrics(timeframe)
        
        return {
            "success": True,
            "data": metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system metrics")

@router.get("/metrics/threats")
async def get_threat_metrics(
    timeframe: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get threat detection statistics and trends"""
    try:
        # Calculate timeframe
        now = datetime.utcnow()
        timeframe_hours = {
            "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720
        }
        hours = timeframe_hours.get(timeframe, 24)
        start_time = now - timedelta(hours=hours)
        
        # Get threat statistics for user
        threat_stats = await get_user_threat_stats(current_user.id, start_time, now, db)
        
        return {
            "success": True,
            "data": threat_stats
        }
        
    except Exception as e:
        logger.error(f"Failed to get threat metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get threat metrics")

@router.get("/metrics/performance")
async def get_performance_metrics(
    timeframe: str = Query("1h", regex="^(1h|6h|24h|7d|30d)$"),
    current_user: User = Depends(get_current_user)
):
    """Get detailed performance analytics and historical data"""
    try:
        performance_data = await performance_tracker.get_performance_metrics(
            user_id=current_user.id,
            timeframe=timeframe
        )
        
        return {
            "success": True,
            "data": performance_data
        }
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")

# WebSocket endpoint for real-time monitoring
@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for real-time monitoring events"""
    try:
        # Authenticate user from token
        user = await authenticate_websocket_user(token, db)
        if not user:
            await websocket.close(code=4001, reason="Authentication failed")
            return
        
        # Accept connection
        await connection_manager.connect(websocket, user.id)
        
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "subscribe":
                    await handle_subscription(websocket, user.id, message.get("channels", []))
                elif message.get("type") == "unsubscribe":
                    await handle_unsubscription(websocket, user.id, message.get("channels", []))
                elif message.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                
        except WebSocketDisconnect:
            pass
        finally:
            connection_manager.disconnect(websocket, user.id)
            
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close(code=4000, reason="Internal server error")

# Helper functions
async def get_user_monitoring_stats(user_id: int, db: Session) -> Dict[str, Any]:
    """Get monitoring statistics for a user"""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Get today's statistics
    threats_today = db.query(ThreatDetection).filter(
        ThreatDetection.user_id == user_id,
        ThreatDetection.detected_at >= today_start
    ).count()
    
    scans_today = db.query(ConnectedApp).filter(
        ConnectedApp.user_id == user_id,
        ConnectedApp.last_scan >= today_start
    ).count()
    
    total_apps = db.query(ConnectedApp).filter(
        ConnectedApp.user_id == user_id,
        ConnectedApp.is_active == True
    ).count()
    
    return {
        "threats_detected_today": threats_today,
        "scans_completed_today": scans_today,
        "total_connected_apps": total_apps,
        "monitoring_active": total_apps > 0
    }

async def get_user_threat_stats(user_id: int, start_time: datetime, end_time: datetime, db: Session) -> Dict[str, Any]:
    """Get threat statistics for a user within timeframe"""
    threats = db.query(ThreatDetection).filter(
        ThreatDetection.user_id == user_id,
        ThreatDetection.detected_at >= start_time,
        ThreatDetection.detected_at <= end_time
    ).all()
    
    # Group by severity
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    threat_types = {}
    
    for threat in threats:
        severity_counts[threat.severity] += 1
        threat_types[threat.threat_type] = threat_types.get(threat.threat_type, 0) + 1
    
    return {
        "total_threats": len(threats),
        "severity_breakdown": severity_counts,
        "threat_types": threat_types,
        "timeframe": {
            "start": start_time.isoformat(),
            "end": end_time.isoformat()
        }
    }

async def authenticate_websocket_user(token: str, db: Session) -> Optional[User]:
    """Authenticate user for WebSocket connection"""
    try:
        # Implement JWT token validation here
        # This is a placeholder - you'll need to add your JWT logic
        return None
    except Exception:
        return None

async def handle_subscription(websocket: WebSocket, user_id: int, channels: List[str]):
    """Handle WebSocket channel subscription"""
    try:
        await connection_manager.subscribe_channels(websocket, user_id, channels)
        await websocket.send_text(json.dumps({
            "type": "subscription_success",
            "channels": channels
        }))
    except Exception as e:
        await websocket.send_text(json.dumps({
            "type": "subscription_error",
            "error": str(e)
        }))

async def handle_unsubscription(websocket: WebSocket, user_id: int, channels: List[str]):
    """Handle WebSocket channel unsubscription"""
    try:
        await connection_manager.unsubscribe_channels(websocket, user_id, channels)
        await websocket.send_text(json.dumps({
            "type": "unsubscription_success",
            "channels": channels
        }))
    except Exception as e:
        await websocket.send_text(json.dumps({
            "type": "unsubscription_error",
            "error": str(e)
        }))

