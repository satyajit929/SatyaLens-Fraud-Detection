import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import json
import hashlib
from abc import ABC, abstractmethod

from ..database import ConnectedApp, AppScanLog, ThreatDetection, User
from ..config import settings
from .permissions import permission_manager

logger = logging.getLogger(__name__)

class BaseAppService(ABC):
    """Base class for app-specific services"""
    
    def __init__(self, app_type: str):
        self.app_type = app_type
        self.name = self._get_app_name()
    
    @abstractmethod
    def _get_app_name(self) -> str:
        """Get human-readable app name"""
        pass
    
    @abstractmethod
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to the app"""
        pass
    
    @abstractmethod
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from the app"""
        pass
    
    @abstractmethod
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test app connection"""
        pass
    
    @abstractmethod
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan app content for threats"""
        pass
    
    async def update_permissions(self, app_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Update app permissions"""
        try:
            # Validate permissions
            valid_permissions = permission_manager.get_valid_permissions(self.app_type)
            for permission in permissions.keys():
                if permission not in valid_permissions:
                    return {
                        "success": False,
                        "error": f"Invalid permission: {permission}"
                    }
            
            # Update in database
            connected_app = db.query(ConnectedApp).filter(
                ConnectedApp.id == app_id,
                ConnectedApp.is_active == True
            ).first()
            
            if not connected_app:
                return {"success": False, "error": "App not found"}
            
            connected_app.permissions = permissions
            connected_app.updated_at = datetime.utcnow()
            db.commit()
            
            return {"success": True, "message": "Permissions updated successfully"}
            
        except Exception as e:
            logger.error(f"Failed to update permissions for {self.app_type}: {e}")
            return {"success": False, "error": str(e)}
    
    def _create_scan_log(self, app_id: int, scan_type: str, db: Session) -> AppScanLog:
        """Create a new scan log entry"""
        scan_log = AppScanLog(
            app_id=app_id,
            scan_type=scan_type,
            status="running",
            created_at=datetime.utcnow()
        )
        db.add(scan_log)
        db.commit()
        db.refresh(scan_log)
        return scan_log
    
    def _update_scan_log(self, scan_log: AppScanLog, status: str, 
                        items_scanned: int = 0, threats_detected: int = 0,
                        error_message: str = None, db: Session = None):
        """Update scan log with results"""
        scan_log.status = status
        scan_log.items_scanned = items_scanned
        scan_log.threats_detected = threats_detected
        scan_log.completed_at = datetime.utcnow()
        scan_log.scan_duration = (scan_log.completed_at - scan_log.created_at).total_seconds()
        
        if error_message:
            scan_log.error_message = error_message
        
        if db:
            db.commit()

class WhatsAppService(BaseAppService):
    """WhatsApp integration service"""
    
    def __init__(self):
        super().__init__("whatsapp")
    
    def _get_app_name(self) -> str:
        return "WhatsApp"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to WhatsApp"""
        try:
            # Simulate WhatsApp connection process
            # In real implementation, this would involve:
            # 1. QR code generation for WhatsApp Web
            # 2. Session establishment
            # 3. Permission validation
            
            connection_data = {
                "session_id": f"wa_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            logger.info(f"WhatsApp connected for user {user_id}")
            
            return {
                "success": True,
                "message": "WhatsApp connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            logger.error(f"WhatsApp connection failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from WhatsApp"""
        try:
            # Cleanup WhatsApp session
            logger.info(f"WhatsApp disconnected for app {app_id}")
            return {"success": True, "message": "WhatsApp disconnected successfully"}
            
        except Exception as e:
            logger.error(f"WhatsApp disconnect failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test WhatsApp connection"""
        try:
            # Simulate connection test
            await asyncio.sleep(1)  # Simulate API call
            
            return {
                "success": True,
                "message": "WhatsApp connection is healthy",
                "details": {
                    "last_message_sync": datetime.utcnow().isoformat(),
                    "connection_quality": "good"
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan WhatsApp messages for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            # Simulate scanning WhatsApp messages
            await asyncio.sleep(2)  # Simulate scan time
            
            # Mock scan results
            items_scanned = 150
            threats_detected = 3
            
            # Create threat detections
            threats = [
                {
                    "type": "phishing_link",
                    "severity": "high",
                    "content": "Suspicious link detected in message",
                    "source": "contact_+919876543210"
                },
                {
                    "type": "fake_offer",
                    "severity": "medium", 
                    "content": "Fake lottery winner message",
                    "source": "unknown_number"
                },
                {
                    "type": "malicious_qr",
                    "severity": "high",
                    "content": "QR code leading to malicious site",
                    "source": "group_chat"
                }
            ]
            
            for threat in threats:
                detection = ThreatDetection(
                    user_id=db.query(ConnectedApp).filter(ConnectedApp.id == app_id).first().user_id,
                    app_id=app_id,
                    threat_type=threat["type"],
                    severity=threat["severity"],
                    content_hash=hashlib.md5(threat["content"].encode()).hexdigest(),
                    threat_data=threat,
                    detected_at=datetime.utcnow()
                )
                db.add(detection)
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            logger.error(f"WhatsApp scan failed: {e}")
            return {"success": False, "error": str(e)}

class MessagesService(BaseAppService):
    """SMS Messages integration service"""
    
    def __init__(self):
        super().__init__("messages")
    
    def _get_app_name(self) -> str:
        return "SMS Messages"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to SMS Messages"""
        try:
            connection_data = {
                "session_id": f"sms_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            logger.info(f"SMS Messages connected for user {user_id}")
            
            return {
                "success": True,
                "message": "SMS Messages connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            logger.error(f"SMS Messages connection failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from SMS Messages"""
        try:
            logger.info(f"SMS Messages disconnected for app {app_id}")
            return {"success": True, "message": "SMS Messages disconnected successfully"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test SMS Messages connection"""
        try:
            await asyncio.sleep(0.5)
            
            return {
                "success": True,
                "message": "SMS Messages connection is healthy",
                "details": {
                    "last_sync": datetime.utcnow().isoformat(),
                    "message_count": 1247
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan SMS messages for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            await asyncio.sleep(1.5)
            
            items_scanned = 89
            threats_detected = 2
            
            threats = [
                {
                    "type": "phishing_sms",
                    "severity": "high",
                    "content": "Fake bank SMS requesting OTP",
                    "source": "sender_BANK123"
                },
                {
                    "type": "spam_offer",
                    "severity": "low",
                    "content": "Unwanted promotional message",
                    "source": "unknown_sender"
                }
            ]
            
            for threat in threats:
                detection = ThreatDetection(
                    user_id=db.query(ConnectedApp).filter(ConnectedApp.id == app_id).first().user_id,
                    app_id=app_id,
                    threat_type=threat["type"],
                    severity=threat["severity"],
                    content_hash=hashlib.md5(threat["content"].encode()).hexdigest(),
                    threat_data=threat,
                    detected_at=datetime.utcnow()
                )
                db.add(detection)
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            return {"success": False, "error": str(e)}

class EmailService(BaseAppService):
    """Email integration service"""
    
    def __init__(self):
        super().__init__("email")
    
    def _get_app_name(self) -> str:
        return "Email"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to Email"""
        try:
            connection_data = {
                "session_id": f"email_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            return {
                "success": True,
                "message": "Email connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from Email"""
        try:
            return {"success": True, "message": "Email disconnected successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test Email connection"""
        try:
            await asyncio.sleep(1)
            
            return {
                "success": True,
                "message": "Email connection is healthy",
                "details": {
                    "last_sync": datetime.utcnow().isoformat(),
                    "inbox_count": 342
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan emails for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            await asyncio.sleep(3)
            
            items_scanned = 234
            threats_detected = 5
            
            threats = [
                {
                    "type": "phishing_email",
                    "severity": "critical",
                    "content": "Fake PayPal security alert",
                    "source": "noreply@paypaI.com"
                },
                {
                    "type": "malware_attachment",
                    "severity": "high",
                    "content": "Suspicious .exe attachment",
                    "source": "unknown@suspicious.com"
                }
            ]
            
            for threat in threats:
                detection = ThreatDetection(
                    user_id=db.query(ConnectedApp).filter(ConnectedApp.id == app_id).first().user_id,
                    app_id=app_id,
                    threat_type=threat["type"],
                    severity=threat["severity"],
                    content_hash=hashlib.md5(threat["content"].encode()).hexdigest(),
                    threat_data=threat,
                    detected_at=datetime.utcnow()
                )
                db.add(detection)
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            return {"success": False, "error": str(e)}

class TelegramService(BaseAppService):
    """Telegram integration service"""
    
    def __init__(self):
        super().__init__("telegram")
    
    def _get_app_name(self) -> str:
        return "Telegram"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to Telegram"""
        try:
            connection_data = {
                "session_id": f"tg_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            return {
                "success": True,
                "message": "Telegram connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from Telegram"""
        try:
            return {"success": True, "message": "Telegram disconnected successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test Telegram connection"""
        try:
            await asyncio.sleep(0.8)
            
            return {
                "success": True,
                "message": "Telegram connection is healthy",
                "details": {
                    "last_sync": datetime.utcnow().isoformat(),
                    "chat_count": 45
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan Telegram messages for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            await asyncio.sleep(2.5)
            
            items_scanned = 178
            threats_detected = 4
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            return {"success": False, "error": str(e)}

class InstagramService(BaseAppService):
    """Instagram integration service"""
    
    def __init__(self):
        super().__init__("instagram")
    
    def _get_app_name(self) -> str:
        return "Instagram"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to Instagram"""
        try:
            connection_data = {
                "session_id": f"ig_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            return {
                "success": True,
                "message": "Instagram connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from Instagram"""
        try:
            return {"success": True, "message": "Instagram disconnected successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test Instagram connection"""
        try:
            await asyncio.sleep(1.2)
            
            return {
                "success": True,
                "message": "Instagram connection is healthy",
                "details": {
                    "last_sync": datetime.utcnow().isoformat(),
                    "dm_count": 23
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan Instagram DMs for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            await asyncio.sleep(1.8)
            
            items_scanned = 67
            threats_detected = 1
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            return {"success": False, "error": str(e)}

class GalleryService(BaseAppService):
    """Gallery integration service"""
    
    def __init__(self):
        super().__init__("gallery")
    
    def _get_app_name(self) -> str:
        return "Gallery"
    
    async def connect(self, user_id: int, permissions: Dict[str, bool], db: Session) -> Dict[str, Any]:
        """Connect to Gallery"""
        try:
            connection_data = {
                "session_id": f"gallery_session_{user_id}_{datetime.utcnow().timestamp()}",
                "connected_at": datetime.utcnow().isoformat(),
                "permissions_granted": permissions
            }
            
            return {
                "success": True,
                "message": "Gallery connected successfully",
                "connection_data": connection_data
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def disconnect(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Disconnect from Gallery"""
        try:
            return {"success": True, "message": "Gallery disconnected successfully"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connection(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Test Gallery connection"""
        try:
            await asyncio.sleep(0.5)
            
            return {
                "success": True,
                "message": "Gallery connection is healthy",
                "details": {
                    "last_sync": datetime.utcnow().isoformat(),
                    "image_count": 1456
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def scan_content(self, app_id: int, db: Session) -> Dict[str, Any]:
        """Scan gallery images for threats"""
        scan_log = self._create_scan_log(app_id, "full_scan", db)
        
        try:
            await asyncio.sleep(4)  # Image scanning takes longer
            
            items_scanned = 1456
            threats_detected = 2
            
            self._update_scan_log(scan_log, "completed", items_scanned, threats_detected, db=db)
            
            return {
                "success": True,
                "scan_id": scan_log.id,
                "items_scanned": items_scanned,
                "threats_detected": threats_detected
            }
            
        except Exception as e:
            self._update_scan_log(scan_log, "failed", error_message=str(e), db=db)
            return {"success": False, "error": str(e)}

# Service registry
SERVICE_REGISTRY = {
    "whatsapp": WhatsAppService,
    "messages": MessagesService,
    "email": EmailService,
    "telegram": TelegramService,
    "instagram": InstagramService,
    "gallery": GalleryService
}

def get_app_service(app_type: str) -> BaseAppService:
    """Get service instance for app type"""
    service_class = SERVICE_REGISTRY.get(app_type)
    if not service_class:
        raise ValueError(f"Unsupported app type: {app_type}")
    
    return service_class()
