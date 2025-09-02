import asyncio
import json
import logging
from typing import Dict, List, Set, Optional, Any, Callable
from datetime import datetime, timedelta
from enum import Enum
import weakref
from dataclasses import dataclass, asdict
from collections import defaultdict
import uuid

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from redis import Redis
import jwt

from ..database import User, get_db
from ..config import settings
from .events import EventType, MonitoringEvent
from .alerts import AlertSeverity

logger = logging.getLogger(__name__)

class ConnectionState(str, Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"

class ChannelType(str, Enum):
    THREATS = "threats"
    ALERTS = "alerts"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    SCANS = "scans"
    HEALTH = "health"
    USER_ACTIVITY = "user_activity"

@dataclass
class WebSocketMessage:
    type: str
    data: Dict[str, Any]
    timestamp: datetime
    user_id: Optional[int] = None
    channel: Optional[str] = None
    message_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "channel": self.channel,
            "message_id": self.message_id or str(uuid.uuid4())
        }

@dataclass
class ConnectionInfo:
    websocket: WebSocket
    user_id: int
    connection_id: str
    state: ConnectionState
    connected_at: datetime
    last_ping: datetime
    subscribed_channels: Set[str]
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    def is_alive(self) -> bool:
        """Check if connection is still alive based on last ping"""
        return (datetime.utcnow() - self.last_ping).seconds < 60

class ConnectionManager:
    """Manages WebSocket connections for real-time monitoring"""
    
    def __init__(self, redis_client: Optional[Redis] = None):
        # Active connections: connection_id -> ConnectionInfo
        self._connections: Dict[str, ConnectionInfo] = {}
        
        # User connections: user_id -> Set[connection_id]
        self._user_connections: Dict[int, Set[str]] = defaultdict(set)
        
        # Channel subscriptions: channel -> Set[connection_id]
        self._channel_subscriptions: Dict[str, Set[str]] = defaultdict(set)
        
        # Message queues for offline users
        self._offline_queues: Dict[int, List[WebSocketMessage]] = defaultdict(list)
        
        # Redis for distributed messaging (optional)
        self._redis = redis_client
        
        # Event handlers
        self._event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Connection statistics
        self._stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "connection_errors": 0
        }
        
        # Start background tasks
        self._cleanup_task = None
        self._heartbeat_task = None
        self._start_background_tasks()

    async def connect(self, websocket: WebSocket, user_id: int, **kwargs) -> str:
        """Accept a new WebSocket connection"""
        try:
            await websocket.accept()
            
            connection_id = str(uuid.uuid4())
            connection_info = ConnectionInfo(
                websocket=websocket,
                user_id=user_id,
                connection_id=connection_id,
                state=ConnectionState.CONNECTED,
                connected_at=datetime.utcnow(),
                last_ping=datetime.utcnow(),
                subscribed_channels=set(),
                user_agent=kwargs.get("user_agent"),
                ip_address=kwargs.get("ip_address")
            )
            
            # Store connection
            self._connections[connection_id] = connection_info
            self._user_connections[user_id].add(connection_id)
            
            # Update stats
            self._stats["total_connections"] += 1
            self._stats["active_connections"] += 1
            
            # Send welcome message
            await self._send_to_connection(connection_id, WebSocketMessage(
                type="connection_established",
                data={
                    "connection_id": connection_id,
                    "user_id": user_id,
                    "server_time": datetime.utcnow().isoformat(),
                    "available_channels": list(ChannelType)
                },
                timestamp=datetime.utcnow(),
                user_id=user_id
            ))
            
            # Deliver queued messages
            await self._deliver_queued_messages(user_id, connection_id)
            
            # Trigger connection event
            await self._trigger_event("user_connected", {
                "user_id": user_id,
                "connection_id": connection_id,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            logger.info(f"WebSocket connection established: {connection_id} for user {user_id}")
            return connection_id
            
        except Exception as e:
            logger.error(f"Failed to establish WebSocket connection: {e}")
            self._stats["connection_errors"] += 1
            raise

    async def disconnect(self, connection_id: str, code: int = 1000, reason: str = "Normal closure"):
        """Disconnect a WebSocket connection"""
        try:
            if connection_id not in self._connections:
                return
            
            connection_info = self._connections[connection_id]
            connection_info.state = ConnectionState.DISCONNECTING
            
            # Remove from subscriptions
            for channel in connection_info.subscribed_channels.copy():
                await self._unsubscribe_from_channel(connection_id, channel)
            
            # Remove from user connections
            self._user_connections[connection_info.user_id].discard(connection_id)
            if not self._user_connections[connection_info.user_id]:
                del self._user_connections[connection_info.user_id]
            
            # Close WebSocket
            try:
                await connection_info.websocket.close(code=code, reason=reason)
            except Exception as e:
                logger.warning(f"Error closing WebSocket: {e}")
            
            # Remove connection
            del self._connections[connection_id]
            
            # Update stats
            self._stats["active_connections"] -= 1
            
            # Trigger disconnection event
            await self._trigger_event("user_disconnected", {
                "user_id": connection_info.user_id,
                "connection_id": connection_id,
                "timestamp": datetime.utcnow().isoformat(),
                "reason": reason
            })
            
            logger.info(f"WebSocket connection closed: {connection_id}")
            
        except Exception as e:
            logger.error(f"Error during WebSocket disconnection: {e}")

    async def subscribe_to_channel(self, connection_id: str, channel: str) -> bool:
        """Subscribe a connection to a channel"""
        try:
            if connection_id not in self._connections:
                return False
            
            connection_info = self._connections[connection_id]
            
            # Validate channel
            if not self._is_valid_channel(channel):
                await self._send_error(connection_id, f"Invalid channel: {channel}")
                return False
            
            # Check permissions
            if not await self._check_channel_permission(connection_info.user_id, channel):
                await self._send_error(connection_id, f"Access denied to channel: {channel}")
                return False
            
            # Add subscription
            connection_info.subscribed_channels.add(channel)
            self._channel_subscriptions[channel].add(connection_id)
            
            # Send confirmation
            await self._send_to_connection(connection_id, WebSocketMessage(
                type="subscription_confirmed",
                data={
                    "channel": channel,
                    "subscribed_at": datetime.utcnow().isoformat()
                },
                timestamp=datetime.utcnow(),
                user_id=connection_info.user_id,
                channel=channel
            ))
            
            logger.debug(f"Connection {connection_id} subscribed to channel {channel}")
            return True
            
        except Exception as e:
            logger.error(f"Error subscribing to channel: {e}")
            return False

    async def unsubscribe_from_channel(self, connection_id: str, channel: str) -> bool:
        """Unsubscribe a connection from a channel"""
        try:
            return await self._unsubscribe_from_channel(connection_id, channel)
        except Exception as e:
            logger.error(f"Error unsubscribing from channel: {e}")
            return False

    async def broadcast_to_channel(self, channel: str, message: WebSocketMessage):
        """Broadcast a message to all subscribers of a channel"""
        try:
            if channel not in self._channel_subscriptions:
                return
            
            connection_ids = self._channel_subscriptions[channel].copy()
            message.channel = channel
            
            # Send to all subscribers
            tasks = []
            for connection_id in connection_ids:
                if connection_id in self._connections:
                    tasks.append(self._send_to_connection(connection_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
            logger.debug(f"Broadcasted message to {len(tasks)} connections in channel {channel}")
            
        except Exception as e:
            logger.error(f"Error broadcasting to channel {channel}: {e}")

    async def send_to_user(self, user_id: int, message: WebSocketMessage):
        """Send a message to all connections of a specific user"""
        try:
            if user_id not in self._user_connections:
                # Queue message for offline user
                self._offline_queues[user_id].append(message)
                # Limit queue size
                if len(self._offline_queues[user_id]) > 100:
                    self._offline_queues[user_id] = self._offline_queues[user_id][-100:]
                return
            
            connection_ids = self._user_connections[user_id].copy()
            message.user_id = user_id
            
            # Send to all user connections
            tasks = []
            for connection_id in connection_ids:
                if connection_id in self._connections:
                    tasks.append(self._send_to_connection(connection_id, message))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
            logger.debug(f"Sent message to {len(tasks)} connections for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error sending message to user {user_id}: {e}")

    async def handle_message(self, connection_id: str, raw_message: str):
        """Handle incoming WebSocket message"""
        try:
            if connection_id not in self._connections:
                return
            
            connection_info = self._connections[connection_id]
            connection_info.last_ping = datetime.utcnow()
            
            # Parse message
            try:
                message_data = json.loads(raw_message)
            except json.JSONDecodeError:
                await self._send_error(connection_id, "Invalid JSON format")
                return
            
            message_type = message_data.get("type")
            if not message_type:
                await self._send_error(connection_id, "Missing message type")
                return
            
            self._stats["messages_received"] += 1
            
            # Handle different message types
            if message_type == "ping":
                await self._handle_ping(connection_id)
            elif message_type == "subscribe":
                await self._handle_subscribe(connection_id, message_data)
            elif message_type == "unsubscribe":
                await self._handle_unsubscribe(connection_id, message_data)
            elif message_type == "get_status":
                await self._handle_get_status(connection_id)
            elif message_type == "authenticate":
                await self._handle_authenticate(connection_id, message_data)
            else:
                await self._send_error(connection_id, f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
            await self._send_error(connection_id, "Internal server error")

    async def broadcast_monitoring_event(self, event: MonitoringEvent):
        """Broadcast a monitoring event to relevant channels"""
        try:
            # Determine target channels based on event type
            channels = self._get_channels_for_event(event)
            
            message = WebSocketMessage(
                type="monitoring_event",
                data={
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "title": event.title,
                    "description": event.description,
                    "metadata": event.metadata,
                    "app_id": event.app_id,
                    "user_id": event.user_id
                },
                timestamp=event.timestamp,
                user_id=event.user_id
            )
            
            # Broadcast to channels
            for channel in channels:
                await self.broadcast_to_channel(channel, message)
            
            # Also send directly to affected user
            if event.user_id:
                await self.send_to_user(event.user_id, message)
                
        except Exception as e:
            logger.error(f"Error broadcasting monitoring event: {e}")

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            **self._stats,
            "channels": {
                channel: len(connections) 
                for channel, connections in self._channel_subscriptions.items()
            },
            "users_online": len(self._user_connections),
            "offline_queues": {
                user_id: len(messages) 
                for user_id, messages in self._offline_queues.items()
            }
        }

    def get_user_connections(self, user_id: int) -> List[str]:
        """Get all connection IDs for a user"""
        return list(self._user_connections.get(user_id, set()))

    def is_user_online(self, user_id: int) -> bool:
        """Check if a user has any active connections"""
        return user_id in self._user_connections and len(self._user_connections[user_id]) > 0

    # Private methods

    async def _send_to_connection(self, connection_id: str, message: WebSocketMessage):
        """Send a message to a specific connection"""
        try:
            if connection_id not in self._connections:
                return
            
            connection_info = self._connections[connection_id]
            
            # Check if connection is still alive
            if not connection_info.is_alive():
                await self.disconnect(connection_id, reason="Connection timeout")
                return
            
            # Send message
            message_dict = message.to_dict()
            await connection_info.websocket.send_text(json.dumps(message_dict))
            
            self._stats["messages_sent"] += 1
            
        except WebSocketDisconnect:
            await self.disconnect(connection_id, reason="Client disconnected")
        except Exception as e:
            logger.error(f"Error sending message to connection {connection_id}: {e}")
            await self.disconnect(connection_id, reason="Send error")

    async def _send_error(self, connection_id: str, error_message: str):
        """Send an error message to a connection"""
        error_msg = WebSocketMessage(
            type="error",
            data={"message": error_message},
            timestamp=datetime.utcnow()
        )
        await self._send_to_connection(connection_id, error_msg)

    async def _unsubscribe_from_channel(self, connection_id: str, channel: str) -> bool:
        """Internal method to unsubscribe from channel"""
        if connection_id not in self._connections:
            return False
        
        connection_info = self._connections[connection_id]
        connection_info.subscribed_channels.discard(channel)
        self._channel_subscriptions[channel].discard(connection_id)
        
        # Clean up empty channel subscriptions
        if not self._channel_subscriptions[channel]:
            del self._channel_subscriptions[channel]
        
        # Send confirmation
        await self._send_to_connection(connection_id, WebSocketMessage(
            type="unsubscription_confirmed",
            data={
                "channel": channel,
                "unsubscribed_at": datetime.utcnow().isoformat()
            },
            timestamp=datetime.utcnow(),
            user_id=connection_info.user_id
        ))
        
        return True

    async def _deliver_queued_messages(self, user_id: int, connection_id: str):
        """Deliver queued messages to a newly connected user"""
        if user_id not in self._offline_queues:
            return
        
        messages = self._offline_queues[user_id]
        if not messages:
            return
        
        # Send queued messages
        for message in messages:
            await self._send_to_connection(connection_id, message)
        
        # Clear queue
        del self._offline_queues[user_id]
        
        logger.info(f"Delivered {len(messages)} queued messages to user {user_id}")

    def _is_valid_channel(self, channel: str) -> bool:
        """Validate channel name"""
        return channel in [ct.value for ct in ChannelType]

    async def _check_channel_permission(self, user_id: int, channel: str) -> bool:
        """Check if user has permission to access channel"""
        # For now, all authenticated users can access all channels
        # You can implement more granular permissions here
        return True

    def _get_channels_for_event(self, event: MonitoringEvent) -> List[str]:
        """Determine which channels should receive an event"""
        channels = []
        
        if event.event_type in [EventType.THREAT_DETECTED, EventType.VULNERABILITY_FOUND]:
            channels.append(ChannelType.THREATS.value)
        
        if event.event_type in [EventType.ALERT_CREATED, EventType.ALERT_UPDATED]:
            channels.append(ChannelType.ALERTS.value)
        
        if event.event_type in [EventType.SCAN_STARTED, EventType.SCAN_COMPLETED]:
            channels.append(ChannelType.SCANS.value)
        
        if event.event_type in [EventType.SYSTEM_ERROR, EventType.SYSTEM_WARNING]:
            channels.append(ChannelType.SYSTEM.value)
        
        if event.event_type in [EventType.PERFORMANCE_DEGRADED]:
            channels.append(ChannelType.PERFORMANCE.value)
        
        return channels

    async def _handle_ping(self, connection_id: str):
        """Handle ping message"""
        pong_msg = WebSocketMessage(
            type="pong",
            data={"timestamp": datetime.utcnow().isoformat()},
            timestamp=datetime.utcnow()
        )
        await self._send_to_connection(connection_id, pong_msg)

    async def _handle_subscribe(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle subscription request"""
        channels = message_data.get("channels", [])
        if isinstance(channels, str):
            channels = [channels]
        
        results = []
        for channel in channels:
            success = await self.subscribe_to_channel(connection_id, channel)
            results.append({"channel": channel, "success": success})
        
        response = WebSocketMessage(
            type="subscription_response",
            data={"results": results},
            timestamp=datetime.utcnow()
        )
        await self._send_to_connection(connection_id, response)

    async def _handle_unsubscribe(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle unsubscription request"""
        channels = message_data.get("channels", [])
        if isinstance(channels, str):
            channels = [channels]
        
        results = []
        for channel in channels:
            success = await self.unsubscribe_from_channel(connection_id, channel)
            results.append({"channel": channel, "success": success})
        
        response = WebSocketMessage(
            type="unsubscription_response",
            data={"results": results},
            timestamp=datetime.utcnow()
        )
        await self._send_to_connection(connection_id, response)

    async def _handle_get_status(self, connection_id: str):
        """Handle status request"""
        if connection_id not in self._connections:
            return
        
        connection_info = self._connections[connection_id]
        
        status = WebSocketMessage(
            type="status_response",
            data={
                "connection_id": connection_id,
                "user_id": connection_info.user_id,
                "connected_at": connection_info.connected_at.isoformat(),
                "subscribed_channels": list(connection_info.subscribed_channels),
                "server_stats": self.get_connection_stats()
            },
            timestamp=datetime.utcnow(),
            user_id=connection_info.user_id
        )
        await self._send_to_connection(connection_id, status)

    async def _handle_authenticate(self, connection_id: str, message_data: Dict[str, Any]):
        """Handle authentication request"""
        # This would implement additional authentication if needed
        # For now, connections are authenticated during initial connection
        pass

    async def _trigger_event(self, event_type: str, data: Dict[str, Any]):
        """Trigger event handlers"""
        if event_type in self._event_handlers:
            for handler in self._event_handlers[event_type]:
                try:
                    await handler(data)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_type}: {e}")

    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_connections())
        
        if not self._heartbeat_task:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())

    async def _cleanup_connections(self):
        """Periodically clean up dead connections"""
        while True:
            try:
                await asyncio.sleep(30)  # Run every 30 seconds
                
                dead_connections = []
                for connection_id, connection_info in self._connections.items():
                    if not connection_info.is_alive():
                        dead_connections.append(connection_id)
                
                for connection_id in dead_connections:
                    await self.disconnect(connection_id, reason="Connection timeout")
                
                if dead_connections:
                    logger.info(f"Cleaned up {len(dead_connections)} dead connections")
                    
            except Exception as e:
                logger.error(f"Error in connection cleanup: {e}")

    async def _heartbeat_monitor(self):
        """Send periodic heartbeat to all connections"""
        while True:
            try:
                await asyncio.sleep(60)  # Send heartbeat every minute
                
                heartbeat_msg = WebSocketMessage(
                    type="heartbeat",
                    data={"server_time": datetime.utcnow().isoformat()},
                    timestamp=datetime.utcnow()
                )
                
                # Send to all active connections
                tasks = []
                for connection_id in list(self._connections.keys()):
                    tasks.append(self._send_to_connection(connection_id, heartbeat_msg))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
            except Exception as e:
                logger.error(f"Error in heartbeat monitor: {e}")

    def add_event_handler(self, event_type: str, handler: Callable):
        """Add an event handler"""
        self._event_handlers[event_type].append(handler)

    def remove_event_handler(self, event_type: str, handler: Callable):
        """Remove an event handler"""
        if event_type in self._event_handlers:
            try:
                self._event_handlers[event_type].remove(handler)
            except ValueError:
                pass

    async def shutdown(self):
        """Shutdown the connection manager"""
        logger.info("Shutting down WebSocket connection manager...")
        
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        
        # Close all connections
        connection_ids = list(self._connections.keys())
        for connection_id in connection_ids:
            await self.disconnect(connection_id, reason="Server shutdown")
        
        logger.info("WebSocket connection manager shutdown complete")

# Global connection manager instance
connection_manager = ConnectionManager()

async def authenticate_websocket_user(token: str, db: Session) -> Optional[User]:
    """Authenticate user from WebSocket token"""
    try:
        # Decode JWT token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        # Get user from database
        user = db.query(User).filter(User.id == int(user_id)).first()
        return user
        
    except jwt.ExpiredSignatureError:
        logger.warning("WebSocket authentication failed: Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("WebSocket authentication failed: Invalid token")
        return None
    except Exception as e:
        logger.error(f"WebSocket authentication error: {e}")
        return None
