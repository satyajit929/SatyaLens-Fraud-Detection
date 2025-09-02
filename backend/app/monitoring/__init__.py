"""
Monitoring module for real-time threat detection and system monitoring.

This module provides:
- Real-time monitoring of connected apps
- Threat detection and alerting
- System health monitoring
- Performance metrics collection
- Alert management and notifications
"""

from .monitor import ThreatMonitor, SystemMonitor
from .alerts import AlertManager, AlertType, AlertSeverity
from .metrics import MetricsCollector, PerformanceTracker
from .realtime import RealtimeProcessor, EventProcessor
from .scheduler import MonitoringScheduler, ScheduledTask

__all__ = [
    'ThreatMonitor',
    'SystemMonitor', 
    'AlertManager',
    'AlertType',
    'AlertSeverity',
    'MetricsCollector',
    'PerformanceTracker',
    'RealtimeProcessor',
    'EventProcessor',
    'MonitoringScheduler',
    'ScheduledTask'
]

# Module version
__version__ = '1.0.0'

# Default monitoring configuration
DEFAULT_CONFIG = {
    'monitoring': {
        'enabled': True,
        'check_interval': 300,  # 5 minutes
        'threat_scan_interval': 900,  # 15 minutes
        'health_check_interval': 600,  # 10 minutes
        'metrics_collection_interval': 60,  # 1 minute
        'alert_cooldown': 1800,  # 30 minutes
        'max_concurrent_scans': 5,
        'scan_timeout': 300,  # 5 minutes
        'enable_realtime': True,
        'enable_scheduled_scans': True,
        'enable_health_checks': True,
        'enable_metrics': True
    },
    'alerts': {
        'enabled': True,
        'email_notifications': True,
        'push_notifications': True,
        'sms_notifications': False,
        'webhook_notifications': False,
        'severity_threshold': 'medium',
        'batch_alerts': True,
        'batch_interval': 300,  # 5 minutes
        'max_alerts_per_batch': 10
    },
    'metrics': {
        'enabled': True,
        'retention_days': 30,
        'aggregation_intervals': [60, 300, 3600, 86400],  # 1m, 5m, 1h, 1d
        'track_performance': True,
        'track_usage': True,
        'track_errors': True,
        'export_prometheus': False
    },
    'realtime': {
        'enabled': True,
        'websocket_enabled': True,
        'event_buffer_size': 1000,
        'event_retention_hours': 24,
        'max_connections_per_user': 5,
        'heartbeat_interval': 30
    }
}

# Monitoring status constants
class MonitoringStatus:
    ACTIVE = "active"
    PAUSED = "paused" 
    STOPPED = "stopped"
    ERROR = "error"
    MAINTENANCE = "maintenance"

# Event types for monitoring
class EventType:
    THREAT_DETECTED = "threat_detected"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    APP_CONNECTED = "app_connected"
    APP_DISCONNECTED = "app_disconnected"
    CONNECTION_ERROR = "connection_error"
    SYSTEM_ERROR = "system_error"
    PERFORMANCE_ALERT = "performance_alert"
    HEALTH_CHECK_FAILED = "health_check_failed"
    USER_ACTION = "user_action"

# Priority levels for monitoring tasks
class Priority:
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5

def get_default_config():
    """Get default monitoring configuration"""
    return DEFAULT_CONFIG.copy()

def validate_config(config: dict) -> bool:
    """Validate monitoring configuration"""
    required_sections = ['monitoring', 'alerts', 'metrics', 'realtime']
    
    for section in required_sections:
        if section not in config:
            return False
    
    # Validate monitoring section
    monitoring = config.get('monitoring', {})
    required_monitoring_keys = [
        'enabled', 'check_interval', 'threat_scan_interval',
        'health_check_interval', 'metrics_collection_interval'
    ]
    
    for key in required_monitoring_keys:
        if key not in monitoring:
            return False
        
        # Validate interval values are positive integers
        if key.endswith('_interval') and not isinstance(monitoring[key], int):
            return False
        
        if key.endswith('_interval') and monitoring[key] <= 0:
            return False
    
    return True

def create_monitoring_config(**overrides) -> dict:
    """Create monitoring configuration with overrides"""
    config = get_default_config()
    
    for section, values in overrides.items():
        if section in config:
            config[section].update(values)
        else:
            config[section] = values
    
    return config

# Initialize module logger
import logging
logger = logging.getLogger(__name__)
logger.info(f"Monitoring module initialized (version {__version__})")