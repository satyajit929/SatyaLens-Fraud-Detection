import asyncio
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import aiofiles
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from redis import Redis
import boto3
from celery import Celery

from ..database import (
    get_db, User, ConnectedApp, ThreatDetection, Alert, 
    SystemMetric, ScanResult, VulnerabilityReport, AuditLog
)
from ..config import settings
from .events import EventType, MonitoringEvent, EventProcessor
from .alerts import AlertManager, AlertType, AlertSeverity
from .websocket import connection_manager
from .scanner import SecurityScanner, VulnerabilityScanner
from .analyzer import ThreatAnalyzer, RiskAssessment
from .notifications import NotificationService

logger = logging.getLogger(__name__)

class ServiceStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"

class MonitoringMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"

class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    DEEP = "deep"
    CUSTOM = "custom"

@dataclass
class ServiceHealth:
    service_name: str
    status: ServiceStatus
    last_check: datetime
    response_time: float
    error_count: int
    uptime_percentage: float
    metadata: Dict[str, Any]

@dataclass
class MonitoringTask:
    task_id: str
    user_id: int
    app_id: int
    task_type: str
    priority: int
    created_at: datetime
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    status: str
    progress: float
    result: Optional[Dict[str, Any]]
    error_message: Optional[str]

class MonitoringService:
    """Core monitoring service that orchestrates all monitoring activities"""
    
    def __init__(self, redis_client: Optional[Redis] = None, celery_app: Optional[Celery] = None):
        self.redis = redis_client or Redis.from_url(settings.REDIS_URL)
        self.celery = celery_app
        self.event_processor = EventProcessor()
        self.alert_manager = AlertManager()
        self.notification_service = NotificationService()
        self.security_scanner = SecurityScanner()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.threat_analyzer = ThreatAnalyzer()
        
        # Service health tracking
        self.service_health: Dict[str, ServiceHealth] = {}
        
        # Active monitoring tasks
        self.active_tasks: Dict[str, MonitoringTask] = {}
        
        # Thread pool for CPU-intensive tasks
        self.executor = ThreadPoolExecutor(max_workers=settings.MAX_WORKER_THREADS)
        
        # Background task handles
        self._background_tasks: Set[asyncio.Task] = set()
        
        # Initialize services
        asyncio.create_task(self._initialize_services())

    async def _initialize_services(self):
        """Initialize all monitoring services"""
        try:
            logger.info("Initializing monitoring services...")
            
            # Start background monitoring tasks
            await self._start_background_tasks()
            
            # Initialize health checks
            await self._initialize_health_checks()
            
            logger.info("Monitoring services initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize monitoring services: {e}")
            raise

    async def start_monitoring(
        self, 
        user_id: int, 
        app_id: int, 
        monitor_types: List[str],
        mode: MonitoringMode = MonitoringMode.ACTIVE,
        priority: int = 5
    ) -> str:
        """Start monitoring for a specific app"""
        try:
            # Validate app ownership
            db = next(get_db())
            app = db.query(ConnectedApp).filter(
                ConnectedApp.id == app_id,
                ConnectedApp.user_id == user_id,
                ConnectedApp.is_active == True
            ).first()
            
            if not app:
                raise ValueError(f"App {app_id} not found or not owned by user {user_id}")
            
            # Create monitoring task
            task_id = str(uuid.uuid4())
            task = MonitoringTask(
                task_id=task_id,
                user_id=user_id,
                app_id=app_id,
                task_type="monitoring",
                priority=priority,
                created_at=datetime.utcnow(),
                scheduled_at=datetime.utcnow(),
                started_at=None,
                completed_at=None,
                status="pending",
                progress=0.0,
                result=None,
                error_message=None
            )
            
            self.active_tasks[task_id] = task
            
            # Schedule monitoring tasks
            for monitor_type in monitor_types:
                if monitor_type == "threat_detection":
                    await self._schedule_threat_monitoring(task_id, app, mode)
                elif monitor_type == "vulnerability_scan":
                    await self._schedule_vulnerability_scan(task_id, app, ScanType.FULL)
                elif monitor_type == "performance_monitoring":
                    await self._schedule_performance_monitoring(task_id, app)
                elif monitor_type == "security_audit":
                    await self._schedule_security_audit(task_id, app)
            
            # Update task status
            task.status = "running"
            task.started_at = datetime.utcnow()
            
            # Log event
            await self.event_processor.process_event(MonitoringEvent(
                event_type=EventType.MONITORING_STARTED,
                user_id=user_id,
                app_id=app_id,
                severity=AlertSeverity.INFO,
                title="Monitoring Started",
                description=f"Started monitoring for app {app.name}",
                metadata={
                    "task_id": task_id,
                    "monitor_types": monitor_types,
                    "mode": mode.value
                }
            ))
            
            # Store in Redis for persistence
            await self._store_task_in_redis(task)
            
            logger.info(f"Started monitoring task {task_id} for app {app_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            raise

    async def stop_monitoring(self, task_id: str, user_id: int) -> bool:
        """Stop a monitoring task"""
        try:
            if task_id not in self.active_tasks:
                return False
            
            task = self.active_tasks[task_id]
            
            # Verify ownership
            if task.user_id != user_id:
                raise PermissionError("Task not owned by user")
            
            # Update task status
            task.status = "stopped"
            task.completed_at = datetime.utcnow()
            task.progress = 100.0
            
            # Cancel any pending Celery tasks
            if self.celery:
                self.celery.control.revoke(task_id, terminate=True)
            
            # Remove from active tasks
            del self.active_tasks[task_id]
            
            # Log event
            await self.event_processor.process_event(MonitoringEvent(
                event_type=EventType.MONITORING_STOPPED,
                user_id=user_id,
                app_id=task.app_id,
                severity=AlertSeverity.INFO,
                title="Monitoring Stopped",
                description=f"Stopped monitoring task {task_id}",
                metadata={"task_id": task_id}
            ))
            
            # Update Redis
            await self._update_task_in_redis(task)
            
            logger.info(f"Stopped monitoring task {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop monitoring task {task_id}: {e}")
            return False

    async def get_monitoring_status(self, user_id: int) -> Dict[str, Any]:
        """Get comprehensive monitoring status for a user"""
        try:
            db = next(get_db())
            
            # Get user's apps
            user_apps = db.query(ConnectedApp).filter(
                ConnectedApp.user_id == user_id,
                ConnectedApp.is_active == True
            ).all()
            
            # Get active tasks for user
            user_tasks = [
                task for task in self.active_tasks.values() 
                if task.user_id == user_id
            ]
            
            # Get recent threats
            recent_threats = db.query(ThreatDetection).filter(
                ThreatDetection.user_id == user_id,
                ThreatDetection.detected_at >= datetime.utcnow() - timedelta(hours=24)
            ).count()
            
            # Get recent alerts
            recent_alerts = db.query(Alert).filter(
                Alert.user_id == user_id,
                Alert.created_at >= datetime.utcnow() - timedelta(hours=24)
            ).count()
            
            # Calculate overall health score
            health_score = await self._calculate_user_health_score(user_id, db)
            
            return {
                "user_id": user_id,
                "total_apps": len(user_apps),
                "active_monitoring_tasks": len(user_tasks),
                "recent_threats_24h": recent_threats,
                "recent_alerts_24h": recent_alerts,
                "health_score": health_score,
                "system_status": await self._get_system_status(),
                "active_tasks": [asdict(task) for task in user_tasks],
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get monitoring status: {e}")
            raise

    async def perform_security_scan(
        self, 
        user_id: int, 
        app_id: int, 
        scan_type: ScanType = ScanType.FULL
    ) -> str:
        """Perform a security scan on an app"""
        try:
            # Validate app
            db = next(get_db())
            app = db.query(ConnectedApp).filter(
                ConnectedApp.id == app_id,
                ConnectedApp.user_id == user_id,
                ConnectedApp.is_active == True
            ).first()
            
            if not app:
                raise ValueError(f"App {app_id} not found")
            
            # Create scan task
            task_id = str(uuid.uuid4())
            task = MonitoringTask(
                task_id=task_id,
                user_id=user_id,
                app_id=app_id,
                task_type="security_scan",
                priority=7,
                created_at=datetime.utcnow(),
                scheduled_at=datetime.utcnow(),
                started_at=datetime.utcnow(),
                completed_at=None,
                status="running",
                progress=0.0,
                result=None,
                error_message=None
            )
            
            self.active_tasks[task_id] = task
            
            # Perform scan based on type
            if scan_type == ScanType.QUICK:
                scan_result = await self._perform_quick_scan(app)
            elif scan_type == ScanType.FULL:
                scan_result = await self._perform_full_scan(app)
            elif scan_type == ScanType.DEEP:
                scan_result = await self._perform_deep_scan(app)
            else:
                scan_result = await self._perform_custom_scan(app)
            
            # Update task with results
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.progress = 100.0
            task.result = scan_result
            
            # Store scan results in database
            await self._store_scan_results(app_id, user_id, scan_result, db)
            
            # Process any threats found
            if scan_result.get("threats"):
                await self._process_scan_threats(user_id, app_id, scan_result["threats"])
            
            # Send notifications if needed
            if scan_result.get("critical_issues"):
                await self._send_scan_notifications(user_id, app_id, scan_result)
            
            # Log completion event
            await self.event_processor.process_event(MonitoringEvent(
                event_type=EventType.SCAN_COMPLETED,
                user_id=user_id,
                app_id=app_id,
                severity=AlertSeverity.INFO,
                title="Security Scan Completed",
                description=f"Security scan completed for {app.name}",
                metadata={
                    "task_id": task_id,
                    "scan_type": scan_type.value,
                    "threats_found": len(scan_result.get("threats", [])),
                    "vulnerabilities_found": len(scan_result.get("vulnerabilities", []))
                }
            ))
            
            # Remove from active tasks
            del self.active_tasks[task_id]
            
            logger.info(f"Completed security scan {task_id} for app {app_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to perform security scan: {e}")
            # Update task with error
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = "failed"
                self.active_tasks[task_id].error_message = str(e)
                self.active_tasks[task_id].completed_at = datetime.utcnow()
            raise

    async def analyze_threat_patterns(self, user_id: int, timeframe_hours: int = 24) -> Dict[str, Any]:
        """Analyze threat patterns for a user"""
        try:
            db = next(get_db())
            
            # Get threats within timeframe
            start_time = datetime.utcnow() - timedelta(hours=timeframe_hours)
            threats = db.query(ThreatDetection).filter(
                ThreatDetection.user_id == user_id,
                ThreatDetection.detected_at >= start_time
            ).all()
            
            # Analyze patterns using threat analyzer
            analysis = await self.threat_analyzer.analyze_patterns(threats)
            
            # Generate risk assessment
            risk_assessment = await self.threat_analyzer.assess_risk(user_id, threats)
            
            # Get recommendations
            recommendations = await self.threat_analyzer.get_recommendations(analysis, risk_assessment)
            
            return {
                "timeframe_hours": timeframe_hours,
                "total_threats": len(threats),
                "threat_analysis": analysis,
                "risk_assessment": asdict(risk_assessment),
                "recommendations": recommendations,
                "analyzed_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze threat patterns: {e}")
            raise

    async def get_system_metrics(self, timeframe: str = "1h") -> Dict[str, Any]:
        """Get system performance metrics"""
        try:
            # Parse timeframe
            timeframe_mapping = {
                "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720
            }
            hours = timeframe_mapping.get(timeframe, 1)
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            db = next(get_db())
            
            # Get system metrics from database
            metrics = db.query(SystemMetric).filter(
                SystemMetric.timestamp >= start_time
            ).order_by(SystemMetric.timestamp.desc()).all()
            
            # Process metrics
            processed_metrics = await self._process_system_metrics(metrics)
            
            # Get current service health
            service_health = {
                name: asdict(health) 
                for name, health in self.service_health.items()
            }
            
            # Get active monitoring statistics
            monitoring_stats = await self._get_monitoring_statistics()
            
            return {
                "timeframe": timeframe,
                "metrics": processed_metrics,
                "service_health": service_health,
                "monitoring_stats": monitoring_stats,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            raise

    async def generate_security_report(self, user_id: int, report_type: str = "comprehensive") -> Dict[str, Any]:
        """Generate a comprehensive security report for a user"""
        try:
            db = next(get_db())
            
            # Get user's apps
            user_apps = db.query(ConnectedApp).filter(
                ConnectedApp.user_id == user_id,
                ConnectedApp.is_active == True
            ).all()
            
            # Get recent scan results
            recent_scans = db.query(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
            
            # Get threat history
            threat_history = db.query(ThreatDetection).filter(
                ThreatDetection.user_id == user_id,
                ThreatDetection.detected_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
            
            # Get vulnerability reports
            vulnerability_reports = db.query(VulnerabilityReport).filter(
                VulnerabilityReport.user_id == user_id,
                VulnerabilityReport.created_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
            
            # Generate comprehensive analysis
            report = {
                "report_id": str(uuid.uuid4()),
                "user_id": user_id,
                "report_type": report_type,
                "generated_at": datetime.utcnow().isoformat(),
                "summary": await self._generate_security_summary(user_apps, recent_scans, threat_history),
                "apps_analysis": await self._analyze_apps_security(user_apps, recent_scans),
                "threat_analysis": await self._analyze_threat_trends(threat_history),
                "vulnerability_analysis": await self._analyze_vulnerabilities(vulnerability_reports),
                "recommendations": await self._generate_security_recommendations(user_id, user_apps, threat_history),
                "compliance_status": await self._check_compliance_status(user_id, user_apps),
                "risk_score": await self._calculate_overall_risk_score(user_id)
            }
            
            # Store report in database for future reference
            await self._store_security_report(report, db)
            
            logger.info(f"Generated security report for user {user_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate security report: {e}")
            raise

    # Private helper methods

    async def _start_background_tasks(self):
        """Start background monitoring tasks"""
        tasks = [
            self._health_check_loop(),
            self._metrics_collection_loop(),
            self._threat_detection_loop(),
            self._cleanup_loop()
        ]
        
        for task_coro in tasks:
            task = asyncio.create_task(task_coro)
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _health_check_loop(self):
        """Continuous health checking of services"""
        while True:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(60)

    async def _metrics_collection_loop(self):
        """Continuous collection of system metrics"""
        while True:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(60)  # Collect every minute
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(120)

    async def _threat_detection_loop(self):
        """Continuous threat detection monitoring"""
        while True:
            try:
                await self._perform_threat_detection_sweep()
                await asyncio.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in threat detection loop: {e}")
                await asyncio.sleep(600)

    async def _cleanup_loop(self):
        """Cleanup old data and completed tasks"""
        while True:
            try:
                await self._cleanup_old_data()
                await asyncio.sleep(3600)  # Cleanup every hour
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(7200)

    async def _perform_health_checks(self):
        """Perform health checks on all services"""
        services_to_check = [
            "database", "redis", "websocket", "scanner", 
            "analyzer", "notification", "storage"
        ]
        
        for service_name in services_to_check:
            try:
                start_time = datetime.utcnow()
                health_status = await self._check_service_health(service_name)
                response_time = (datetime.utcnow() - start_time).total_seconds()
                
                # Update service health
                if service_name not in self.service_health:
                    self.service_health[service_name] = ServiceHealth(
                        service_name=service_name,
                        status=ServiceStatus.HEALTHY,
                        last_check=datetime.utcnow(),
                        response_time=response_time,
                        error_count=0,
                        uptime_percentage=100.0,
                        metadata={}
                    )
                
                health = self.service_health[service_name]
                health.last_check = datetime.utcnow()
                health.response_time = response_time
                health.status = health_status
                
                if health_status != ServiceStatus.HEALTHY:
                    health.error_count += 1
                
            except Exception as e:
                logger.error(f"Health check failed for {service_name}: {e}")
                if service_name in self.service_health:
                    self.service_health[service_name].error_count += 1
                    self.service_health[service_name].status = ServiceStatus.UNHEALTHY

    async def _check_service_health(self, service_name: str) -> ServiceStatus:
        """Check health of a specific service"""
        try:
            if service_name == "database":
                db = next(get_db())
                db.execute("SELECT 1")
                return ServiceStatus.HEALTHY
                
            elif service_name == "redis":
                self.redis.ping()
                return ServiceStatus.HEALTHY
                
            elif service_name == "websocket":
                stats = connection_manager.get_connection_stats()
                return ServiceStatus.HEALTHY if stats["active_connections"] >= 0 else ServiceStatus.DEGRADED
                
            elif service_name == "scanner":
                # Test scanner functionality
                return ServiceStatus.HEALTHY
                
            elif service_name == "analyzer":
                # Test analyzer functionality
                return ServiceStatus.HEALTHY
                
            elif service_name == "notification":
                # Test notification service
                return ServiceStatus.HEALTHY
                
            elif service_name == "storage":
                # Test storage service
                return ServiceStatus.HEALTHY
                
            else:
                return ServiceStatus.UNKNOWN
                
        except Exception as e:
            logger.error(f"Service health check failed for {service_name}: {e}")
            return ServiceStatus.UNHEALTHY

    async def _collect_system_metrics(self):
        """Collect and store system metrics"""
        try:
            db = next(get_db())
            
            # Collect various metrics
            metrics = {
                "cpu_usage": await self._get_cpu_usage(),
                "memory_usage": await self._get_memory_usage(),
                "disk_usage": await self._get_disk_usage(),
                "network_io": await self._get_network_io(),
                "active_connections": len(connection_manager._connections),
                "active_tasks": len(self.active_tasks),
                "redis_memory": await self._get_redis_memory_usage(),
                "database_connections": await self._get_db_connection_count()
            }
            
            # Store in database
            system_metric = SystemMetric(
                metric_name="system_overview",
                metric_value=json.dumps(metrics),
                timestamp=datetime.utcnow(),
                metadata={"collected_by": "monitoring_service"}
            )
            
            db.add(system_metric)
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")

    async def _perform_threat_detection_sweep(self):
        """Perform a sweep for new threats across all monitored apps"""
        try:
            db = next(get_db())
            
            # Get all active apps with monitoring enabled
            active_apps = db.query(ConnectedApp).filter(
                ConnectedApp.is_active == True,
                ConnectedApp.monitoring_enabled == True
            ).all()
            
            for app in active_apps:
                try:
                    # Perform threat detection
                    threats = await self.threat_analyzer.detect_threats(app)
                    
                    # Process any new threats found
                    if threats:
                        await self._process_detected_threats(app.user_id, app.id, threats)
                        
                except Exception as e:
                    logger.error(f"Threat detection failed for app {app.id}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to perform threat detection sweep: {e}")

    async def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        try:
            db = next(get_db())
            
            # Clean up old system metrics (keep 30 days)
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            db.query(SystemMetric).filter(
                SystemMetric.timestamp < cutoff_date
            ).delete()
            
            # Clean up old scan results (keep 90 days)
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            db.query(ScanResult).filter(
                ScanResult.created_at < cutoff_date
            ).delete()
            
            # Clean up resolved alerts (keep 60 days)
            cutoff_date = datetime.utcnow() - timedelta(days=60)
            db.query(Alert).filter(
                Alert.status == "resolved",
                Alert.created_at < cutoff_date
            ).delete()
            
            db.commit()
            
            # Clean up Redis cache
            await self._cleanup_redis_cache()
            
            logger.info("Completed data cleanup")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")

    async def _cleanup_redis_cache(self):
        """Clean up old Redis cache entries"""
        try:
            # Clean up old task data
            pattern = "monitoring:task:*"
            keys = self.redis.keys(pattern)
            
            for key in keys:
                task_data = self.redis.get(key)
                if task_data:
                    task = json.loads(task_data)
                    created_at = datetime.fromisoformat(task.get("created_at", ""))
                    
                    # Remove tasks older than 7 days
                    if (datetime.utcnow() - created_at).days > 7:
                        self.redis.delete(key)
                        
        except Exception as e:
            logger.error(f"Failed to cleanup Redis cache: {e}")

    # Additional helper methods would continue here...
    # This includes methods for scanning, analysis, reporting, etc.
    
    async def shutdown(self):
        """Shutdown the monitoring service"""
        logger.info("Shutting down monitoring service...")
        
        # Cancel all background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("Monitoring service shutdown complete")

# Global monitoring service instance
monitoring_service = MonitoringService()