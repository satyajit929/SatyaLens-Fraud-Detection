"""
Monitoring Tests for Fraud Detection System

This module contains comprehensive tests for the monitoring system including
logging, metrics collection, alerting, performance monitoring, and observability features.
"""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import status
import redis
from elasticsearch import Elasticsearch

# Local imports
from app.core.logger import FraudLogger, fraud_logger
from app.core.metrics import MetricsCollector, metrics_collector
from app.core.monitoring import (
    HealthMonitor, 
    PerformanceMonitor,
    AlertManager,
    SystemMonitor
)
from app.services.monitoring_service import MonitoringService
from tests import TestDataFactory, PerformanceTimer, MockExternalService


class TestFraudLogger:
    """Test fraud detection logging system"""
    
    @pytest.fixture
    def logger(self, test_redis):
        """Create logger instance with test Redis"""
        return FraudLogger(redis_client=test_redis)
    
    @pytest.fixture
    def sample_transaction(self):
        """Sample transaction data for logging"""
        return TestDataFactory.create_transaction(
            id="txn_test_123",
            amount=150.00,
            user_id=1,
            merchant_id="merchant_test"
        )
    
    @pytest.fixture
    def sample_fraud_event(self):
        """Sample fraud event data"""
        return {
            "transaction_id": "txn_test_123",
            "user_id": 1,
            "fraud_score": 0.85,
            "indicators": ["unusual_location", "high_velocity"],
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "high"
        }
    
    def test_log_transaction_success(self, logger, sample_transaction):
        """Test successful transaction logging"""
        result = logger.log_transaction(
            transaction_id=sample_transaction["id"],
            user_id=sample_transaction["user_id"],
            amount=sample_transaction["amount"],
            status="completed",
            processing_time=0.25
        )
        
        assert result is True
        
        # Verify log entry was created
        logs = logger.get_transaction_logs(sample_transaction["id"])
        assert len(logs) > 0
        assert logs[0]["transaction_id"] == sample_transaction["id"]
        assert logs[0]["status"] == "completed"
    
    def test_log_fraud_detection(self, logger, sample_fraud_event):
        """Test fraud detection event logging"""
        result = logger.log_fraud_detection(
            transaction_id=sample_fraud_event["transaction_id"],
            fraud_score=sample_fraud_event["fraud_score"],
            indicators=sample_fraud_event["indicators"],
            model_version="v1.2.3",
            confidence=0.92
        )
        
        assert result is True
        
        # Verify fraud log entry
        logs = logger.get_fraud_logs(sample_fraud_event["transaction_id"])
        assert len(logs) > 0
        assert logs[0]["fraud_score"] == sample_fraud_event["fraud_score"]
        assert logs[0]["indicators"] == sample_fraud_event["indicators"]
    
    def test_log_security_event(self, logger):
        """Test security event logging"""
        result = logger.log_security_event(
            event_type="failed_login",
            user_id=1,
            ip_address="192.168.1.100",
            user_agent="Test Browser",
            details={"attempts": 3, "reason": "invalid_password"}
        )
        
        assert result is True
        
        # Verify security log entry
        logs = logger.get_security_logs(user_id=1)
        assert len(logs) > 0
        assert logs[0]["event_type"] == "failed_login"
        assert logs[0]["ip_address"] == "192.168.1.100"
    
    def test_log_api_request(self, logger):
        """Test API request logging"""
        result = logger.log_api_request(
            method="POST",
            endpoint="/transactions/analyze",
            status_code=200,
            response_time=0.15,
            user_id=1,
            ip_address="192.168.1.1",
            request_size=1024,
            response_size=512
        )
        
        assert result is True
        
        # Verify API log entry
        logs = logger.get_api_logs(endpoint="/transactions/analyze")
        assert len(logs) > 0
        assert logs[0]["method"] == "POST"
        assert logs[0]["status_code"] == 200
    
    def test_log_system_event(self, logger):
        """Test system event logging"""
        result = logger.log_system_event(
            event_type="database_connection_error",
            severity="critical",
            component="database",
            message="Connection timeout after 30 seconds",
            metadata={"timeout": 30, "retry_count": 3}
        )
        
        assert result is True
        
        # Verify system log entry
        logs = logger.get_system_logs(component="database")
        assert len(logs) > 0
        assert logs[0]["event_type"] == "database_connection_error"
        assert logs[0]["severity"] == "critical"
    
    def test_log_performance_metrics(self, logger):
        """Test performance metrics logging"""
        result = logger.log_performance_metrics(
            operation="fraud_detection",
            duration=0.45,
            cpu_usage=25.5,
            memory_usage=128.7,
            metadata={"model": "random_forest", "features": 15}
        )
        
        assert result is True
        
        # Verify performance log entry
        logs = logger.get_performance_logs(operation="fraud_detection")
        assert len(logs) > 0
        assert logs[0]["duration"] == 0.45
        assert logs[0]["cpu_usage"] == 25.5
    
    def test_get_logs_with_filters(self, logger, sample_transaction):
        """Test retrieving logs with various filters"""
        # Create multiple log entries
        logger.log_transaction(sample_transaction["id"], 1, 100.0, "completed", 0.1)
        logger.log_transaction(sample_transaction["id"], 1, 200.0, "failed", 0.2)
        
        # Test filtering by status
        completed_logs = logger.get_transaction_logs(
            sample_transaction["id"], 
            filters={"status": "completed"}
        )
        assert len(completed_logs) == 1
        assert completed_logs[0]["status"] == "completed"
        
        # Test filtering by time range
        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow() + timedelta(minutes=5)
        
        time_filtered_logs = logger.get_transaction_logs(
            sample_transaction["id"],
            start_time=start_time,
            end_time=end_time
        )
        assert len(time_filtered_logs) >= 1
    
    def test_log_aggregation(self, logger):
        """Test log aggregation functionality"""
        # Create multiple log entries for aggregation
        for i in range(10):
            logger.log_api_request(
                method="GET",
                endpoint="/health",
                status_code=200,
                response_time=0.1 + (i * 0.01),
                user_id=i % 3,  # Rotate between 3 users
                ip_address=f"192.168.1.{i}"
            )
        
        # Test aggregation by endpoint
        aggregated = logger.aggregate_logs(
            log_type="api_requests",
            group_by="endpoint",
            time_range=timedelta(hours=1)
        )
        
        assert "/health" in aggregated
        assert aggregated["/health"]["count"] == 10
        assert "avg_response_time" in aggregated["/health"]
    
    @patch('app.core.logger.Elasticsearch')
    def test_elasticsearch_integration(self, mock_es, logger):
        """Test Elasticsearch integration for log storage"""
        mock_es_client = Mock()
        mock_es.return_value = mock_es_client
        
        # Configure logger with Elasticsearch
        logger.configure_elasticsearch("http://localhost:9200")
        
        # Log an event
        logger.log_transaction("txn_123", 1, 100.0, "completed", 0.1)
        
        # Verify Elasticsearch index was called
        mock_es_client.index.assert_called()
        
        call_args = mock_es_client.index.call_args
        assert "fraud_detection" in call_args[1]["index"]
        assert call_args[1]["body"]["transaction_id"] == "txn_123"
    
    def test_log_rotation(self, logger, test_redis):
        """Test log rotation functionality"""
        # Create many log entries to trigger rotation
        for i in range(1000):
            logger.log_api_request(
                method="GET",
                endpoint="/test",
                status_code=200,
                response_time=0.1,
                user_id=1,
                ip_address="192.168.1.1"
            )
        
        # Trigger log rotation
        logger.rotate_logs(max_entries=500)
        
        # Verify logs were rotated (should have <= 500 entries)
        logs = logger.get_api_logs(endpoint="/test")
        assert len(logs) <= 500
    
    def test_concurrent_logging(self, logger):
        """Test concurrent logging operations"""
        import concurrent.futures
        
        def log_transaction(i):
            return logger.log_transaction(
                f"txn_{i}",
                user_id=i % 10,
                amount=100.0 + i,
                status="completed",
                processing_time=0.1
            )
        
        # Test concurrent logging
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(log_transaction, i) for i in range(100)]
            results = [future.result() for future in futures]
        
        # All logging operations should succeed
        assert all(results)
        
        # Verify all logs were created
        total_logs = 0
        for i in range(100):
            logs = logger.get_transaction_logs(f"txn_{i}")
            total_logs += len(logs)
        
        assert total_logs == 100


class TestMetricsCollector:
    """Test metrics collection system"""
    
    @pytest.fixture
    def metrics(self, test_redis):
        """Create metrics collector with test Redis"""
        return MetricsCollector(redis_client=test_redis)
    
    def test_counter_metrics(self, metrics):
        """Test counter metrics functionality"""
        # Increment counter
        metrics.increment_counter("transactions_processed")
        metrics.increment_counter("transactions_processed", value=5)
        
        # Get counter value
        count = metrics.get_counter("transactions_processed")
        assert count == 6
        
        # Test counter with labels
        metrics.increment_counter("api_requests", labels={"endpoint": "/health", "method": "GET"})
        metrics.increment_counter("api_requests", labels={"endpoint": "/health", "method": "GET"})
        
        health_requests = metrics.get_counter("api_requests", labels={"endpoint": "/health", "method": "GET"})
        assert health_requests == 2
    
    def test_gauge_metrics(self, metrics):
        """Test gauge metrics functionality"""
        # Set gauge value
        metrics.set_gauge("active_connections", 25)
        assert metrics.get_gauge("active_connections") == 25
        
        # Update gauge value
        metrics.set_gauge("active_connections", 30)
        assert metrics.get_gauge("active_connections") == 30
        
        # Test gauge with labels
        metrics.set_gauge("cpu_usage", 45.5, labels={"server": "web-01"})
        metrics.set_gauge("cpu_usage", 52.3, labels={"server": "web-02"})
        
        web01_cpu = metrics.get_gauge("cpu_usage", labels={"server": "web-01"})
        web02_cpu = metrics.get_gauge("cpu_usage", labels={"server": "web-02"})
        
        assert web01_cpu == 45.5
        assert web02_cpu == 52.3
    
    def test_histogram_metrics(self, metrics):
        """Test histogram metrics functionality"""
        # Record histogram values
        response_times = [0.1, 0.15, 0.12, 0.18, 0.25, 0.09, 0.22]
        
        for time_val in response_times:
            metrics.record_histogram("response_time", time_val)
        
        # Get histogram statistics
        stats = metrics.get_histogram_stats("response_time")
        
        assert stats["count"] == len(response_times)
        assert stats["sum"] == sum(response_times)
        assert abs(stats["avg"] - (sum(response_times) / len(response_times))) < 0.001
        assert stats["min"] == min(response_times)
        assert stats["max"] == max(response_times)
    
    def test_timer_metrics(self, metrics):
        """Test timer metrics functionality"""
        # Test timer context manager
        with metrics.timer("database_query"):
            time.sleep(0.1)  # Simulate database query
        
        # Get timer statistics
        stats = metrics.get_timer_stats("database_query")
        
        assert stats["count"] == 1
        assert stats["avg"] >= 0.1  # Should be at least 100ms
        assert stats["avg"] < 0.2   # But not too much more
    
    def test_custom_metrics(self, metrics):
        """Test custom metrics functionality"""
        # Record custom metric
        metrics.record_custom_metric(
            "fraud_detection_accuracy",
            0.95,
            metric_type="gauge",
            labels={"model": "random_forest", "version": "v1.2"}
        )
        
        # Get custom metric
        value = metrics.get_custom_metric(
            "fraud_detection_accuracy",
            labels={"model": "random_forest", "version": "v1.2"}
        )
        
        assert value == 0.95
    
    def test_metrics_aggregation(self, metrics):
        """Test metrics aggregation over time periods"""
        # Record metrics over time
        for i in range(24):  # 24 hours of data
            timestamp = datetime.utcnow() - timedelta(hours=i)
            metrics.record_time_series_metric(
                "hourly_transactions",
                100 + (i * 5),  # Varying transaction count
                timestamp=timestamp
            )
        
        # Get aggregated metrics
        daily_stats = metrics.get_time_series_stats(
            "hourly_transactions",
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow(),
            aggregation="sum"
        )
        
        assert daily_stats["total"] > 0
        assert "hourly_breakdown" in daily_stats
    
    def test_metrics_export(self, metrics):
        """Test metrics export functionality"""
        # Create various metrics
        metrics.increment_counter("test_counter", value=10)
        metrics.set_gauge("test_gauge", 42.5)
        metrics.record_histogram("test_histogram", 0.15)
        
        # Export metrics in Prometheus format
        prometheus_output = metrics.export_prometheus_format()
        
        assert "test_counter" in prometheus_output
        assert "test_gauge" in prometheus_output
        assert "test_histogram" in prometheus_output
        
        # Export metrics in JSON format
        json_output = metrics.export_json_format()
        json_data = json.loads(json_output)
        
        assert "counters" in json_data
        assert "gauges" in json_data
        assert "histograms" in json_data
    
    def test_metrics_alerts(self, metrics):
        """Test metrics-based alerting"""
        # Set up alert thresholds
        metrics.set_alert_threshold("error_rate", threshold=0.05, operator="greater_than")
        metrics.set_alert_threshold("response_time_p95", threshold=1.0, operator="greater_than")
        
        # Record metrics that should trigger alerts
        metrics.set_gauge("error_rate", 0.08)  # Above threshold
        metrics.set_gauge("response_time_p95", 1.5)  # Above threshold
        
        # Check for triggered alerts
        alerts = metrics.get_triggered_alerts()
        
        assert len(alerts) == 2
        assert any(alert["metric"] == "error_rate" for alert in alerts)
        assert any(alert["metric"] == "response_time_p95" for alert in alerts)


class TestHealthMonitor:
    """Test health monitoring system"""
    
    @pytest.fixture
    def health_monitor(self, test_db, test_redis):
        """Create health monitor instance"""
        return HealthMonitor(db_session=test_db, redis_client=test_redis)
    
    def test_database_health_check(self, health_monitor):
        """Test database health check"""
        result = health_monitor.check_database_health()
        
        assert result["status"] in ["healthy", "unhealthy"]
        assert "response_time" in result
        assert "details" in result
        
        if result["status"] == "healthy":
            assert result["response_time"] > 0
    
    def test_redis_health_check(self, health_monitor):
        """Test Redis health check"""
        result = health_monitor.check_redis_health()
        
        assert result["status"] in ["healthy", "unhealthy"]
        assert "response_time" in result
        assert "details" in result
    
    def test_external_service_health_check(self, health_monitor):
        """Test external service health check"""
        # Mock external service
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.elapsed.total_seconds.return_value = 0.1
            mock_get.return_value = mock_response
            
            result = health_monitor.check_external_service_health(
                "payment_processor",
                "http://localhost:8001/health"
            )
            
            assert result["status"] == "healthy"
            assert result["response_time"] == 0.1
    
    def test_system_resource_check(self, health_monitor):
        """Test system resource monitoring"""
        result = health_monitor.check_system_resources()
        
        assert "cpu_usage" in result
        assert "memory_usage" in result
        assert "disk_usage" in result
        assert "network_io" in result
        
        # Values should be reasonable
        assert 0 <= result["cpu_usage"] <= 100
        assert 0 <= result["memory_usage"] <= 100
        assert 0 <= result["disk_usage"] <= 100
    
    def test_application_health_check(self, health_monitor):
        """Test application-specific health checks"""
        result = health_monitor.check_application_health()
        
        assert "fraud_detection_model" in result
        assert "cache_hit_rate" in result
        assert "active_connections" in result
        assert "queue_size" in result
    
    def test_comprehensive_health_check(self, health_monitor):
        """Test comprehensive health check"""
        result = health_monitor.get_comprehensive_health_status()
        
        assert "overall_status" in result
        assert "services" in result
        assert "system_resources" in result
        assert "application_metrics" in result
        assert "timestamp" in result
        
        # Overall status should be determined from individual checks
        assert result["overall_status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_health_history_tracking(self, health_monitor):
        """Test health status history tracking"""
        # Record multiple health checks
        for i in range(5):
            health_monitor.record_health_check_result({
                "overall_status": "healthy" if i % 2 == 0 else "degraded",
                "timestamp": datetime.utcnow() - timedelta(minutes=i)
            })
        
        # Get health history
        history = health_monitor.get_health_history(hours=1)
        
        assert len(history) == 5
        assert all("overall_status" in entry for entry in history)
        assert all("timestamp" in entry for entry in history)
    
    def test_health_alerts(self, health_monitor):
        """Test health-based alerting"""
        # Simulate unhealthy status
        unhealthy_result = {
            "overall_status": "unhealthy",
            "services": {
                "database": {"status": "unhealthy", "error": "Connection timeout"}
            }
        }
        
        alerts = health_monitor.check_for_health_alerts(unhealthy_result)
        
        assert len(alerts) > 0
        assert any("database" in alert["message"] for alert in alerts)


class TestPerformanceMonitor:
    """Test performance monitoring system"""
    
    @pytest.fixture
    def perf_monitor(self, test_redis):
        """Create performance monitor instance"""
        return PerformanceMonitor(redis_client=test_redis)
    
    def test_response_time_monitoring(self, perf_monitor):
        """Test response time monitoring"""
        # Record response times
        response_times = [0.1, 0.15, 0.12, 0.18, 0.25, 0.09, 0.22]
        
        for rt in response_times:
            perf_monitor.record_response_time("/api/transactions", rt)
        
        # Get response time statistics
        stats = perf_monitor.get_response_time_stats("/api/transactions")
        
        assert stats["count"] == len(response_times)
        assert abs(stats["average"] - (sum(response_times) / len(response_times))) < 0.001
        assert stats["p50"] > 0
        assert stats["p95"] > 0
        assert stats["p99"] > 0
    
    def test_throughput_monitoring(self, perf_monitor):
        """Test throughput monitoring"""
        # Record requests over time
        for i in range(100):
            perf_monitor.record_request("/api/health", datetime.utcnow())
        
        # Get throughput statistics
        stats = perf_monitor.get_throughput_stats("/api/health", window_minutes=5)
        
        assert stats["requests_per_minute"] > 0
        assert stats["total_requests"] == 100
    
    def test_error_rate_monitoring(self, perf_monitor):
        """Test error rate monitoring"""
        # Record successful and failed requests
        for i in range(90):  # 90 successful
            perf_monitor.record_request_result("/api/transactions", success=True)
        
        for i in range(10):  # 10 failed
            perf_monitor.record_request_result("/api/transactions", success=False)
        
        # Get error rate
        error_rate = perf_monitor.get_error_rate("/api/transactions")
        
        assert abs(error_rate - 0.1) < 0.01  # Should be ~10%
    
    def test_resource_utilization_monitoring(self, perf_monitor):
        """Test resource utilization monitoring"""
        # Record resource usage
        perf_monitor.record_resource_usage(
            cpu_percent=45.5,
            memory_percent=62.3,
            disk_io_read=1024,
            disk_io_write=512,
            network_io_sent=2048,
            network_io_recv=1536
        )
        
        # Get resource statistics
        stats = perf_monitor.get_resource_stats(window_minutes=5)
        
        assert "cpu" in stats
        assert "memory" in stats
        assert "disk_io" in stats
        assert "network_io" in stats
    
    def test_database_performance_monitoring(self, perf_monitor):
        """Test database performance monitoring"""
        # Record database query performance
        queries = [
            {"query": "SELECT * FROM users", "duration": 0.05, "rows": 100},
            {"query": "SELECT * FROM transactions", "duration": 0.15, "rows": 500},
            {"query": "INSERT INTO logs", "duration": 0.02, "rows": 1}
        ]
        
        for query in queries:
            perf_monitor.record_database_query(
                query["query"],
                query["duration"],
                query["rows"]
            )
        
        # Get database performance stats
        stats = perf_monitor.get_database_performance_stats()
        
        assert "total_queries" in stats
        assert "average_duration" in stats
        assert "slow_queries" in stats
        assert stats["total_queries"] == 3
    
    def test_cache_performance_monitoring(self, perf_monitor):
        """Test cache performance monitoring"""
        # Record cache operations
        for i in range(80):  # 80 hits
            perf_monitor.record_cache_operation("hit")
        
        for i in range(20):  # 20 misses
            perf_monitor.record_cache_operation("miss")
        
        # Get cache performance stats
        stats = perf_monitor.get_cache_performance_stats()
        
        assert stats["hit_rate"] == 0.8  # 80%
        assert stats["miss_rate"] == 0.2  # 20%
        assert stats["total_operations"] == 100
    
    def test_performance_alerts(self, perf_monitor):
        """Test performance-based alerting"""
        # Set performance thresholds
        perf_monitor.set_performance_threshold("response_time_p95", 1.0)
        perf_monitor.set_performance_threshold("error_rate", 0.05)
        
        # Record performance data that exceeds thresholds
        for i in range(10):
            perf_monitor.record_response_time("/api/slow", 1.5)  # Slow responses
            perf_monitor.record_request_result("/api/errors", success=False)  # Errors
        
        # Check for performance alerts
        alerts = perf_monitor.get_performance_alerts()
        
        assert len(alerts) > 0
        assert any("response_time" in alert["metric"] for alert in alerts)


class TestAlertManager:
    """Test alerting system"""
    
    @pytest.fixture
    def alert_manager(self, test_redis):
        """Create alert manager instance"""
        return AlertManager(redis_client=test_redis)
    
    def test_create_alert(self, alert_manager):
        """Test alert creation"""
        alert = alert_manager.create_alert(
            alert_type="high_fraud_score",
            severity="critical",
            message="Transaction txn_123 has fraud score 0.95",
            metadata={
                "transaction_id": "txn_123",
                "fraud_score": 0.95,
                "user_id": 1
            }
        )
        
        assert alert["id"] is not None
        assert alert["alert_type"] == "high_fraud_score"
        assert alert["severity"] == "critical"
        assert alert["status"] == "active"
        assert "timestamp" in alert
    
    def test_alert_routing(self, alert_manager):
        """Test alert routing based on severity and type"""
        # Configure alert routing rules
        alert_manager.configure_routing_rule(
            alert_type="high_fraud_score",
            severity="critical",
            channels=["email", "slack", "pagerduty"]
        )
        
        alert_manager.configure_routing_rule(
            alert_type="system_error",
            severity="warning",
            channels=["slack"]
        )
        
        # Create alerts
        critical_alert = alert_manager.create_alert(
            "high_fraud_score", "critical", "Critical fraud detected"
        )
        
        warning_alert = alert_manager.create_alert(
            "system_error", "warning", "System warning occurred"
        )
        
        # Check routing
        critical_channels = alert_manager.get_alert_channels(critical_alert["id"])
        warning_channels = alert_manager.get_alert_channels(warning_alert["id"])
        
        assert "email" in critical_channels
        assert "slack" in critical_channels
        assert "pagerduty" in critical_channels
        
        assert "slack" in warning_channels
        assert "email" not in warning_channels
    
    def test_alert_escalation(self, alert_manager):
        """Test alert escalation"""
        # Configure escalation rules
        alert_manager.configure_escalation_rule(
            alert_type="high_fraud_score",
            escalation_time_minutes=5,
            escalation_severity="critical"
        )
        
        # Create alert
        alert = alert_manager.create_alert(
            "high_fraud_score", "high", "Fraud detected"
        )
        
        # Simulate time passing
        alert_manager.process_escalations(
            current_time=datetime.utcnow() + timedelta(minutes=6)
        )
        
        # Check if alert was escalated
        updated_alert = alert_manager.get_alert(alert["id"])
        assert updated_alert["severity"] == "critical"
    
    def test_alert_suppression(self, alert_manager):
        """Test alert suppression to prevent spam"""
        # Configure suppression rule
        alert_manager.configure_suppression_rule(
            alert_type="database_connection_error",
            suppression_window_minutes=10,
            max_alerts=1
        )
        
        # Create multiple similar alerts
        alerts = []
        for i in range(5):
            alert = alert_manager.create_alert(
                "database_connection_error",
                "high",
                f"Database connection failed - attempt {i+1}"
            )
            alerts.append(alert)
        
        # Only first alert should be active, others suppressed
        active_alerts = [a for a in alerts if a["status"] == "active"]
        suppressed_alerts = [a for a in alerts if a["status"] == "suppressed"]
        
        assert len(active_alerts) == 1
        assert len(suppressed_alerts) == 4
    
    def test_alert_acknowledgment(self, alert_manager):
        """Test alert acknowledgment"""
        # Create alert
        alert = alert_manager.create_alert(
            "system_error", "high", "System error occurred"
        )
        
        # Acknowledge alert
        result = alert_manager.acknowledge_alert(
            alert["id"],
            acknowledged_by="admin@example.com",
            acknowledgment_note="Investigating the issue"
        )
        
        assert result is True
        
        # Check alert status
        updated_alert = alert_manager.get_alert(alert["id"])
        assert updated_alert["status"] == "acknowledged"
        assert updated_alert["acknowledged_by"] == "admin@example.com"
    
    def test_alert_resolution(self, alert_manager):
        """Test alert resolution"""
        # Create and acknowledge alert
        alert = alert_manager.create_alert(
            "system_error", "high", "System error occurred"
        )
        
        alert_manager.acknowledge_alert(alert["id"], "admin@example.com")
        
        # Resolve alert
        result = alert_manager.resolve_alert(
            alert["id"],
            resolved_by="admin@example.com",
            resolution_note="Issue fixed by restarting service"
        )
        
        assert result is True
        
        # Check alert status
        updated_alert = alert_manager.get_alert(alert["id"])
        assert updated_alert["status"] == "resolved"
        assert updated_alert["resolved_by"] == "admin@example.com"
    
    @patch('app.core.monitoring.send_email')
    @patch('app.core.monitoring.send_slack_message')
    def test_alert_notification_delivery(self, mock_slack, mock_email, alert_manager):
        """Test alert notification delivery"""
        # Configure notification channels
        alert_manager.configure_notification_channel(
            "email",
            config={"smtp_server": "localhost", "recipients": ["admin@example.com"]}
        )
        
        alert_manager.configure_notification_channel(
            "slack",
            config={"webhook_url": "https://hooks.slack.com/test", "channel": "#alerts"}
        )
        
        # Create alert with notifications
        alert = alert_manager.create_alert(
            "critical_error",
            "critical",
            "Critical system error",
            notify_channels=["email", "slack"]
        )
        
        # Process notifications
        alert_manager.process_notifications()
        
        # Verify notifications were sent
        mock_email.assert_called_once()
        mock_slack.assert_called_once()
    
    def test_alert_metrics(self, alert_manager):
        """Test alert metrics collection"""
        # Create various alerts
        alert_manager.create_alert("fraud_detection", "high", "Fraud detected")
        alert_manager.create_alert("system_error", "medium", "System error")
        alert_manager.create_alert("performance_issue", "low", "Performance degraded")
        
        # Get alert metrics
        metrics = alert_manager.get_alert_metrics(time_window_hours=24)
        
        assert "total_alerts" in metrics
        assert "alerts_by_severity" in metrics
        assert "alerts_by_type" in metrics
        assert "resolution_time_avg" in metrics
        
        assert metrics["total_alerts"] == 3
        assert metrics["alerts_by_severity"]["high"] == 1
        assert metrics["alerts_by_severity"]["medium"] == 1
        assert metrics["alerts_by_severity"]["low"] == 1


class TestSystemMonitor:
    """Test system monitoring integration"""
    
    @pytest.fixture
    def system_monitor(self, test_db, test_redis):
        """Create system monitor instance"""
        return SystemMonitor(db_session=test_db, redis_client=test_redis)
    
    def test_comprehensive_monitoring(self, system_monitor):
        """Test comprehensive system monitoring"""
        # Run comprehensive monitoring check
        result = system_monitor.run_monitoring_cycle()
        
        assert "health_status" in result
        assert "performance_metrics" in result
        assert "alerts_generated" in result
        assert "timestamp" in result
    
    def test_monitoring_dashboard_data(self, system_monitor):
        """Test monitoring dashboard data collection"""
        dashboard_data = system_monitor.get_dashboard_data()
        
        assert "system_health" in dashboard_data
        assert "performance_overview" in dashboard_data
        assert "recent_alerts" in dashboard_data
        assert "fraud_detection_stats" in dashboard_data
        assert "api_metrics" in dashboard_data
    
    def test_monitoring_reports(self, system_monitor):
        """Test monitoring report generation"""
        # Generate daily report
        daily_report = system_monitor.generate_daily_report()
        
        assert "date" in daily_report
        assert "summary" in daily_report
        assert "health_incidents" in daily_report
        assert "performance_summary" in daily_report
        assert "alert_summary" in daily_report
        assert "fraud_detection_summary" in daily_report
    
    @pytest.mark.asyncio
    async def test_real_time_monitoring(self, system_monitor):
        """Test real-time monitoring capabilities"""
        # Start real-time monitoring
        monitoring_task = asyncio.create_task(
            system_monitor.start_real_time_monitoring(interval_seconds=1)
        )
        
        # Let it run for a few seconds
        await asyncio.sleep(3)
        
        # Stop monitoring
        monitoring_task.cancel()
        
        # Check that monitoring data was collected
        recent_data = system_monitor.get_recent_monitoring_data(minutes=5)
        assert len(recent_data) > 0


class TestMonitoringIntegration:
    """Integration tests for monitoring system"""
    
    @pytest.fixture
    def client(self, test_app):
        """Create test client"""
        return TestClient(test_app)
    
    @pytest.fixture
    def monitoring_service(self, test_db, test_redis):
        """Create monitoring service"""
        return MonitoringService(db_session=test_db, redis_client=test_redis)
    
    def test_end_to_end_monitoring_flow(self, client, monitoring_service):
        """Test complete monitoring flow"""
        # 1. Make API request (should be logged)
        response = client.get("/health")
        assert response.status_code == 200
        
        # 2. Check that request was logged
        api_logs = fraud_logger.get_api_logs(endpoint="/health", limit=1)
        assert len(api_logs) > 0
        
        # 3. Check that metrics were recorded
        request_count = metrics_collector.get_counter("api_requests", 
                                                     labels={"endpoint": "/health"})
        assert request_count > 0
        
        # 4. Generate monitoring report
        report = monitoring_service.generate_monitoring_report()
        assert "api_metrics" in report
        assert report["api_metrics"]["total_requests"] > 0
    
    def test_fraud_detection_monitoring(self, client, monitoring_service):
        """Test fraud detection monitoring integration"""
        # This would require setting up a complete fraud detection flow
        # For now, we'll test the monitoring components in isolation
        
        # Simulate fraud detection event
        fraud_logger.log_fraud_detection(
            transaction_id="txn_test_123",
            fraud_score=0.85,
            indicators=["unusual_location", "high_velocity"],
            model_version="v1.2.3",
            confidence=0.92
        )
        
        # Record fraud detection metrics
        metrics_collector.increment_counter("fraud_detections")
        metrics_collector.record_histogram("fraud_scores", 0.85)
        
        # Check monitoring data
        fraud_logs = fraud_logger.get_fraud_logs("txn_test_123")
        assert len(fraud_logs) > 0
        
        fraud_count = metrics_collector.get_counter("fraud_detections")
        assert fraud_count > 0
    
    def test_performance_monitoring_integration(self, client):
        """Test performance monitoring integration"""
        # Make multiple requests to generate performance data
        with PerformanceTimer() as timer:
            for i in range(10):
                response = client.get("/health")
                assert response.status_code == 200
        
        # Check that performance data was collected
        # This would depend on the actual implementation of performance monitoring
        assert timer.elapsed_ms > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])