"""
Application Tests for Fraud Detection System

This module contains comprehensive tests for the main application setup, configuration,
middleware, error handling, health checks, and overall application behavior.
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import status, FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
import redis
from sqlalchemy import create_engine

# Local imports
from app.main import create_app, app
from app.core import settings, database, cache_manager
from app.core.middleware import (
    SecurityHeadersMiddleware, 
    RequestLoggingMiddleware,
    RateLimitMiddleware,
    CORSMiddleware
)
from app.core.exceptions import (
    FraudDetectionException,
    ValidationError,
    AuthenticationError,
    RateLimitError
)
from tests import TestDataFactory, PerformanceTimer, LoadTestScenario


class TestApplicationSetup:
    """Test application initialization and configuration"""
    
    def test_app_creation(self):
        """Test application creation"""
        test_app = create_app()
        
        assert isinstance(test_app, FastAPI)
        assert test_app.title == "Fraud Detection API"
        assert test_app.version == settings.app_version
        assert test_app.description is not None
    
    def test_app_settings_configuration(self):
        """Test application settings are properly configured"""
        test_app = create_app()
        
        # Check that settings are accessible
        assert hasattr(settings, 'database_url')
        assert hasattr(settings, 'redis_url')
        assert hasattr(settings, 'secret_key')
        assert hasattr(settings, 'environment')
        
        # Check environment-specific settings
        if settings.environment == "test":
            assert "test" in settings.database_url.lower()
    
    def test_database_connection_setup(self):
        """Test database connection is properly configured"""
        # Test database engine creation
        engine = create_engine(settings.database_url)
        
        # Test connection
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            assert result.fetchone()[0] == 1
    
    def test_redis_connection_setup(self):
        """Test Redis connection is properly configured"""
        redis_client = redis.Redis.from_url(settings.redis_url)
        
        # Test connection
        assert redis_client.ping() is True
        
        # Test basic operations
        redis_client.set("test_key", "test_value")
        assert redis_client.get("test_key").decode() == "test_value"
        redis_client.delete("test_key")
    
    def test_middleware_registration(self):
        """Test that all required middleware is registered"""
        test_app = create_app()
        
        # Check middleware stack
        middleware_classes = [type(middleware.cls) for middleware in test_app.user_middleware]
        
        # Should include our custom middleware
        assert any("SecurityHeaders" in str(cls) for cls in middleware_classes)
        assert any("RequestLogging" in str(cls) for cls in middleware_classes)
        assert any("RateLimit" in str(cls) for cls in middleware_classes)
    
    def test_exception_handlers_registration(self):
        """Test that exception handlers are properly registered"""
        test_app = create_app()
        
        # Check that custom exception handlers are registered
        assert FraudDetectionException in test_app.exception_handlers
        assert ValidationError in test_app.exception_handlers
        assert AuthenticationError in test_app.exception_handlers
    
    def test_router_registration(self):
        """Test that all routers are properly registered"""
        test_app = create_app()
        
        # Get all registered routes
        routes = [route.path for route in test_app.routes]
        
        # Check that main API routes are registered
        assert any("/auth" in route for route in routes)
        assert any("/transactions" in route for route in routes)
        assert any("/users" in route for route in routes)
        assert any("/fraud" in route for route in routes)
        assert any("/health" in route for route in routes)


class TestApplicationMiddleware:
    """Test application middleware functionality"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(create_app())
    
    def test_security_headers_middleware(self, client):
        """Test security headers are added to responses"""
        response = client.get("/health")
        
        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        
        assert "Strict-Transport-Security" in response.headers
    
    def test_cors_middleware(self, client):
        """Test CORS middleware configuration"""
        # Test preflight request
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET"
            }
        )
        
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers
    
    @patch('app.core.logger.fraud_logger')
    def test_request_logging_middleware(self, mock_logger, client):
        """Test request logging middleware"""
        response = client.get("/health")
        
        # Verify that request was logged
        mock_logger.log_api_request.assert_called()
        
        # Check log call arguments
        call_args = mock_logger.log_api_request.call_args
        assert call_args[1]['method'] == 'GET'
        assert '/health' in call_args[1]['endpoint']
        assert call_args[1]['status_code'] == 200
    
    def test_rate_limit_middleware(self, client):
        """Test rate limiting middleware"""
        # Make requests up to the limit
        responses = []
        for i in range(10):  # Assuming limit is higher than this
            response = client.get("/health")
            responses.append(response)
        
        # All requests should succeed initially
        for response in responses:
            assert response.status_code == 200
        
        # Test rate limit headers are present
        last_response = responses[-1]
        assert "X-RateLimit-Limit" in last_response.headers
        assert "X-RateLimit-Remaining" in last_response.headers
    
    def test_request_id_middleware(self, client):
        """Test request ID is added to responses"""
        response = client.get("/health")
        
        assert "X-Request-ID" in response.headers
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) > 0
        
        # Request ID should be unique for each request
        response2 = client.get("/health")
        request_id2 = response2.headers["X-Request-ID"]
        assert request_id != request_id2


class TestApplicationHealthChecks:
    """Test application health check endpoints"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_basic_health_check(self, client):
        """Test basic health check endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data
        assert "environment" in data
    
    def test_detailed_health_check(self, client):
        """Test detailed health check endpoint"""
        response = client.get("/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "services" in data
        assert "database" in data["services"]
        assert "redis" in data["services"]
        assert "external_apis" in data["services"]
    
    def test_readiness_check(self, client):
        """Test readiness check endpoint"""
        response = client.get("/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["ready"] is True
        assert "checks" in data
    
    def test_liveness_check(self, client):
        """Test liveness check endpoint"""
        response = client.get("/health/live")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["alive"] is True
    
    @patch('app.core.database.engine.connect')
    def test_health_check_database_failure(self, mock_connect, client):
        """Test health check when database is down"""
        mock_connect.side_effect = Exception("Database connection failed")
        
        response = client.get("/health/detailed")
        
        # Should still return 200 but indicate database is unhealthy
        assert response.status_code == 200
        data = response.json()
        
        assert data["services"]["database"]["status"] == "unhealthy"
    
    @patch('redis.Redis.ping')
    def test_health_check_redis_failure(self, mock_ping, client):
        """Test health check when Redis is down"""
        mock_ping.side_effect = Exception("Redis connection failed")
        
        response = client.get("/health/detailed")
        
        # Should still return 200 but indicate Redis is unhealthy
        assert response.status_code == 200
        data = response.json()
        
        assert data["services"]["redis"]["status"] == "unhealthy"


class TestApplicationErrorHandling:
    """Test application error handling"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_404_error_handling(self, client):
        """Test 404 error handling"""
        response = client.get("/nonexistent-endpoint")
        
        assert response.status_code == 404
        data = response.json()
        
        assert "detail" in data
        assert "error_code" in data
        assert "timestamp" in data
    
    def test_405_error_handling(self, client):
        """Test 405 method not allowed error handling"""
        response = client.post("/health")  # GET-only endpoint
        
        assert response.status_code == 405
        data = response.json()
        
        assert "detail" in data
        assert "method not allowed" in data["detail"].lower()
    
    def test_422_validation_error_handling(self, client):
        """Test 422 validation error handling"""
        # Send invalid JSON to registration endpoint
        response = client.post(
            "/auth/register",
            json={"email": "invalid-email"}  # Missing required fields
        )
        
        assert response.status_code == 422
        data = response.json()
        
        assert "detail" in data
        assert isinstance(data["detail"], list)
    
    def test_500_internal_error_handling(self, client):
        """Test 500 internal server error handling"""
        # This would need a specific endpoint that raises an unhandled exception
        # For testing purposes, we'll mock an internal error
        
        with patch('app.api.endpoints.health.get_health_status') as mock_health:
            mock_health.side_effect = Exception("Internal server error")
            
            response = client.get("/health")
            
            assert response.status_code == 500
            data = response.json()
            
            assert "detail" in data
            assert "internal server error" in data["detail"].lower()
    
    def test_custom_exception_handling(self, client):
        """Test custom exception handling"""
        # This would test our custom FraudDetectionException handling
        # We'd need an endpoint that can raise this exception for testing
        pass
    
    @patch('app.core.logger.fraud_logger')
    def test_error_logging(self, mock_logger, client):
        """Test that errors are properly logged"""
        # Trigger a 404 error
        client.get("/nonexistent-endpoint")
        
        # Verify error was logged
        # This depends on how error logging is implemented
        pass


class TestApplicationSecurity:
    """Test application security features"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_sql_injection_protection(self, client):
        """Test SQL injection protection"""
        malicious_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in malicious_payloads:
            # Test in query parameters
            response = client.get(f"/transactions?search={payload}")
            
            # Should not cause server error (500)
            assert response.status_code != 500
    
    def test_xss_protection(self, client):
        """Test XSS protection"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            # Test in request body
            response = client.post(
                "/auth/register",
                json={
                    "email": "test@example.com",
                    "username": "testuser",
                    "full_name": payload,
                    "password": "SecurePassword123!"
                }
            )
            
            # Should either reject or sanitize
            if response.status_code == 201:
                data = response.json()
                # XSS payload should not be returned as-is
                assert payload not in str(data)
    
    def test_csrf_protection(self, client):
        """Test CSRF protection"""
        # Test that state-changing operations require proper authentication
        response = client.post("/transactions/analyze", json={
            "amount": 100.00,
            "merchant_id": "test_merchant"
        })
        
        # Should require authentication
        assert response.status_code == 401
    
    def test_request_size_limits(self, client):
        """Test request size limits"""
        # Create a large payload
        large_payload = {"data": "x" * (10 * 1024 * 1024)}  # 10MB
        
        response = client.post("/auth/register", json=large_payload)
        
        # Should reject large requests
        assert response.status_code in [413, 422]  # Payload too large or validation error
    
    def test_sensitive_data_exposure(self, client):
        """Test that sensitive data is not exposed"""
        # Register a user
        user_data = TestDataFactory.create_user()
        response = client.post("/auth/register", json=user_data)
        
        if response.status_code == 201:
            data = response.json()
            
            # Password should not be in response
            assert "password" not in str(data)
            assert user_data["password"] not in str(data)


class TestApplicationPerformance:
    """Test application performance characteristics"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_health_check_performance(self, client):
        """Test health check endpoint performance"""
        with PerformanceTimer() as timer:
            response = client.get("/health")
        
        assert response.status_code == 200
        assert timer.elapsed_ms < 100  # Should be very fast
    
    def test_concurrent_requests_performance(self, client):
        """Test performance under concurrent load"""
        import concurrent.futures
        import threading
        
        def make_request():
            return client.get("/health")
        
        # Test with multiple concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            with PerformanceTimer() as timer:
                futures = [executor.submit(make_request) for _ in range(50)]
                responses = [future.result() for future in futures]
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200
        
        # Should handle concurrent load reasonably well
        assert timer.elapsed_ms < 5000  # 5 seconds for 50 concurrent requests
    
    def test_memory_usage_stability(self, client):
        """Test memory usage doesn't grow excessively"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Make many requests
        for i in range(100):
            response = client.get("/health")
            assert response.status_code == 200
        
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be reasonable (less than 50MB)
        assert memory_growth < 50 * 1024 * 1024
    
    @pytest.mark.asyncio
    async def test_load_testing_scenario(self, client):
        """Test application under load"""
        async def make_health_request(user_id):
            """Simulate user making health check request"""
            import asyncio
            await asyncio.sleep(0.01)  # Small delay
            response = client.get("/health")
            return response.status_code == 200
        
        # Run load test scenario
        scenario = LoadTestScenario(
            name="health_check_load",
            concurrent_users=20,
            duration_seconds=10
        )
        
        results = await scenario.run_scenario(make_health_request)
        
        # Verify load test results
        assert results["successful_requests"] > 0
        assert results["failed_requests"] == 0
        assert results["average_response_time"] < 1.0  # Less than 1 second average


class TestApplicationConfiguration:
    """Test application configuration management"""
    
    def test_environment_specific_settings(self):
        """Test environment-specific configuration"""
        # Test settings are loaded correctly for test environment
        assert settings.environment == "test"
        assert "test" in settings.database_url.lower()
    
    def test_feature_flags(self):
        """Test feature flag configuration"""
        # Test that feature flags are properly configured
        assert hasattr(settings, 'enable_ml_fraud_detection')
        assert hasattr(settings, 'enable_real_time_monitoring')
        assert hasattr(settings, 'enable_advanced_analytics')
    
    def test_external_service_configuration(self):
        """Test external service configuration"""
        # Test that external service URLs are configured
        assert hasattr(settings, 'payment_processor_url')
        assert hasattr(settings, 'credit_bureau_url')
        
        # In test environment, these should be mock URLs
        if settings.environment == "test":
            assert "mock" in settings.payment_processor_url.lower()
    
    def test_security_configuration(self):
        """Test security configuration"""
        # Test security settings
        assert settings.secret_key is not None
        assert len(settings.secret_key) >= 32  # Should be sufficiently long
        assert settings.algorithm == "HS256"
        assert settings.access_token_expire_minutes > 0
    
    def test_logging_configuration(self):
        """Test logging configuration"""
        # Test logging settings
        assert hasattr(settings, 'log_level')
        assert hasattr(settings, 'log_format')
        assert settings.log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']


class TestApplicationIntegration:
    """Integration tests for the complete application"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_full_application_startup(self, client):
        """Test complete application startup process"""
        # Test that application starts successfully
        response = client.get("/health")
        assert response.status_code == 200
        
        # Test that all major endpoints are accessible
        endpoints_to_test = [
            ("/health", 200),
            ("/health/ready", 200),
            ("/health/live", 200),
            ("/docs", 200),  # OpenAPI docs
            ("/redoc", 200),  # ReDoc documentation
        ]
        
        for endpoint, expected_status in endpoints_to_test:
            response = client.get(endpoint)
            assert response.status_code == expected_status
    
    def test_database_integration(self, client):
        """Test database integration works correctly"""
        # This would test that database operations work through the API
        # For example, registering a user should create a database record
        
        user_data = TestDataFactory.create_user()
        response = client.post("/auth/register", json=user_data)
        
        if response.status_code == 201:
            # User should be created in database
            data = response.json()
            assert "user" in data
            assert data["user"]["email"] == user_data["email"]
    
    def test_cache_integration(self, client):
        """Test cache integration works correctly"""
        # Test that caching works for appropriate endpoints
        # Make the same request twice and verify caching behavior
        
        response1 = client.get("/health/detailed")
        response2 = client.get("/health/detailed")
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # Both should succeed (caching should be transparent)
    
    def test_external_service_integration(self, client):
        """Test external service integration"""
        # In test environment, external services should be mocked
        # This test verifies the mocking works correctly
        
        # This would test transaction analysis which uses external services
        # But requires authentication, so we'd need to set that up first
        pass
    
    def test_end_to_end_workflow(self, client):
        """Test complete end-to-end workflow"""
        # Test a complete user workflow:
        # 1. Register user
        # 2. Login
        # 3. Analyze transaction
        # 4. Check fraud results
        # 5. Logout
        
        # 1. Register
        user_data = TestDataFactory.create_user()
        register_response = client.post("/auth/register", json=user_data)
        
        if register_response.status_code != 201:
            pytest.skip("User registration failed, skipping end-to-end test")
        
        # 2. Login
        login_data = {
            "username": user_data["email"],
            "password": user_data["password"]
        }
        login_response = client.post("/auth/login", data=login_data)
        assert login_response.status_code == 200
        
        token_data = login_response.json()
        access_token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # 3. Test authenticated endpoint
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.status_code == 200
        
        # 4. Logout
        logout_response = client.post("/auth/logout", headers=headers)
        assert logout_response.status_code == 200


class TestApplicationDocumentation:
    """Test application documentation and API schema"""
    
    @pytest.fixture
    def client(self):
        return TestClient(create_app())
    
    def test_openapi_schema_generation(self, client):
        """Test OpenAPI schema is generated correctly"""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        schema = response.json()
        
        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema
        assert schema["info"]["title"] == "Fraud Detection API"
    
    def test_swagger_ui_accessibility(self, client):
        """Test Swagger UI is accessible"""
        response = client.get("/docs")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_redoc_accessibility(self, client):
        """Test ReDoc documentation is accessible"""
        response = client.get("/redoc")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_api_endpoints_documented(self, client):
        """Test that all API endpoints are documented"""
        response = client.get("/openapi.json")
        schema = response.json()
        
        paths = schema.get("paths", {})
        
        # Check that main endpoints are documented
        expected_paths = [
            "/auth/login",
            "/auth/register", 
            "/auth/logout",
            "/health",
            "/transactions/analyze"
        ]
        
        for expected_path in expected_paths:
            assert any(expected_path in path for path in paths.keys())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])