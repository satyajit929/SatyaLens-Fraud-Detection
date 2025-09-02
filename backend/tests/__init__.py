"""
Test Suite for Fraud Detection System

This package contains comprehensive tests for all components of the fraud detection system
including unit tests, integration tests, performance tests, and security tests.
"""

import os
import sys
import pytest
import asyncio
from pathlib import Path

# Add the app directory to Python path for imports
app_dir = Path(__file__).parent.parent / "app"
sys.path.insert(0, str(app_dir))

# Test configuration
TEST_DATABASE_URL = "sqlite:///./test_fraud_detection.db"
TEST_REDIS_URL = "redis://localhost:6379/1"
TEST_ELASTICSEARCH_URL = "http://localhost:9200"

# Test settings
class TestSettings:
    """Test configuration settings"""
    
    # Database
    database_url = TEST_DATABASE_URL
    database_echo = False
    
    # Redis
    redis_url = TEST_REDIS_URL
    redis_decode_responses = True
    
    # Security
    secret_key = "test-secret-key-not-for-production"
    algorithm = "HS256"
    access_token_expire_minutes = 30
    
    # Logging
    log_level = "DEBUG"
    log_format = "json"
    enable_elasticsearch_logging = False
    
    # Rate limiting
    enable_rate_limiting = True
    
    # Environment
    environment = "test"
    app_name = "fraud-detection-test"
    app_version = "1.0.0-test"
    
    # External services (mock endpoints)
    payment_processor_url = "http://localhost:8001/mock"
    credit_bureau_url = "http://localhost:8002/mock"
    
    # Feature flags
    enable_ml_fraud_detection = True
    enable_real_time_monitoring = False
    enable_advanced_analytics = False

# Global test settings instance
test_settings = TestSettings()

# Pytest fixtures that are available to all tests
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def test_app():
    """Create test application instance"""
    from app.main import create_app
    from app.core import settings
    
    # Override settings for testing
    for key, value in vars(test_settings).items():
        if not key.startswith('_'):
            setattr(settings, key, value)
    
    app = create_app()
    return app

@pytest.fixture(scope="function")
def test_db():
    """Create test database for each test function"""
    from app.core.database import engine, Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Create test engine
    test_engine = create_engine(TEST_DATABASE_URL, echo=False)
    
    # Create all tables
    Base.metadata.create_all(bind=test_engine)
    
    # Create session
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestSessionLocal()
    
    yield session
    
    # Cleanup
    session.close()
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture(scope="function")
def test_redis():
    """Create test Redis connection"""
    import redis
    
    redis_client = redis.Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    
    # Clear test database
    redis_client.flushdb()
    
    yield redis_client
    
    # Cleanup
    redis_client.flushdb()
    redis_client.close()

@pytest.fixture(scope="function")
def test_user_data():
    """Sample user data for testing"""
    return {
        "id": 1,
        "email": "test@example.com",
        "username": "testuser",
        "full_name": "Test User",
        "is_active": True,
        "is_verified": True,
        "created_at": "2024-01-01T00:00:00Z"
    }

@pytest.fixture(scope="function")
def test_transaction_data():
    """Sample transaction data for testing"""
    return {
        "id": "txn_123456789",
        "user_id": 1,
        "amount": 100.00,
        "currency": "USD",
        "merchant_id": "merchant_123",
        "merchant_name": "Test Merchant",
        "transaction_type": "purchase",
        "payment_method": "credit_card",
        "card_last_four": "1234",
        "timestamp": "2024-01-01T12:00:00Z",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0 (Test Browser)",
        "location": {
            "country": "US",
            "state": "CA",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194
        }
    }

@pytest.fixture(scope="function")
def test_fraud_indicators():
    """Sample fraud indicators for testing"""
    return [
        "unusual_location",
        "high_velocity",
        "suspicious_merchant",
        "card_testing_pattern"
    ]

# Test utilities
class TestDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    def create_user(**kwargs):
        """Create test user data"""
        default_data = {
            "email": "user@example.com",
            "username": "testuser",
            "full_name": "Test User",
            "password": "testpassword123",
            "is_active": True,
            "is_verified": True
        }
        default_data.update(kwargs)
        return default_data
    
    @staticmethod
    def create_transaction(**kwargs):
        """Create test transaction data"""
        default_data = {
            "amount": 100.00,
            "currency": "USD",
            "merchant_id": "merchant_123",
            "transaction_type": "purchase",
            "payment_method": "credit_card",
            "ip_address": "192.168.1.1"
        }
        default_data.update(kwargs)
        return default_data
    
    @staticmethod
    def create_fraud_case(**kwargs):
        """Create test fraud case data"""
        default_data = {
            "transaction_id": "txn_123456789",
            "risk_score": 0.75,
            "fraud_indicators": ["unusual_location", "high_velocity"],
            "status": "pending_review",
            "confidence": 0.85
        }
        default_data.update(kwargs)
        return default_data

# Test helpers
class MockExternalService:
    """Mock external service for testing"""
    
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.call_count = 0
        self.last_request = None
    
    def mock_response(self, endpoint, response):
        """Set mock response for endpoint"""
        self.responses[endpoint] = response
    
    def get_response(self, endpoint, request_data=None):
        """Get mock response for endpoint"""
        self.call_count += 1
        self.last_request = request_data
        return self.responses.get(endpoint, {"status": "success"})

# Performance testing utilities
class PerformanceTimer:
    """Timer for performance testing"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        self.end_time = time.time()
    
    @property
    def elapsed_time(self):
        """Get elapsed time in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def elapsed_ms(self):
        """Get elapsed time in milliseconds"""
        elapsed = self.elapsed_time
        return elapsed * 1000 if elapsed else None

# Security testing utilities
class SecurityTestHelper:
    """Helper for security testing"""
    
    @staticmethod
    def generate_jwt_token(payload, secret="test-secret", algorithm="HS256"):
        """Generate JWT token for testing"""
        import jwt
        return jwt.encode(payload, secret, algorithm=algorithm)
    
    @staticmethod
    def create_malicious_payload(payload_type="sql_injection"):
        """Create malicious payloads for security testing"""
        payloads = {
            "sql_injection": "'; DROP TABLE users; --",
            "xss": "<script>alert('xss')</script>",
            "command_injection": "; rm -rf /",
            "path_traversal": "../../etc/passwd",
            "ldap_injection": "*)(&(objectClass=*)",
            "xml_injection": "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"
        }
        return payloads.get(payload_type, "malicious_input")

# Load testing utilities
class LoadTestScenario:
    """Load testing scenario"""
    
    def __init__(self, name, concurrent_users=10, duration_seconds=60):
        self.name = name
        self.concurrent_users = concurrent_users
        self.duration_seconds = duration_seconds
        self.results = []
    
    async def run_scenario(self, test_function):
        """Run load test scenario"""
        import asyncio
        import time
        
        start_time = time.time()
        tasks = []
        
        # Create concurrent tasks
        for i in range(self.concurrent_users):
            task = asyncio.create_task(self._run_user_session(test_function, i))
            tasks.append(task)
        
        # Wait for completion or timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.duration_seconds
            )
        except asyncio.TimeoutError:
            # Cancel remaining tasks
            for task in tasks:
                task.cancel()
        
        end_time = time.time()
        
        return {
            "scenario": self.name,
            "duration": end_time - start_time,
            "concurrent_users": self.concurrent_users,
            "total_requests": len(self.results),
            "successful_requests": len([r for r in self.results if r.get("success")]),
            "failed_requests": len([r for r in self.results if not r.get("success")]),
            "average_response_time": sum(r.get("response_time", 0) for r in self.results) / len(self.results) if self.results else 0
        }
    
    async def _run_user_session(self, test_function, user_id):
        """Run individual user session"""
        import time
        
        session_start = time.time()
        
        while time.time() - session_start < self.duration_seconds:
            request_start = time.time()
            
            try:
                await test_function(user_id)
                success = True
                error = None
            except Exception as e:
                success = False
                error = str(e)
            
            request_end = time.time()
            
            self.results.append({
                "user_id": user_id,
                "success": success,
                "error": error,
                "response_time": request_end - request_start,
                "timestamp": request_start
            })
            
            # Small delay between requests
            await asyncio.sleep(0.1)

# Export test utilities
__all__ = [
    "test_settings",
    "TestSettings",
    "TestDataFactory",
    "MockExternalService", 
    "PerformanceTimer",
    "SecurityTestHelper",
    "LoadTestScenario"
]

# Test configuration validation
def validate_test_environment():
    """Validate test environment setup"""
    import redis
    import sqlite3
    
    errors = []
    
    # Check Redis connection
    try:
        redis_client = redis.Redis.from_url(TEST_REDIS_URL)
        redis_client.ping()
        redis_client.close()
    except Exception as e:
        errors.append(f"Redis connection failed: {e}")
    
    # Check SQLite
    try:
        conn = sqlite3.connect(":memory:")
        conn.close()
    except Exception as e:
        errors.append(f"SQLite not available: {e}")
    
    if errors:
        raise RuntimeError(f"Test environment validation failed: {'; '.join(errors)}")

# Run validation on import
try:
    validate_test_environment()
except Exception as e:
    print(f"Warning: {e}")

print("Test suite initialized successfully")

