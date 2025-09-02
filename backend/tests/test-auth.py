"""
Authentication Tests for Fraud Detection System

This module contains comprehensive tests for the authentication system including
login, logout, token management, password security, rate limiting, and security features.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import jwt
from fastapi.testclient import TestClient
from fastapi import status
import bcrypt

# Local imports
from app.core.security import SecurityManager, create_access_token, verify_token
from app.core.rate_limiter import RateLimitError
from app.services.auth_service import AuthService
from app.models.user import User
from app.api.endpoints.auth import router
from tests import TestDataFactory, SecurityTestHelper, PerformanceTimer


class TestAuthenticationEndpoints:
    """Test authentication API endpoints"""
    
    @pytest.fixture
    def client(self, test_app):
        """Create test client"""
        return TestClient(test_app)
    
    @pytest.fixture
    def auth_service(self, test_db):
        """Create auth service instance"""
        return AuthService(test_db)
    
    @pytest.fixture
    def valid_user_data(self):
        """Valid user registration data"""
        return TestDataFactory.create_user(
            email="test@example.com",
            username="testuser",
            password="SecurePassword123!",
            full_name="Test User"
        )
    
    @pytest.fixture
    def existing_user(self, test_db, valid_user_data):
        """Create existing user in database"""
        user = User(**valid_user_data)
        user.password_hash = bcrypt.hashpw(
            valid_user_data["password"].encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')
        test_db.add(user)
        test_db.commit()
        test_db.refresh(user)
        return user

    def test_user_registration_success(self, client, valid_user_data):
        """Test successful user registration"""
        response = client.post("/auth/register", json=valid_user_data)
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        
        assert "user" in data
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == valid_user_data["email"]
        assert data["user"]["username"] == valid_user_data["username"]
        assert "password" not in data["user"]
    
    def test_user_registration_duplicate_email(self, client, existing_user, valid_user_data):
        """Test registration with duplicate email"""
        response = client.post("/auth/register", json=valid_user_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "email already registered" in data["detail"].lower()
    
    def test_user_registration_invalid_email(self, client, valid_user_data):
        """Test registration with invalid email"""
        valid_user_data["email"] = "invalid-email"
        response = client.post("/auth/register", json=valid_user_data)
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_user_registration_weak_password(self, client, valid_user_data):
        """Test registration with weak password"""
        valid_user_data["password"] = "123"
        response = client.post("/auth/register", json=valid_user_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "password" in data["detail"].lower()
    
    def test_user_login_success(self, client, existing_user):
        """Test successful user login"""
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert data["token_type"] == "bearer"
        
        # Verify token is valid
        token_payload = jwt.decode(
            data["access_token"], 
            options={"verify_signature": False}
        )
        assert token_payload["sub"] == str(existing_user.id)
    
    def test_user_login_invalid_credentials(self, client, existing_user):
        """Test login with invalid credentials"""
        login_data = {
            "username": existing_user.email,
            "password": "WrongPassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert "incorrect" in data["detail"].lower()
    
    def test_user_login_nonexistent_user(self, client):
        """Test login with nonexistent user"""
        login_data = {
            "username": "nonexistent@example.com",
            "password": "SomePassword123!"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_user_login_inactive_user(self, client, existing_user, test_db):
        """Test login with inactive user"""
        existing_user.is_active = False
        test_db.commit()
        
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert "inactive" in data["detail"].lower()
    
    def test_token_refresh_success(self, client, existing_user):
        """Test successful token refresh"""
        # First login to get refresh token
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        login_data = login_response.json()
        refresh_token = login_data["refresh_token"]
        
        # Use refresh token to get new access token
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == status.HTTP_200_OK
        refresh_data = refresh_response.json()
        
        assert "access_token" in refresh_data
        assert "expires_in" in refresh_data
        assert refresh_data["access_token"] != login_data["access_token"]
    
    def test_token_refresh_invalid_token(self, client):
        """Test token refresh with invalid token"""
        response = client.post(
            "/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_user_logout_success(self, client, existing_user):
        """Test successful user logout"""
        # Login first
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Logout
        headers = {"Authorization": f"Bearer {access_token}"}
        logout_response = client.post("/auth/logout", headers=headers)
        
        assert logout_response.status_code == status.HTTP_200_OK
        data = logout_response.json()
        assert data["message"] == "Successfully logged out"
    
    def test_logout_without_token(self, client):
        """Test logout without authentication token"""
        response = client.post("/auth/logout")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_get_current_user_success(self, client, existing_user):
        """Test getting current user info"""
        # Login first
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Get current user
        headers = {"Authorization": f"Bearer {access_token}"}
        response = client.get("/auth/me", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["id"] == existing_user.id
        assert data["email"] == existing_user.email
        assert data["username"] == existing_user.username
        assert "password" not in data
    
    def test_change_password_success(self, client, existing_user):
        """Test successful password change"""
        # Login first
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Change password
        headers = {"Authorization": f"Bearer {access_token}"}
        password_data = {
            "current_password": "SecurePassword123!",
            "new_password": "NewSecurePassword456!",
            "confirm_password": "NewSecurePassword456!"
        }
        
        response = client.put("/auth/change-password", json=password_data, headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Password changed successfully"
        
        # Verify old password no longer works
        old_login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        old_response = client.post("/auth/login", data=old_login_data)
        assert old_response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Verify new password works
        new_login_data = {
            "username": existing_user.email,
            "password": "NewSecurePassword456!"
        }
        new_response = client.post("/auth/login", data=new_login_data)
        assert new_response.status_code == status.HTTP_200_OK
    
    def test_change_password_wrong_current(self, client, existing_user):
        """Test password change with wrong current password"""
        # Login first
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Try to change password with wrong current password
        headers = {"Authorization": f"Bearer {access_token}"}
        password_data = {
            "current_password": "WrongPassword",
            "new_password": "NewSecurePassword456!",
            "confirm_password": "NewSecurePassword456!"
        }
        
        response = client.put("/auth/change-password", json=password_data, headers=headers)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "current password" in data["detail"].lower()
    
    def test_change_password_mismatch(self, client, existing_user):
        """Test password change with mismatched new passwords"""
        # Login first
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Try to change password with mismatched passwords
        headers = {"Authorization": f"Bearer {access_token}"}
        password_data = {
            "current_password": "SecurePassword123!",
            "new_password": "NewSecurePassword456!",
            "confirm_password": "DifferentPassword789!"
        }
        
        response = client.put("/auth/change-password", json=password_data, headers=headers)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "passwords do not match" in data["detail"].lower()


class TestAuthenticationSecurity:
    """Test authentication security features"""
    
    def test_password_hashing(self):
        """Test password hashing security"""
        password = "TestPassword123!"
        
        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Verify password
        assert bcrypt.checkpw(password.encode('utf-8'), hashed)
        
        # Verify wrong password fails
        assert not bcrypt.checkpw("WrongPassword".encode('utf-8'), hashed)
        
        # Verify hash is different each time
        hashed2 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        assert hashed != hashed2
    
    def test_jwt_token_creation_and_verification(self):
        """Test JWT token creation and verification"""
        user_id = 123
        token = create_access_token({"sub": str(user_id)})
        
        # Verify token
        payload = verify_token(token)
        assert payload["sub"] == str(user_id)
        assert "exp" in payload
        assert "iat" in payload
    
    def test_jwt_token_expiration(self):
        """Test JWT token expiration"""
        # Create token with short expiration
        token = create_access_token(
            {"sub": "123"}, 
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        # Verify expired token fails
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(token)
    
    def test_jwt_token_invalid_signature(self):
        """Test JWT token with invalid signature"""
        token = create_access_token({"sub": "123"})
        
        # Tamper with token
        tampered_token = token[:-10] + "tampered123"
        
        # Verify tampered token fails
        with pytest.raises(jwt.InvalidSignatureError):
            verify_token(tampered_token)
    
    def test_sql_injection_protection(self, client):
        """Test SQL injection protection in login"""
        malicious_payloads = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "admin'/**/OR/**/1=1#"
        ]
        
        for payload in malicious_payloads:
            login_data = {
                "username": payload,
                "password": "password"
            }
            
            response = client.post("/auth/login", data=login_data)
            
            # Should return 401 (not 500 or other error indicating SQL injection)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_xss_protection(self, client, valid_user_data):
        """Test XSS protection in registration"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            user_data = valid_user_data.copy()
            user_data["full_name"] = payload
            
            response = client.post("/auth/register", json=user_data)
            
            # Should either reject or sanitize the input
            if response.status_code == status.HTTP_201_CREATED:
                data = response.json()
                # Verify XSS payload is not returned as-is
                assert payload not in str(data)
    
    def test_brute_force_protection(self, client, existing_user):
        """Test brute force protection"""
        login_data = {
            "username": existing_user.email,
            "password": "WrongPassword"
        }
        
        # Make multiple failed login attempts
        for i in range(6):  # Assuming rate limit is 5 attempts
            response = client.post("/auth/login", data=login_data)
            
            if i < 5:
                assert response.status_code == status.HTTP_401_UNAUTHORIZED
            else:
                # Should be rate limited after 5 attempts
                assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    def test_session_fixation_protection(self, client, existing_user):
        """Test session fixation protection"""
        # Login and get token
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        response1 = client.post("/auth/login", data=login_data)
        token1 = response1.json()["access_token"]
        
        # Login again and get new token
        response2 = client.post("/auth/login", data=login_data)
        token2 = response2.json()["access_token"]
        
        # Tokens should be different (new session each time)
        assert token1 != token2
    
    def test_concurrent_session_handling(self, client, existing_user):
        """Test concurrent session handling"""
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        # Create multiple sessions
        tokens = []
        for i in range(3):
            response = client.post("/auth/login", data=login_data)
            assert response.status_code == status.HTTP_200_OK
            tokens.append(response.json()["access_token"])
        
        # All tokens should be valid initially
        for token in tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/auth/me", headers=headers)
            assert response.status_code == status.HTTP_200_OK


class TestAuthenticationPerformance:
    """Test authentication performance"""
    
    def test_login_performance(self, client, existing_user):
        """Test login endpoint performance"""
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        with PerformanceTimer() as timer:
            response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == status.HTTP_200_OK
        assert timer.elapsed_ms < 1000  # Should complete within 1 second
    
    def test_token_verification_performance(self, existing_user):
        """Test token verification performance"""
        token = create_access_token({"sub": str(existing_user.id)})
        
        # Test multiple verifications
        times = []
        for i in range(100):
            with PerformanceTimer() as timer:
                payload = verify_token(token)
            times.append(timer.elapsed_ms)
            assert payload["sub"] == str(existing_user.id)
        
        # Average verification should be very fast
        avg_time = sum(times) / len(times)
        assert avg_time < 10  # Should be under 10ms on average
    
    def test_password_hashing_performance(self):
        """Test password hashing performance"""
        password = "TestPassword123!"
        
        with PerformanceTimer() as timer:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Hashing should complete within reasonable time
        assert timer.elapsed_ms < 500  # Should be under 500ms
        
        # Verification should be fast
        with PerformanceTimer() as timer:
            result = bcrypt.checkpw(password.encode('utf-8'), hashed)
        
        assert result is True
        assert timer.elapsed_ms < 100  # Should be under 100ms


class TestAuthService:
    """Test AuthService business logic"""
    
    @pytest.fixture
    def auth_service(self, test_db):
        return AuthService(test_db)
    
    def test_create_user_success(self, auth_service, valid_user_data):
        """Test successful user creation"""
        user = auth_service.create_user(valid_user_data)
        
        assert user.id is not None
        assert user.email == valid_user_data["email"]
        assert user.username == valid_user_data["username"]
        assert user.is_active is True
        assert user.password_hash is not None
        assert user.password_hash != valid_user_data["password"]
    
    def test_authenticate_user_success(self, auth_service, existing_user):
        """Test successful user authentication"""
        user = auth_service.authenticate_user(
            existing_user.email, 
            "SecurePassword123!"
        )
        
        assert user is not None
        assert user.id == existing_user.id
        assert user.email == existing_user.email
    
    def test_authenticate_user_wrong_password(self, auth_service, existing_user):
        """Test authentication with wrong password"""
        user = auth_service.authenticate_user(
            existing_user.email, 
            "WrongPassword"
        )
        
        assert user is None
    
    def test_authenticate_nonexistent_user(self, auth_service):
        """Test authentication of nonexistent user"""
        user = auth_service.authenticate_user(
            "nonexistent@example.com", 
            "SomePassword"
        )
        
        assert user is None
    
    def test_get_user_by_email(self, auth_service, existing_user):
        """Test getting user by email"""
        user = auth_service.get_user_by_email(existing_user.email)
        
        assert user is not None
        assert user.id == existing_user.id
        assert user.email == existing_user.email
    
    def test_get_user_by_username(self, auth_service, existing_user):
        """Test getting user by username"""
        user = auth_service.get_user_by_username(existing_user.username)
        
        assert user is not None
        assert user.id == existing_user.id
        assert user.username == existing_user.username
    
    def test_update_password(self, auth_service, existing_user):
        """Test password update"""
        new_password = "NewSecurePassword456!"
        
        success = auth_service.update_password(
            existing_user.id, 
            "SecurePassword123!", 
            new_password
        )
        
        assert success is True
        
        # Verify old password no longer works
        user = auth_service.authenticate_user(existing_user.email, "SecurePassword123!")
        assert user is None
        
        # Verify new password works
        user = auth_service.authenticate_user(existing_user.email, new_password)
        assert user is not None
    
    def test_update_password_wrong_current(self, auth_service, existing_user):
        """Test password update with wrong current password"""
        success = auth_service.update_password(
            existing_user.id, 
            "WrongCurrentPassword", 
            "NewSecurePassword456!"
        )
        
        assert success is False
    
    @patch('app.core.logger.fraud_logger.log_security_event')
    def test_security_event_logging(self, mock_log, auth_service, existing_user):
        """Test that security events are logged"""
        # Successful authentication should log event
        auth_service.authenticate_user(existing_user.email, "SecurePassword123!")
        
        # Verify security event was logged
        mock_log.assert_called()
        
        # Failed authentication should also log event
        auth_service.authenticate_user(existing_user.email, "WrongPassword")
        
        # Should have been called twice now
        assert mock_log.call_count >= 2


class TestAuthenticationIntegration:
    """Integration tests for authentication system"""
    
    def test_full_user_lifecycle(self, client):
        """Test complete user lifecycle: register -> login -> use token -> logout"""
        # 1. Register user
        user_data = TestDataFactory.create_user()
        register_response = client.post("/auth/register", json=user_data)
        assert register_response.status_code == status.HTTP_201_CREATED
        
        register_data = register_response.json()
        user_id = register_data["user"]["id"]
        
        # 2. Login
        login_data = {
            "username": user_data["email"],
            "password": user_data["password"]
        }
        login_response = client.post("/auth/login", data=login_data)
        assert login_response.status_code == status.HTTP_200_OK
        
        login_result = login_response.json()
        access_token = login_result["access_token"]
        
        # 3. Use token to access protected endpoint
        headers = {"Authorization": f"Bearer {access_token}"}
        me_response = client.get("/auth/me", headers=headers)
        assert me_response.status_code == status.HTTP_200_OK
        
        me_data = me_response.json()
        assert me_data["id"] == user_id
        
        # 4. Logout
        logout_response = client.post("/auth/logout", headers=headers)
        assert logout_response.status_code == status.HTTP_200_OK
    
    def test_token_blacklisting_after_logout(self, client, existing_user):
        """Test that tokens are invalidated after logout"""
        # Login
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        login_response = client.post("/auth/login", data=login_data)
        token_data = login_response.json()
        access_token = token_data["access_token"]
        
        # Use token (should work)
        headers = {"Authorization": f"Bearer {access_token}"}
        response1 = client.get("/auth/me", headers=headers)
        assert response1.status_code == status.HTTP_200_OK
        
        # Logout
        logout_response = client.post("/auth/logout", headers=headers)
        assert logout_response.status_code == status.HTTP_200_OK
        
        # Try to use token after logout (should fail)
        response2 = client.get("/auth/me", headers=headers)
        assert response2.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_concurrent_authentication(self, client, existing_user):
        """Test concurrent authentication requests"""
        login_data = {
            "username": existing_user.email,
            "password": "SecurePassword123!"
        }
        
        # Make concurrent login requests
        tasks = []
        for i in range(10):
            task = asyncio.create_task(
                asyncio.to_thread(client.post, "/auth/login", data=login_data)
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == status.HTTP_200_OK
            assert "access_token" in response.json()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])