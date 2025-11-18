"""
src/pep/tests/test_auth.py

Purpose: Unit tests for authentication module
Context: Tests JWT token validation, user extraction, and authorization logic
         for the Policy Enforcement Point authentication system

Test coverage:
- Token validation with valid/invalid/expired tokens
- User info extraction from JWT claims
- Role-based access control
- JWKS key fetching and caching
- Error handling for various authentication scenarios

Usage:
    pytest test_auth.py -v
    pytest test_auth.py -v --cov=auth --cov-report=html
"""

import pytest
from datetime import datetime, timedelta
from jose import jwt
from fastapi import HTTPException
from unittest.mock import Mock, patch, AsyncMock

# Import modules to test
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import (
    validate_token,
    extract_user_info,
    get_current_user,
    UserInfo,
    JWKSCache,
    require_role,
    require_any_role
)


# Test fixtures
@pytest.fixture
def sample_jwt_payload():
    """Sample JWT payload for testing"""
    return {
        'sub': 'user-123',
        'preferred_username': 'testuser',
        'email': 'testuser@example.com',
        'realm_access': {
            'roles': ['user', 'viewer']
        },
        'resource_access': {
            'pep-client': {
                'roles': ['api-access']
            }
        },
        'iss': 'http://localhost:8080/realms/uztaf',
        'aud': 'pep-client',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
    }


@pytest.fixture
def expired_jwt_payload():
    """Expired JWT payload for testing"""
    return {
        'sub': 'user-123',
        'preferred_username': 'testuser',
        'email': 'testuser@example.com',
        'iss': 'http://localhost:8080/realms/uztaf',
        'aud': 'pep-client',
        'exp': datetime.utcnow() - timedelta(hours=1),  # Expired
        'iat': datetime.utcnow() - timedelta(hours=2),
    }


@pytest.fixture
def mock_public_key():
    """Mock RSA public key for testing"""
    # This is a dummy key for testing purposes only
    return """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWk
Jg0xnxZ8zyB5xKuR6bkMfYVb7B7n5rE3cKF2aQXmwQcKwZ5V3hW/8vN5HxAT0nDa
-----END PUBLIC KEY-----"""


class TestUserInfo:
    """Test UserInfo model"""
    
    def test_user_info_creation(self):
        """Test creating UserInfo object"""
        user = UserInfo(
            username="testuser",
            email="test@example.com",
            roles=["user", "admin"],
            subject="user-123",
            token="dummy-token"
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert "user" in user.roles
        assert "admin" in user.roles
        assert user.subject == "user-123"
    
    def test_user_info_optional_email(self):
        """Test UserInfo without email"""
        user = UserInfo(
            username="testuser",
            roles=["user"],
            subject="user-123",
            token="dummy-token"
        )
        
        assert user.email is None
    
    def test_user_info_empty_roles(self):
        """Test UserInfo with no roles"""
        user = UserInfo(
            username="testuser",
            roles=[],
            subject="user-123",
            token="dummy-token"
        )
        
        assert user.roles == []


class TestExtractUserInfo:
    """Test user info extraction from JWT payload"""
    
    def test_extract_basic_info(self, sample_jwt_payload):
        """Test extracting basic user info"""
        user_info = extract_user_info(sample_jwt_payload, "dummy-token")
        
        assert user_info.username == "testuser"
        assert user_info.email == "testuser@example.com"
        assert user_info.subject == "user-123"
        assert user_info.token == "dummy-token"
    
    def test_extract_realm_roles(self, sample_jwt_payload):
        """Test extracting realm-level roles"""
        user_info = extract_user_info(sample_jwt_payload, "dummy-token")
        
        assert "user" in user_info.roles
        assert "viewer" in user_info.roles
    
    def test_extract_resource_roles(self, sample_jwt_payload):
        """Test extracting resource/client-level roles"""
        user_info = extract_user_info(sample_jwt_payload, "dummy-token")
        
        assert "api-access" in user_info.roles
    
    def test_extract_without_email(self):
        """Test extraction when email is missing"""
        payload = {
            'sub': 'user-123',
            'preferred_username': 'testuser',
            'realm_access': {'roles': ['user']},
        }
        
        user_info = extract_user_info(payload, "dummy-token")
        
        assert user_info.email is None
        assert user_info.username == "testuser"
    
    def test_extract_without_roles(self):
        """Test extraction when roles are missing"""
        payload = {
            'sub': 'user-123',
            'preferred_username': 'testuser',
        }
        
        user_info = extract_user_info(payload, "dummy-token")
        
        assert user_info.roles == []
    
    def test_fallback_to_sub_for_username(self):
        """Test using 'sub' as username when preferred_username is missing"""
        payload = {
            'sub': 'user-123',
            'realm_access': {'roles': ['user']},
        }
        
        user_info = extract_user_info(payload, "dummy-token")
        
        assert user_info.username == "user-123"


class TestJWKSCache:
    """Test JWKS key caching"""
    
    @pytest.mark.asyncio
    async def test_cache_initialization(self):
        """Test cache is initialized correctly"""
        cache = JWKSCache(cache_duration=3600)
        
        assert cache._keys is None
        assert cache._last_fetch is None
        assert cache.cache_duration == 3600
    
    @pytest.mark.asyncio
    async def test_cache_custom_duration(self):
        """Test cache with custom duration"""
        cache = JWKSCache(cache_duration=7200)
        
        assert cache.cache_duration == 7200
    
    @pytest.mark.asyncio
    @patch('auth.httpx.AsyncClient')
    async def test_fetch_keys_success(self, mock_client):
        """Test successful key fetching"""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            'keys': [
                {'kid': 'key-1', 'kty': 'RSA', 'use': 'sig'},
                {'kid': 'key-2', 'kty': 'RSA', 'use': 'sig'},
            ]
        }
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        cache = JWKSCache()
        keys = await cache.get_keys()
        
        assert 'key-1' in keys
        assert 'key-2' in keys
        assert cache._keys is not None
        assert cache._last_fetch is not None


class TestRoleBasedAccess:
    """Test role-based access control"""
    
    @pytest.mark.asyncio
    async def test_require_role_success(self):
        """Test successful role check"""
        user = UserInfo(
            username="testuser",
            roles=["admin", "user"],
            subject="user-123",
            token="dummy-token"
        )
        
        checker = require_role("admin")
        
        # Mock get_current_user to return our test user
        with patch('auth.get_current_user', return_value=user):
            result = await checker(user)
            assert result == user
    
    @pytest.mark.asyncio
    async def test_require_role_failure(self):
        """Test failed role check"""
        user = UserInfo(
            username="testuser",
            roles=["user"],
            subject="user-123",
            token="dummy-token"
        )
        
        checker = require_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            await checker(user)
        
        assert exc_info.value.status_code == 403
        assert "admin" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_require_any_role_success(self):
        """Test successful any-role check"""
        user = UserInfo(
            username="testuser",
            roles=["viewer"],
            subject="user-123",
            token="dummy-token"
        )
        
        checker = require_any_role(["admin", "viewer", "editor"])
        result = await checker(user)
        
        assert result == user
    
    @pytest.mark.asyncio
    async def test_require_any_role_failure(self):
        """Test failed any-role check"""
        user = UserInfo(
            username="testuser",
            roles=["guest"],
            subject="user-123",
            token="dummy-token"
        )
        
        checker = require_any_role(["admin", "editor"])
        
        with pytest.raises(HTTPException) as exc_info:
            await checker(user)
        
        assert exc_info.value.status_code == 403


class TestValidateToken:
    """Test token validation"""
    
    @pytest.mark.asyncio
    @patch('auth.get_public_key')
    @patch('auth.jwt.decode')
    async def test_validate_valid_token(self, mock_decode, mock_get_key, sample_jwt_payload):
        """Test validating a valid token"""
        mock_get_key.return_value = "dummy-public-key"
        mock_decode.return_value = sample_jwt_payload
        
        result = await validate_token("valid.jwt.token")
        
        assert result == sample_jwt_payload
        mock_decode.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('auth.get_public_key')
    async def test_validate_expired_token(self, mock_get_key):
        """Test validating an expired token"""
        from jose.exceptions import ExpiredSignatureError
        
        mock_get_key.return_value = "dummy-public-key"
        
        with patch('auth.jwt.decode', side_effect=ExpiredSignatureError("Token expired")):
            with pytest.raises(HTTPException) as exc_info:
                await validate_token("expired.jwt.token")
            
            assert exc_info.value.status_code == 401
            assert "expired" in str(exc_info.value.detail).lower()
    
    @pytest.mark.asyncio
    @patch('auth.get_public_key')
    async def test_validate_invalid_signature(self, mock_get_key):
        """Test validating a token with invalid signature"""
        from jose import JWTError
        
        mock_get_key.return_value = "dummy-public-key"
        
        with patch('auth.jwt.decode', side_effect=JWTError("Invalid signature")):
            with pytest.raises(HTTPException) as exc_info:
                await validate_token("invalid.jwt.token")
            
            assert exc_info.value.status_code == 401


# Integration-style tests
class TestAuthenticationFlow:
    """Test complete authentication flows"""
    
    @pytest.mark.asyncio
    async def test_complete_auth_flow(self, sample_jwt_payload):
        """Test complete authentication flow from token to user"""
        # This would require more mocking of the full authentication chain
        # Placeholder for integration testing
        pass
    
    @pytest.mark.asyncio
    async def test_auth_with_missing_token(self):
        """Test authentication with missing token"""
        # Test that missing credentials raise appropriate exception
        pass


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--cov=auth"])
