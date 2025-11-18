"""
src/pep/auth.py

Purpose: Authentication and authorization module for PEP
Context: Handles JWT token validation with Keycloak, extracts user information,
         and provides dependency injection for FastAPI routes. Implements
         OAuth2/OIDC token validation using public keys from Keycloak.

Architecture:
- Validates JWT tokens issued by Keycloak
- Extracts user claims (username, email, roles) from tokens
- Provides FastAPI dependency for route protection
- Caches JWK public keys for performance
- Supports both Bearer token and cookie-based authentication

Security Features:
- Token signature verification using RS256
- Token expiration validation
- Audience and issuer validation
- Role-based access control support

Dependencies:
- python-jose: JWT handling
- cryptography: RSA key operations
- httpx: Fetch JWKS from Keycloak
"""

import os
import logging
from typing import Optional, List
from datetime import datetime, timedelta
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, jwk
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# OAuth2 scheme for extracting Bearer tokens
security = HTTPBearer()

# Configuration from environment
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'uztaf')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'pep-client')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')

# Construct Keycloak URLs
KEYCLOAK_JWKS_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"


class UserInfo(BaseModel):
    """
    User information extracted from JWT token
    
    Attributes:
        username: User's username/preferred username
        email: User's email address
        roles: List of roles assigned to user
        subject: User's unique identifier (sub claim)
        token: Original JWT token string
    """
    username: str
    email: Optional[str] = None
    roles: List[str] = []
    subject: str
    token: str


class JWKSCache:
    """
    Cache for Keycloak's public keys (JWKS)
    
    Context: Public keys are fetched from Keycloak and cached to avoid
             repeated HTTP requests. Cache expires after 1 hour.
    """
    
    def __init__(self, cache_duration: int = 3600):
        """
        Args:
            cache_duration: Cache duration in seconds (default: 1 hour)
        """
        self.cache_duration = cache_duration
        self._keys = None
        self._last_fetch = None
    
    async def get_keys(self) -> dict:
        """
        Get JWKS keys, fetching from Keycloak if cache is expired
        
        Returns:
            Dictionary of public keys indexed by key ID (kid)
        
        Raises:
            HTTPException: If unable to fetch keys from Keycloak
        """
        now = datetime.now()
        
        # Check if cache is valid
        if (self._keys is not None and 
            self._last_fetch is not None and 
            (now - self._last_fetch).seconds < self.cache_duration):
            return self._keys
        
        # Fetch new keys from Keycloak
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(KEYCLOAK_JWKS_URL, timeout=10.0)
                response.raise_for_status()
                jwks = response.json()
            
            # Index keys by kid for fast lookup
            self._keys = {key['kid']: key for key in jwks.get('keys', [])}
            self._last_fetch = now
            
            logger.info(f"Fetched {len(self._keys)} public keys from Keycloak")
            return self._keys
        
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS from Keycloak: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cannot reach authentication server"
            )


# Global JWKS cache instance
jwks_cache = JWKSCache()


async def get_public_key(token: str) -> str:
    """
    Get the public key for token verification
    
    Args:
        token: JWT token string
    
    Returns:
        Public key in PEM format
    
    Raises:
        HTTPException: If key cannot be found or fetched
    """
    try:
        # Decode header without verification to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing key ID (kid)"
            )
        
        # Get keys from cache
        keys = await jwks_cache.get_keys()
        
        if kid not in keys:
            logger.warning(f"Key ID {kid} not found in JWKS, refreshing cache")
            # Force refresh and try again
            jwks_cache._keys = None
            keys = await jwks_cache.get_keys()
            
            if kid not in keys:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token key ID"
                )
        
        # Convert JWK to PEM
        key = keys[kid]
        return jwk.construct(key).to_pem().decode('utf-8')
    
    except JWTError as e:
        logger.error(f"JWT error while extracting key: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format"
        )


async def validate_token(token: str) -> dict:
    """
    Validate JWT token and extract claims
    
    Validation steps:
    1. Fetch appropriate public key based on token's kid
    2. Verify token signature
    3. Verify token expiration
    4. Verify issuer and audience
    
    Args:
        token: JWT token string
    
    Returns:
        Dictionary of token claims
    
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        # Get public key for this token
        public_key = await get_public_key(token)
        
        # Decode and validate token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[JWT_ALGORITHM],
            issuer=KEYCLOAK_ISSUER,
            audience=KEYCLOAK_CLIENT_ID,
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iss': True,
                'verify_aud': True,
            }
        )
        
        return payload
    
    except ExpiredSignatureError:
        logger.warning("Received expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except JWTClaimsError as e:
        logger.warning(f"Token claims validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    except JWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def extract_user_info(payload: dict, token: str) -> UserInfo:
    """
    Extract user information from JWT payload
    
    Args:
        payload: Decoded JWT claims
        token: Original token string
    
    Returns:
        UserInfo object with user details
    """
    # Extract roles from token
    roles = []
    
    # Keycloak stores roles in different locations depending on configuration
    if 'realm_access' in payload:
        roles.extend(payload['realm_access'].get('roles', []))
    
    if 'resource_access' in payload and KEYCLOAK_CLIENT_ID in payload['resource_access']:
        roles.extend(payload['resource_access'][KEYCLOAK_CLIENT_ID].get('roles', []))
    
    # Build UserInfo object
    return UserInfo(
        username=payload.get('preferred_username', payload.get('sub')),
        email=payload.get('email'),
        roles=roles,
        subject=payload['sub'],
        token=token
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> UserInfo:
    """
    FastAPI dependency to get current authenticated user
    
    This function is used as a dependency in route handlers to enforce
    authentication. It extracts the Bearer token, validates it, and
    returns user information.
    
    Usage:
        @app.get("/protected")
        async def protected_route(user: UserInfo = Depends(get_current_user)):
            return {"message": f"Hello {user.username}"}
    
    Args:
        credentials: HTTP Authorization credentials (Bearer token)
    
    Returns:
        UserInfo object for authenticated user
    
    Raises:
        HTTPException: If token is missing or invalid
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Validate token and extract claims
    payload = await validate_token(token)
    
    # Extract user information
    user_info = extract_user_info(payload, token)
    
    logger.debug(f"Authenticated user: {user_info.username}")
    
    return user_info


def require_role(required_role: str):
    """
    FastAPI dependency factory for role-based access control
    
    Usage:
        @app.get("/admin")
        async def admin_route(user: UserInfo = Depends(require_role("admin"))):
            return {"message": "Admin access granted"}
    
    Args:
        required_role: Role name required for access
    
    Returns:
        Dependency function that checks for role
    """
    async def role_checker(user: UserInfo = Depends(get_current_user)) -> UserInfo:
        if required_role not in user.roles:
            logger.warning(
                f"User {user.username} attempted to access resource "
                f"requiring role {required_role}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        return user
    
    return role_checker


def require_any_role(required_roles: List[str]):
    """
    FastAPI dependency factory for checking multiple roles (OR logic)
    
    User must have at least one of the specified roles
    
    Args:
        required_roles: List of acceptable role names
    
    Returns:
        Dependency function that checks for any role
    """
    async def role_checker(user: UserInfo = Depends(get_current_user)) -> UserInfo:
        if not any(role in user.roles for role in required_roles):
            logger.warning(
                f"User {user.username} attempted to access resource "
                f"requiring one of roles: {required_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        return user
    
    return role_checker
