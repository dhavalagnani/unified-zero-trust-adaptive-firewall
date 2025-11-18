"""
src/pep/app.py

Purpose: Main FastAPI application for the Policy Enforcement Point (PEP)
Context: This is a Zero-Trust reverse proxy that enforces authentication and
         authorization for all requests. It validates JWT tokens from Keycloak,
         checks authorization policies, and proxies requests to backend services.
         
Architecture:
- Acts as a middleware between clients and backend services
- Validates OIDC/OAuth2 tokens from Keycloak
- Enforces fine-grained access control policies
- Logs all access attempts for security auditing
- Integrates with correlation engine for adaptive responses

Dependencies:
- FastAPI: Web framework
- httpx: Async HTTP client for proxying
- python-jose: JWT token validation
- pydantic: Configuration and data validation

Usage:
    uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
"""

import os
import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import yaml

from auth import validate_token, get_current_user, UserInfo
from proxy import proxy_request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    """Load configuration from config.yaml or environment variables"""
    config_path = os.getenv("PEP_CONFIG", "config.yaml")
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    # Fallback to environment variables
    return {
        'keycloak': {
            'url': os.getenv('KEYCLOAK_URL', 'http://localhost:8080'),
            'realm': os.getenv('KEYCLOAK_REALM', 'uztaf'),
            'client_id': os.getenv('KEYCLOAK_CLIENT_ID', 'pep-client'),
        },
        'backend': {
            'url': os.getenv('BACKEND_SERVICE_URL', 'http://localhost:8080'),
            'timeout': int(os.getenv('BACKEND_TIMEOUT', '30')),
        },
        'pep': {
            'host': os.getenv('PEP_HOST', '0.0.0.0'),
            'port': int(os.getenv('PEP_PORT', '8000')),
            'log_level': os.getenv('PEP_LOG_LEVEL', 'INFO'),
        }
    }

config = load_config()

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    logger.info("Starting PEP (Policy Enforcement Point)")
    logger.info(f"Backend service: {config['backend']['url']}")
    logger.info(f"Keycloak realm: {config['keycloak']['realm']}")
    
    # Startup: Initialize HTTP client
    app.state.http_client = httpx.AsyncClient(
        timeout=config['backend']['timeout'],
        follow_redirects=True
    )
    
    yield
    
    # Shutdown: Clean up resources
    logger.info("Shutting down PEP")
    await app.state.http_client.aclose()

# Create FastAPI application
app = FastAPI(
    title="UZTAF Policy Enforcement Point",
    description="Zero-Trust reverse proxy with authentication and authorization",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware (configure based on your needs)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint (no authentication required)
@app.get("/health")
async def health_check():
    """
    Health check endpoint for load balancers and monitoring
    Returns: Service status and version
    """
    return {
        "status": "healthy",
        "service": "pep",
        "version": "1.0.0"
    }

# Metrics endpoint (no authentication required)
@app.get("/metrics")
async def metrics():
    """
    Prometheus-compatible metrics endpoint
    Returns: Service metrics in Prometheus format
    """
    # TODO: Implement actual metrics collection
    return Response(
        content="# HELP pep_requests_total Total number of requests\n"
                "# TYPE pep_requests_total counter\n"
                "pep_requests_total 0\n",
        media_type="text/plain"
    )

# Authentication info endpoint
@app.get("/auth/userinfo")
async def get_user_info(user: UserInfo = Depends(get_current_user)):
    """
    Get current authenticated user information
    Requires: Valid JWT token
    Returns: User information from token
    """
    return {
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "authenticated": True
    }

# Main proxy endpoint - catches all other requests
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_handler(
    request: Request,
    path: str,
    user: UserInfo = Depends(get_current_user)
):
    """
    Main proxy handler that forwards authenticated requests to backend
    
    Flow:
    1. Authentication is validated by Depends(get_current_user)
    2. Log the request for audit purposes
    3. Check authorization policies (TODO: implement fine-grained policies)
    4. Proxy request to backend service
    5. Return backend response to client
    
    Args:
        request: FastAPI request object
        path: Request path to proxy
        user: Authenticated user information
    
    Returns:
        Backend service response
    """
    
    # Log access attempt
    logger.info(
        f"Access: user={user.username} method={request.method} "
        f"path=/{path} ip={request.client.host}"
    )
    
    # TODO: Implement fine-grained authorization policies
    # Example: Check if user has permission to access this resource
    # if not check_authorization(user, path, request.method):
    #     raise HTTPException(status_code=403, detail="Access denied")
    
    # Proxy the request to backend
    try:
        response = await proxy_request(
            request,
            path,
            config['backend']['url'],
            app.state.http_client
        )
        return response
    
    except httpx.ConnectError:
        logger.error(f"Cannot connect to backend service: {config['backend']['url']}")
        raise HTTPException(
            status_code=502,
            detail="Backend service unavailable"
        )
    
    except httpx.TimeoutException:
        logger.error(f"Backend request timeout for path: /{path}")
        raise HTTPException(
            status_code=504,
            detail="Backend request timeout"
        )
    
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal proxy error"
        )

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent JSON response"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path)
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "path": str(request.url.path)
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "app:app",
        host=config['pep']['host'],
        port=config['pep']['port'],
        log_level=config['pep']['log_level'].lower(),
        reload=False  # Set to True for development
    )
