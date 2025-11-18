"""
src/pep/proxy.py

Purpose: HTTP proxying functionality for the Policy Enforcement Point
Context: Handles the actual proxying of authenticated requests to backend services.
         Preserves headers, body, and query parameters while adding authentication
         context for backend services.

Architecture:
- Async HTTP client using httpx for high performance
- Preserves original request headers (excluding sensitive ones)
- Forwards response with appropriate status codes
- Handles streaming responses for large payloads
- Adds custom headers for backend authentication context

Usage:
    This module is used by app.py to proxy requests after authentication
"""

import logging
from typing import Dict, Optional
from urllib.parse import urljoin

from fastapi import Request
from fastapi.responses import StreamingResponse, Response
import httpx

logger = logging.getLogger(__name__)

# Headers to exclude from proxying (security reasons)
EXCLUDED_HEADERS = {
    'host',
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
}


def get_proxy_headers(request: Request) -> Dict[str, str]:
    """
    Extract and filter headers for proxying to backend
    
    Context: Some headers should not be forwarded to backend services
             (e.g., Host, Connection). This function filters those out
             and prepares headers for the backend request.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Dictionary of headers to forward to backend
    """
    headers = {}
    
    for name, value in request.headers.items():
        name_lower = name.lower()
        
        # Skip excluded headers
        if name_lower in EXCLUDED_HEADERS:
            continue
        
        headers[name] = value
    
    # Add X-Forwarded headers for backend context
    if request.client:
        headers['X-Forwarded-For'] = request.client.host
        headers['X-Forwarded-Port'] = str(request.client.port)
    
    headers['X-Forwarded-Proto'] = request.url.scheme
    headers['X-Forwarded-Host'] = request.headers.get('host', '')
    
    return headers


def add_user_context_headers(headers: Dict[str, str], user_info) -> Dict[str, str]:
    """
    Add user authentication context as headers for backend services
    
    Context: Backend services may need to know who the authenticated user is.
             These headers provide that context without exposing the JWT token.
    
    Args:
        headers: Existing headers dictionary
        user_info: UserInfo object from authentication
    
    Returns:
        Updated headers dictionary
    """
    headers['X-Auth-User'] = user_info.username
    headers['X-Auth-Subject'] = user_info.subject
    
    if user_info.email:
        headers['X-Auth-Email'] = user_info.email
    
    if user_info.roles:
        headers['X-Auth-Roles'] = ','.join(user_info.roles)
    
    return headers


async def proxy_request(
    request: Request,
    path: str,
    backend_url: str,
    client: httpx.AsyncClient
) -> Response:
    """
    Proxy an authenticated request to the backend service
    
    Flow:
    1. Extract and filter request headers
    2. Construct backend URL
    3. Read request body
    4. Make async request to backend
    5. Stream response back to client
    
    Args:
        request: FastAPI request object
        path: Request path to proxy
        backend_url: Base URL of backend service
        client: Async HTTP client instance
    
    Returns:
        FastAPI Response with backend's response
    
    Raises:
        httpx.ConnectError: If cannot connect to backend
        httpx.TimeoutException: If backend request times out
    """
    
    # Construct full backend URL
    target_url = urljoin(backend_url.rstrip('/') + '/', path.lstrip('/'))
    
    # Add query parameters
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"
    
    # Get headers to forward
    headers = get_proxy_headers(request)
    
    # Add user context (commented out for now, can be enabled if needed)
    # if hasattr(request.state, 'user'):
    #     headers = add_user_context_headers(headers, request.state.user)
    
    # Read request body
    body = await request.body()
    
    logger.debug(
        f"Proxying request: {request.method} {target_url} "
        f"(body_size={len(body)} bytes)"
    )
    
    # Make request to backend
    backend_response = await client.request(
        method=request.method,
        url=target_url,
        headers=headers,
        content=body,
    )
    
    # Prepare response headers
    response_headers = {}
    for name, value in backend_response.headers.items():
        name_lower = name.lower()
        
        # Skip certain headers that FastAPI handles
        if name_lower in {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}:
            continue
        
        response_headers[name] = value
    
    # Create response
    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
    )


async def proxy_request_streaming(
    request: Request,
    path: str,
    backend_url: str,
    client: httpx.AsyncClient
) -> StreamingResponse:
    """
    Proxy request with streaming response (for large payloads)
    
    Context: For large responses (e.g., file downloads, video streaming),
             we want to stream the response rather than buffering it all
             in memory. This function implements streaming proxy.
    
    Args:
        request: FastAPI request object
        path: Request path to proxy
        backend_url: Base URL of backend service
        client: Async HTTP client instance
    
    Returns:
        StreamingResponse with backend's streamed response
    """
    
    # Construct full backend URL
    target_url = urljoin(backend_url.rstrip('/') + '/', path.lstrip('/'))
    
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"
    
    # Get headers
    headers = get_proxy_headers(request)
    
    # Read request body
    body = await request.body()
    
    logger.debug(f"Streaming proxy: {request.method} {target_url}")
    
    # Make streaming request to backend
    async def generate():
        async with client.stream(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        ) as backend_response:
            
            # Stream chunks
            async for chunk in backend_response.aiter_bytes():
                yield chunk
    
    # Get response headers
    # Note: In streaming mode, we need to make an initial request to get headers
    backend_response = await client.request(
        method='HEAD' if request.method != 'HEAD' else request.method,
        url=target_url,
        headers=headers,
    )
    
    response_headers = {
        name: value
        for name, value in backend_response.headers.items()
        if name.lower() not in {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
    }
    
    return StreamingResponse(
        generate(),
        status_code=backend_response.status_code,
        headers=response_headers,
    )


async def health_check_backend(backend_url: str, client: httpx.AsyncClient) -> bool:
    """
    Check if backend service is healthy and reachable
    
    Context: Used by health check endpoints and startup validation
             to ensure backend services are available.
    
    Args:
        backend_url: Base URL of backend service
        client: Async HTTP client instance
    
    Returns:
        True if backend is healthy, False otherwise
    """
    try:
        # Try to reach backend health endpoint
        health_url = urljoin(backend_url, '/health')
        response = await client.get(health_url, timeout=5.0)
        
        if response.status_code == 200:
            logger.info(f"Backend service is healthy: {backend_url}")
            return True
        else:
            logger.warning(
                f"Backend health check returned status {response.status_code}"
            )
            return False
    
    except httpx.HTTPError as e:
        logger.error(f"Backend health check failed: {e}")
        return False


def get_client_ip(request: Request) -> str:
    """
    Get the real client IP address from request
    
    Context: When behind proxies/load balancers, the client IP is typically
             in X-Forwarded-For or X-Real-IP headers.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Client IP address as string
    """
    # Check X-Forwarded-For header (may have multiple IPs)
    x_forwarded_for = request.headers.get('x-forwarded-for')
    if x_forwarded_for:
        # Get the first IP in the chain (original client)
        return x_forwarded_for.split(',')[0].strip()
    
    # Check X-Real-IP header
    x_real_ip = request.headers.get('x-real-ip')
    if x_real_ip:
        return x_real_ip
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"
