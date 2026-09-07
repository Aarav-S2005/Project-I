"""Token authentication and request context extraction for the Zero-Trust Gateway."""

import time
from typing import Any

import jwt
from fastapi import HTTPException, Request, status

from app.common.schemas import RequestContext, Resource, Subject

DEFAULT_JWT_SECRET = "zero-trust-gateway-secret-key-change-in-prod"
JWT_ALGORITHM = "HS256"


def create_access_token(
    subject: str,
    session_id: str,
    expires_in_seconds: int = 86400,
    secret: str = DEFAULT_JWT_SECRET,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Generate a signed JWT token containing subject and session identifiers.

    Args:
        subject: Subject identifier (e.g. 'user:alice').
        session_id: Session identifier (e.g. 'sess_123').
        expires_in_seconds: Token validity duration.
        secret: Signing secret.
        extra_claims: Optional custom claims.

    Returns:
        str: Encoded JWT string.
    """
    now = time.time()
    payload: dict[str, Any] = {
        "sub": subject,
        "session_id": session_id,
        "iat": int(now),
        "exp": int(now + expires_in_seconds),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(
    token: str,
    secret: str = DEFAULT_JWT_SECRET,
) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: Bearer JWT token string.
        secret: Signing secret.

    Returns:
        dict[str, Any]: Decoded payload.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err
    except jwt.InvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err


def extract_request_context(
    request: Request,
    resource: Resource | str,
    permission: str = "view",
    secret: str = DEFAULT_JWT_SECRET,
) -> RequestContext:
    """Extract authenticated context and client metadata from an incoming HTTP request.

    Args:
        request: FastAPI Request instance.
        resource: Target Resource being accessed.
        permission: Permission requested on the resource.
        secret: JWT verification secret.

    Returns:
        RequestContext: Structured request context.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = auth_header.removeprefix("Bearer ").strip()
    payload = decode_access_token(raw_token, secret=secret)

    subject_raw = str(payload.get("sub", "user:anonymous"))
    session_id = str(payload.get("session_id", "sess_default"))
    subject = Subject.from_string(subject_raw)

    target_res = Resource.from_string(resource) if isinstance(resource, str) else resource

    # Extract client metadata
    client_host = request.headers.get("X-Forwarded-For")
    if client_host:
        client_ip = client_host.split(",")[0].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    # Geo coordinates if provided in headers (e.g. from edge CDN / mobile app)
    lat_header = request.headers.get("X-Client-Latitude")
    lon_header = request.headers.get("X-Client-Longitude")
    latitude = float(lat_header) if lat_header else None
    longitude = float(lon_header) if lon_header else None

    user_agent = request.headers.get("User-Agent", "Unknown")
    device_id = request.headers.get("X-Device-Id")

    return RequestContext(
        session_id=session_id,
        subject=subject,
        resource=target_res,
        permission=permission,
        ip_address=client_ip,
        latitude=latitude,
        longitude=longitude,
        timestamp=time.time(),
        user_agent=user_agent,
        device_id=device_id,
    )
