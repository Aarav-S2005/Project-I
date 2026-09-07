"""Reverse proxy forwarding authorized requests to upstream target microservices."""

import logging

import httpx

logger = logging.getLogger(__name__)


async def forward_request(
    target_url: str,
    method: str,
    headers: dict[str, str],
    content: bytes | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    """Forward an authorized HTTP request to an upstream service.

    Args:
        target_url: Destination URL.
        method: HTTP method (GET, POST, etc.).
        headers: Request headers.
        content: Request payload bytes.
        timeout: Request timeout in seconds.

    Returns:
        tuple[int, dict[str, str], bytes]: Status code, response headers, and body bytes.
    """
    # Clean headers that shouldn't be forwarded directly
    cleaned_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in {"host", "content-length", "authorization"}
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method=method,
                url=target_url,
                headers=cleaned_headers,
                content=content,
                timeout=timeout,
            )
            resp_headers: dict[str, str] = {k: v for k, v in resp.headers.items()}
            return resp.status_code, resp_headers, resp.content
    except Exception as exc:
        logger.warning("Upstream request to %s failed: %s", target_url, exc)
        return (
            502,
            {"Content-Type": "application/json"},
            b'{"error": "Bad Gateway: upstream unavailable"}',
        )
