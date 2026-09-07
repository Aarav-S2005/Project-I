"""Unit tests for token authentication and request context extraction."""

import time

import pytest
from fastapi import HTTPException, Request

from app.common.schemas import Resource
from app.gateway.auth import create_access_token, decode_access_token, extract_request_context


class TestAuthAndContext:
    """Test JWT token management and request header extraction."""

    def test_create_and_decode_token(self) -> None:
        token = create_access_token(
            subject="user:alice",
            session_id="sess_123",
            expires_in_seconds=3600,
        )

        payload = decode_access_token(token)
        assert payload["sub"] == "user:alice"
        assert payload["session_id"] == "sess_123"
        assert payload["exp"] > time.time()

    def test_expired_token(self) -> None:
        # Expired token in past
        token = create_access_token(
            subject="user:alice",
            session_id="sess_123",
            expires_in_seconds=-10,
        )

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_invalid_token(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token("invalid.jwt.token")
        assert exc_info.value.status_code == 401

    def test_extract_request_context_valid(self) -> None:
        token = create_access_token(subject="user:bob", session_id="sess_bob_1")
        scope = {
            "type": "http",
            "headers": [
                (b"authorization", f"Bearer {token}".encode()),
                (b"user-agent", b"PytestClient/1.0"),
                (b"x-forwarded-for", b"203.0.113.195"),
                (b"x-client-latitude", b"37.7749"),
                (b"x-client-longitude", b"-122.4194"),
                (b"x-device-id", b"device_mac_1"),
            ],
            "client": ("127.0.0.1", 8000),
        }
        req = Request(scope)

        context = extract_request_context(
            request=req,
            resource=Resource(type="document", id="doc50"),
            permission="view",
        )

        assert context.subject.type == "user"
        assert context.subject.id == "bob"
        assert context.session_id == "sess_bob_1"
        assert context.resource.type == "document"
        assert context.resource.id == "doc50"
        assert context.permission == "view"
        assert context.ip_address == "203.0.113.195"
        assert context.latitude == 37.7749
        assert context.longitude == -122.4194
        assert context.device_id == "device_mac_1"

    def test_extract_request_context_missing_auth(self) -> None:
        scope = {
            "type": "http",
            "headers": [],
            "client": ("127.0.0.1", 8000),
        }
        req = Request(scope)

        with pytest.raises(HTTPException) as exc_info:
            extract_request_context(
                request=req,
                resource="document:doc1",
            )
        assert exc_info.value.status_code == 401
