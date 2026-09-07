"""FastAPI entrypoint for the Zero-Trust API Gateway service."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.audit.api import router as audit_router
from app.common.schemas import DecisionAction, Resource
from app.gateway.auth import create_access_token, extract_request_context
from app.gateway.interceptor import ZeroTrustInterceptor

# Global interceptor instance
_interceptor: ZeroTrustInterceptor | None = None


def get_interceptor() -> ZeroTrustInterceptor:
    """Dependency provider for ZeroTrustInterceptor."""
    global _interceptor
    if _interceptor is None:
        _interceptor = ZeroTrustInterceptor()
    return _interceptor


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize gateway pipeline on startup."""
    get_interceptor()
    yield


app = FastAPI(
    title="Zero-Trust API Gateway",
    description="Zero-Trust API Gateway with Graph-Aware Trust & Closed-Loop Policy Feedback",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount audit API router
app.include_router(audit_router)


class TokenRequest(BaseModel):
    """Payload for issuing a test JWT access token."""

    subject: str = Field("user:alice", description="Subject string, e.g. user:alice")
    session_id: str = Field("sess_demo_1", description="Session identifier")
    expires_in_seconds: int = Field(86400, description="Token TTL in seconds")


class TokenResponse(BaseModel):
    """Response containing signed JWT token."""

    access_token: str
    token_type: str = "Bearer"
    subject: str
    session_id: str


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Gateway health probe."""
    return {"status": "ok", "service": "zero_trust_gateway"}


@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
async def issue_token(request: TokenRequest) -> TokenResponse:
    """Issue a JWT Bearer token for client authentication."""
    token = create_access_token(
        subject=request.subject,
        session_id=request.session_id,
        expires_in_seconds=request.expires_in_seconds,
    )
    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        subject=request.subject,
        session_id=request.session_id,
    )


@app.api_route(
    "/api/v1/{resource_type}/{resource_id}",
    methods=["GET", "POST", "PUT", "DELETE"],
    tags=["Gateway Proxy"],
)
async def access_resource(
    resource_type: str,
    resource_id: str,
    request: Request,
    permission: str = Query("view", description="Permission to verify (e.g. view, edit)"),
    interceptor: Annotated[ZeroTrustInterceptor, Depends(get_interceptor)] = None,  # type: ignore[assignment]
) -> JSONResponse:
    """Protected resource endpoint with continuous zero-trust authorization evaluation."""
    target_resource = Resource(type=resource_type, id=resource_id)

    # 1. Extract authenticated request context
    context = extract_request_context(
        request=request,
        resource=target_resource,
        permission=permission,
    )

    # 2. Execute zero-trust interceptor pipeline
    audit_record = interceptor.evaluate_request(context)
    decision = audit_record.decision

    base_headers = {
        "X-Trust-Score": str(decision.trust_score.score),
        "X-Audit-Record-Id": audit_record.record_id,
        "X-Decision-Action": decision.action,
    }

    # 3. Handle decision bands
    if decision.action == DecisionAction.ALLOW:
        return JSONResponse(
            status_code=200,
            content={
                "status": "allowed",
                "message": "Access granted",
                "resource": f"{resource_type}:{resource_id}",
                "permission": permission,
                "trust_score": decision.trust_score.score,
                "audit_record_id": audit_record.record_id,
            },
            headers=base_headers,
        )

    if decision.action == DecisionAction.STEP_UP:
        headers = {
            **base_headers,
            "WWW-Authenticate": 'Step-Up realm="ZeroTrustGateway"',
        }
        return JSONResponse(
            status_code=401,
            content={
                "status": "step_up_required",
                "detail": decision.reason,
                "challenge": "MFA_REQUIRED",
                "trust_score": decision.trust_score.score,
                "audit_record_id": audit_record.record_id,
            },
            headers=headers,
        )

    if decision.action == DecisionAction.NARROW:
        headers = {
            **base_headers,
            "X-Narrow-Applied": "true",
        }
        return JSONResponse(
            status_code=403,
            content={
                "status": "narrowed",
                "detail": decision.reason,
                "narrow_applied": True,
                "trust_score": decision.trust_score.score,
                "audit_record_id": audit_record.record_id,
                "top_anomaly_drivers": audit_record.top_anomaly_drivers,
            },
            headers=headers,
        )

    # DENY band
    return JSONResponse(
        status_code=403,
        content={
            "status": "denied",
            "detail": decision.reason,
            "trust_score": decision.trust_score.score,
            "audit_record_id": audit_record.record_id,
            "top_anomaly_drivers": audit_record.top_anomaly_drivers,
        },
        headers=base_headers,
    )
