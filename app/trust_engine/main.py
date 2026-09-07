"""FastAPI application entrypoint for the standalone Trust Engine microservice."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.common.schemas import FeatureVector, RequestContext, TrustScore
from app.trust_engine.service import TrustScoringService

# Global service instance
_scoring_service: TrustScoringService | None = None


def get_trust_scoring_service() -> TrustScoringService:
    """Dependency provider for TrustScoringService."""
    global _scoring_service
    if _scoring_service is None:
        _scoring_service = TrustScoringService()
    return _scoring_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize resources on startup."""
    get_trust_scoring_service()
    yield


app = FastAPI(
    title="Zero-Trust Scoring Service",
    description="Continuous trust scoring microservice using graph-aware anomaly detection",
    version="0.1.0",
    lifespan=lifespan,
)


class EvaluateRequest(BaseModel):
    """Payload for trust evaluation request."""

    context: RequestContext
    feature_vector: FeatureVector | None = None


class EvaluateResponse(BaseModel):
    """Response payload containing evaluated trust score and features."""

    trust_score: TrustScore
    features: FeatureVector


class ResetTrustRequest(BaseModel):
    """Payload for resetting session trust (e.g. after step-up MFA)."""

    session_id: str
    new_score: float = Field(1.0, ge=0.0, le=1.0)


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Service health probe."""
    return {"status": "ok", "service": "trust_engine"}


@app.post("/evaluate", response_model=EvaluateResponse, tags=["Scoring"])
async def evaluate_trust(
    request: EvaluateRequest,
    service: Annotated[TrustScoringService, Depends(get_trust_scoring_service)],
) -> EvaluateResponse:
    """Evaluate trust score for a given request context."""
    trust, features = service.evaluate(
        context=request.context,
        feature_vector=request.feature_vector,
    )
    return EvaluateResponse(trust_score=trust, features=features)


@app.post("/reset", tags=["Scoring"])
async def reset_session_trust(
    request: ResetTrustRequest,
    service: Annotated[TrustScoringService, Depends(get_trust_scoring_service)],
) -> dict[str, Any]:
    """Reset session trust score back to a baseline value."""
    service.score_manager.reset_session_trust(
        session_id=request.session_id,
        new_score=request.new_score,
    )
    return {"status": "reset", "session_id": request.session_id, "score": request.new_score}
