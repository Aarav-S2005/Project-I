"""FastAPI router providing audit log query endpoints and SHAP explanation details."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.audit.logger import AuditLogger
from app.common.schemas import AuditRecord

router = APIRouter(prefix="/audit", tags=["Audit & Explainability"])

_global_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Dependency provider for AuditLogger."""
    global _global_audit_logger
    if _global_audit_logger is None:
        _global_audit_logger = AuditLogger()
    return _global_audit_logger


@router.get("/records", response_model=list[AuditRecord])
async def query_audit_records(
    session_id: str | None = Query(None, description="Filter by session ID"),
    subject: str | None = Query(None, description="Filter by subject string (e.g. user:alice)"),
    action: str | None = Query(None, description="Filter by action (allow, step_up, narrow, deny)"),
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    logger: Annotated[AuditLogger, Depends(get_audit_logger)] = None,  # type: ignore[assignment]
) -> list[AuditRecord]:
    """Query recent gateway access decisions with feature-level SHAP attributions."""
    return logger.query_records(
        session_id=session_id,
        subject_key=subject,
        action_filter=action,
        limit=limit,
    )


@router.get("/records/{record_id}", response_model=AuditRecord)
async def get_audit_record(
    record_id: str,
    logger: Annotated[AuditLogger, Depends(get_audit_logger)] = None,  # type: ignore[assignment]
) -> AuditRecord:
    """Retrieve full audit record and feature attribution payload for a decision UUID."""
    record = logger.get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return record
