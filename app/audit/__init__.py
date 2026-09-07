"""Audit module: SHAP explanation generation and audit log storage/API."""

from app.audit.api import get_audit_logger, router
from app.audit.explainer import SHAPExplainer
from app.audit.logger import AuditLogger

__all__ = [
    "AuditLogger",
    "SHAPExplainer",
    "get_audit_logger",
    "router",
]
