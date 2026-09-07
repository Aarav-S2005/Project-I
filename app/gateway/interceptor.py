"""Zero-Trust request interceptor executing full policy, scoring, and audit lifecycle."""

import logging
from typing import Any

from app.audit.logger import AuditLogger
from app.common.schemas import AuditRecord, RequestContext
from app.decision.engine import DecisionEngine
from app.features import FeatureExtractor
from app.policy.client import SpiceDBClient, get_spicedb_client
from app.trust_engine.service import TrustScoringService

logger = logging.getLogger(__name__)


class ZeroTrustInterceptor:
    """Coordinates the continuous Zero-Trust evaluation pipeline for incoming API requests."""

    def __init__(
        self,
        spicedb_client: SpiceDBClient | None = None,
        feature_extractor: FeatureExtractor | None = None,
        trust_service: TrustScoringService | None = None,
        decision_engine: DecisionEngine | None = None,
        audit_logger: AuditLogger | None = None,
        redis_client: Any = None,
    ) -> None:
        """Initialize interceptor with all pipeline sub-components."""
        self.spicedb_client = spicedb_client or get_spicedb_client()
        self.feature_extractor = feature_extractor or FeatureExtractor(
            spicedb_client=self.spicedb_client,
            redis_client=redis_client,
        )
        self.trust_service = trust_service or TrustScoringService(
            feature_extractor=self.feature_extractor,
            spicedb_client=self.spicedb_client,
            redis_client=redis_client,
        )
        self.decision_engine = decision_engine or DecisionEngine(
            spicedb_client=self.spicedb_client,
        )
        self.audit_logger = audit_logger or AuditLogger(redis_client=redis_client)

    def evaluate_request(self, context: RequestContext) -> AuditRecord:
        """Execute the full 5-stage Zero-Trust authorization and anomaly scoring pipeline.

        Pipeline Stages:
            1. ReBAC Policy Evaluation (SpiceDB)
            2. Feature Extraction (Behavioral rolling metrics & Graph traversal paths)
            3. Continuous Trust Scoring (Isolation Forest anomaly model & stateful decay)
            4. Decision Engine Evaluation (allow, step_up, narrow with write-back, deny)
            5. Audit Logging with SHAP feature attribution

        Args:
            context: Incoming request context metadata.

        Returns:
            AuditRecord: Immutable audit record containing decision and SHAP explanation.
        """
        # 1. Base ReBAC check
        policy_allowed = self.spicedb_client.check_access(
            subject=context.subject,
            relation=context.permission,
            resource=context.resource,
        )

        # 2. Extract behavioral and graph features
        features = self.feature_extractor.extract_features(context)

        # 3. Evaluate anomaly model and stateful trust score
        trust_score, _ = self.trust_service.evaluate(context, feature_vector=features)

        # 4. Determine response action and execute closed-loop feedback if needed
        decision = self.decision_engine.evaluate_decision(
            policy_allowed=policy_allowed,
            trust_score=trust_score,
            context=context,
        )

        # 5. Log immutable audit record with SHAP attribution
        audit_record = self.audit_logger.log_decision(
            decision=decision,
            feature_vector=features,
            model=self.trust_service.model,
        )

        return audit_record
