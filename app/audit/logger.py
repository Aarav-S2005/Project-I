"""Audit logger capturing decision records and SHAP feature-level attributions."""

import json
import logging
import uuid
from typing import Any

import redis

from app.audit.explainer import SHAPExplainer
from app.common.config import settings
from app.common.schemas import AuditRecord, DecisionResult, FeatureVector
from app.trust_engine.model import AnomalyModel

logger = logging.getLogger(__name__)


class AuditLogger:
    """Manages creation, explanation generation, and persistence of immutable audit records."""

    def __init__(
        self,
        explainer: SHAPExplainer | None = None,
        redis_client: Any = None,
    ) -> None:
        """Initialize AuditLogger with SHAP explainer and Redis client.

        Args:
            explainer: Injected SHAPExplainer instance.
            redis_client: Injected Redis client instance.
        """
        self.explainer = explainer or SHAPExplainer()
        if redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def log_decision(
        self,
        decision: DecisionResult,
        feature_vector: FeatureVector,
        model: AnomalyModel | None = None,
    ) -> AuditRecord:
        """Create and persist an explainable audit record for an evaluated decision.

        Args:
            decision: Evaluated DecisionResult.
            feature_vector: Feature vector active at time of evaluation.
            model: Optional anomaly model instance for SHAP attribution.

        Returns:
            AuditRecord: Complete audit log record with SHAP attributions.
        """
        record_id = str(uuid.uuid4())
        session_id = decision.context.session_id
        subject_key = decision.context.subject.to_string()

        # 1. Generate SHAP feature attributions
        attributions = self.explainer.explain(features=feature_vector, model=model)

        # 2. Extract top anomaly drivers
        top_drivers = [a.feature_name for a in attributions if a.direction == "anomalous"][:3]

        record = AuditRecord(
            record_id=record_id,
            session_id=session_id,
            timestamp=decision.timestamp,
            decision=decision,
            feature_vector=feature_vector,
            attributions=attributions,
            top_anomaly_drivers=top_drivers,
        )

        # 3. Persist record in Redis
        try:
            record_json = record.model_dump_json()
            pipe = self._redis.pipeline()
            # Store record data with 7-day retention (604800s)
            pipe.setex(f"audit:record:{record_id}", 604800, record_json)
            pipe.lpush(f"audit:session:{session_id}", record_id)
            pipe.ltrim(f"audit:session:{session_id}", 0, 100)
            pipe.lpush(f"audit:subject:{subject_key}", record_id)
            pipe.ltrim(f"audit:subject:{subject_key}", 0, 100)
            pipe.lpush("audit:all", record_id)
            pipe.ltrim("audit:all", 0, 500)
            pipe.execute()
        except Exception as exc:
            logger.warning("Failed persisting audit record to Redis: %s", exc)

        return record

    def get_record(self, record_id: str) -> AuditRecord | None:
        """Retrieve a specific audit record by UUID.

        Args:
            record_id: Unique audit record UUID.

        Returns:
            AuditRecord | None: Deserialized record if found.
        """
        try:
            raw = self._redis.get(f"audit:record:{record_id}")
            if raw:
                data = json.loads(raw)
                return AuditRecord.model_validate(data)
        except Exception as exc:
            logger.warning("Failed retrieving audit record %s from Redis: %s", record_id, exc)
        return None

    def query_records(
        self,
        session_id: str | None = None,
        subject_key: str | None = None,
        action_filter: str | None = None,
        limit: int = 50,
    ) -> list[AuditRecord]:
        """Query recent audit records with optional filters.

        Args:
            session_id: Filter by session ID.
            subject_key: Filter by subject string (e.g. 'user:alice').
            action_filter: Filter by decision action ('allow', 'step_up', 'narrow', 'deny').
            limit: Maximum records to return.

        Returns:
            list[AuditRecord]: Matching audit records ordered by most recent first.
        """
        if session_id:
            index_key = f"audit:session:{session_id}"
        elif subject_key:
            index_key = f"audit:subject:{subject_key}"
        else:
            index_key = "audit:all"

        try:
            record_ids = self._redis.lrange(index_key, 0, limit * 2)
            results: list[AuditRecord] = []
            for r_id in record_ids:
                rec = self.get_record(r_id)
                if rec is not None:
                    if action_filter and rec.decision.action != action_filter:
                        continue
                    results.append(rec)
                    if len(results) >= limit:
                        break
            return results
        except Exception as exc:
            logger.warning("Failed querying audit records from Redis: %s", exc)
            return []
