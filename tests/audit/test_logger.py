"""Unit and API router tests for AuditLogger."""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.api import get_audit_logger, router
from app.audit.explainer import SHAPExplainer
from app.audit.logger import AuditLogger
from app.common.schemas import (
    AuditRecord,
    BehavioralFeatures,
    DecisionAction,
    DecisionResult,
    FeatureAttribution,
    FeatureVector,
    GraphFeatures,
    RequestContext,
    Resource,
    Subject,
    TrustScore,
)


def _make_dummy_features() -> FeatureVector:
    """Helper to construct a valid dummy FeatureVector."""
    return FeatureVector(
        behavioral=BehavioralFeatures(
            request_rate_1m=1.0,
            request_rate_5m=5.0,
            geo_velocity_kmh=0.0,
            device_fingerprint_mismatch=0.0,
            time_of_day_deviation=0.0,
        ),
        graph=GraphFeatures(
            hop_count=1,
            path_novelty_score=0.0,
            privilege_shortcut_flag=0.0,
            traversal_path_signature="user:a->doc:d#reader",
        ),
    )


class TestAuditLogger:
    """Test AuditLogger record generation, persistence, and queries."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        mock = MagicMock()
        pipe = MagicMock()
        pipe.execute.return_value = [True, 1, True, 1, True, 1, True]
        mock.pipeline.return_value = pipe
        return mock

    @pytest.fixture
    def mock_explainer(self) -> MagicMock:
        mock = MagicMock(spec=SHAPExplainer)
        mock.explain.return_value = [
            FeatureAttribution(
                feature_name="request_rate_1m",
                feature_value=120.0,
                shap_value=-0.35,
                contribution_score=0.65,
                direction="anomalous",
            ),
            FeatureAttribution(
                feature_name="hop_count",
                feature_value=1.0,
                shap_value=0.10,
                contribution_score=0.35,
                direction="benign",
            ),
        ]
        return mock

    @pytest.fixture
    def sample_decision(self) -> DecisionResult:
        context = RequestContext(
            session_id="sess_audit_test",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc200"),
            timestamp=1000.0,
        )
        trust = TrustScore(
            score=0.35,
            previous_score=0.80,
            raw_anomaly_score=0.75,
            decay_amount=0.45,
            recovery_amount=0.0,
            session_id="sess_audit_test",
            timestamp=1000.0,
        )
        return DecisionResult(
            action=DecisionAction.NARROW,
            reason="Anomalous trust score: closed loop narrowing applied",
            trust_score=trust,
            policy_allowed=True,
            narrow_applied=True,
            challenge_required=False,
            context=context,
            timestamp=1000.0,
        )

    def test_log_decision(
        self,
        mock_redis: MagicMock,
        mock_explainer: MagicMock,
        sample_decision: DecisionResult,
    ) -> None:
        logger = AuditLogger(explainer=mock_explainer, redis_client=mock_redis)
        features = _make_dummy_features()

        record = logger.log_decision(decision=sample_decision, feature_vector=features)

        assert record.session_id == "sess_audit_test"
        assert record.decision.action == DecisionAction.NARROW
        assert len(record.attributions) == 2
        assert record.top_anomaly_drivers == ["request_rate_1m"]
        mock_redis.pipeline.assert_called_once()

    def test_get_record(
        self,
        mock_redis: MagicMock,
        mock_explainer: MagicMock,
        sample_decision: DecisionResult,
    ) -> None:
        logger = AuditLogger(explainer=mock_explainer, redis_client=mock_redis)
        rec = AuditRecord(
            record_id="rec_123",
            session_id="sess_123",
            timestamp=1000.0,
            decision=sample_decision,
            feature_vector=_make_dummy_features(),
            attributions=[],
            top_anomaly_drivers=[],
        )
        mock_redis.get.return_value = rec.model_dump_json()

        retrieved = logger.get_record("rec_123")
        assert retrieved is not None
        assert retrieved.record_id == "rec_123"
        assert retrieved.session_id == "sess_123"


class TestAuditAPI:
    """Test FastAPI audit query endpoints."""

    @pytest.fixture
    def test_app(self) -> FastAPI:
        app = FastAPI()
        app.include_router(router)
        return app

    @pytest.fixture
    def client(self, test_app: FastAPI) -> Generator[TestClient, None, None]:
        mock_logger = MagicMock(spec=AuditLogger)
        sample_rec = AuditRecord(
            record_id="rec_api_1",
            session_id="sess_api_1",
            timestamp=1000.0,
            decision=DecisionResult(
                action=DecisionAction.ALLOW,
                reason="Normal access",
                trust_score=TrustScore(
                    score=0.95,
                    previous_score=0.95,
                    raw_anomaly_score=0.05,
                    decay_amount=0.0,
                    recovery_amount=0.0,
                    session_id="sess_api_1",
                    timestamp=1000.0,
                ),
                policy_allowed=True,
                narrow_applied=False,
                challenge_required=False,
                context=RequestContext(
                    session_id="sess_api_1",
                    subject=Subject(type="user", id="bob"),
                    resource=Resource(type="document", id="doc1"),
                    timestamp=1000.0,
                ),
                timestamp=1000.0,
            ),
            feature_vector=_make_dummy_features(),
            attributions=[
                FeatureAttribution(
                    feature_name="request_rate_1m",
                    feature_value=1.0,
                    shap_value=0.1,
                    contribution_score=0.5,
                    direction="benign",
                )
            ],
            top_anomaly_drivers=[],
        )

        mock_logger.query_records.return_value = [sample_rec]
        mock_logger.get_record.side_effect = lambda rid: sample_rec if rid == "rec_api_1" else None

        test_app.dependency_overrides[get_audit_logger] = lambda: mock_logger
        yield TestClient(test_app)
        test_app.dependency_overrides.clear()

    def test_query_records_endpoint(self, client: TestClient) -> None:
        resp = client.get("/audit/records?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["record_id"] == "rec_api_1"

    def test_get_record_endpoint(self, client: TestClient) -> None:
        resp = client.get("/audit/records/rec_api_1")
        assert resp.status_code == 200
        assert resp.json()["record_id"] == "rec_api_1"

    def test_get_record_not_found(self, client: TestClient) -> None:
        resp = client.get("/audit/records/non_existent_id")
        assert resp.status_code == 404
