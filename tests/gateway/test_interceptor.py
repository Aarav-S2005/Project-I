"""Unit tests for ZeroTrustInterceptor pipeline orchestration."""

from unittest.mock import MagicMock

import pytest

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
from app.decision.engine import DecisionEngine
from app.features import FeatureExtractor
from app.gateway.interceptor import ZeroTrustInterceptor
from app.policy.client import SpiceDBClient
from app.trust_engine.service import TrustScoringService


class TestZeroTrustInterceptor:
    """Test full 5-stage evaluation lifecycle in ZeroTrustInterceptor."""

    @pytest.fixture
    def mock_spicedb(self) -> MagicMock:
        mock = MagicMock(spec=SpiceDBClient)
        mock.check_access.return_value = True
        return mock

    @pytest.fixture
    def mock_feature_extractor(self) -> MagicMock:
        mock = MagicMock(spec=FeatureExtractor)
        mock.extract_features.return_value = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=1.0,
                request_rate_5m=3.0,
                geo_velocity_kmh=0.0,
                device_fingerprint_mismatch=0.0,
                time_of_day_deviation=0.0,
            ),
            graph=GraphFeatures(
                hop_count=2,
                path_novelty_score=0.0,
                privilege_shortcut_flag=0.0,
                traversal_path_signature="user:a->team:t#member->doc:d#view",
            ),
        )
        return mock

    @pytest.fixture
    def mock_trust_service(self) -> MagicMock:
        mock = MagicMock(spec=TrustScoringService)
        mock.evaluate.return_value = (
            TrustScore(
                score=0.92,
                previous_score=0.90,
                raw_anomaly_score=0.10,
                decay_amount=0.0,
                recovery_amount=0.02,
                session_id="sess_pipe_1",
                timestamp=1000.0,
            ),
            FeatureVector(
                behavioral=BehavioralFeatures(
                    request_rate_1m=1.0,
                    request_rate_5m=3.0,
                    geo_velocity_kmh=0.0,
                    device_fingerprint_mismatch=0.0,
                    time_of_day_deviation=0.0,
                ),
                graph=GraphFeatures(
                    hop_count=2,
                    path_novelty_score=0.0,
                    privilege_shortcut_flag=0.0,
                    traversal_path_signature="user:a->team:t#member->doc:d#view",
                ),
            ),
        )
        mock.model = MagicMock()
        return mock

    @pytest.fixture
    def mock_decision_engine(self) -> MagicMock:
        mock = MagicMock(spec=DecisionEngine)
        return mock

    @pytest.fixture
    def mock_audit_logger(self) -> MagicMock:
        mock = MagicMock(spec=AuditLogger)
        return mock

    def test_evaluate_request_lifecycle(
        self,
        mock_spicedb: MagicMock,
        mock_feature_extractor: MagicMock,
        mock_trust_service: MagicMock,
        mock_decision_engine: MagicMock,
        mock_audit_logger: MagicMock,
    ) -> None:
        context = RequestContext(
            session_id="sess_pipe_1",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1000.0,
        )

        expected_decision = DecisionResult(
            action=DecisionAction.ALLOW,
            reason="Access allowed",
            trust_score=mock_trust_service.evaluate.return_value[0],
            policy_allowed=True,
            narrow_applied=False,
            challenge_required=False,
            context=context,
            timestamp=1000.0,
        )
        mock_decision_engine.evaluate_decision.return_value = expected_decision

        expected_record = AuditRecord(
            record_id="rec_pipeline_1",
            session_id="sess_pipe_1",
            timestamp=1000.0,
            decision=expected_decision,
            feature_vector=mock_feature_extractor.extract_features.return_value,
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
        mock_audit_logger.log_decision.return_value = expected_record

        interceptor = ZeroTrustInterceptor(
            spicedb_client=mock_spicedb,
            feature_extractor=mock_feature_extractor,
            trust_service=mock_trust_service,
            decision_engine=mock_decision_engine,
            audit_logger=mock_audit_logger,
        )

        result_record = interceptor.evaluate_request(context)

        assert result_record.record_id == "rec_pipeline_1"
        assert result_record.decision.action == DecisionAction.ALLOW
        mock_spicedb.check_access.assert_called_once_with(
            subject=context.subject,
            relation="view",
            resource=context.resource,
        )
        mock_feature_extractor.extract_features.assert_called_once_with(context)
        mock_trust_service.evaluate.assert_called_once()
        mock_decision_engine.evaluate_decision.assert_called_once()
        mock_audit_logger.log_decision.assert_called_once()
