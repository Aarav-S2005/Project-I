"""Unit and API route tests for TrustScoringService."""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.common.schemas import (
    BehavioralFeatures,
    FeatureVector,
    GraphFeatures,
    RequestContext,
    Resource,
    Subject,
    TrustScore,
)
from app.features import FeatureExtractor
from app.trust_engine.decay import TrustScoreManager
from app.trust_engine.main import app, get_trust_scoring_service
from app.trust_engine.model import AnomalyModel
from app.trust_engine.service import TrustScoringService


class TestTrustScoringService:
    """Test TrustScoringService orchestration."""

    @pytest.fixture
    def mock_model(self) -> MagicMock:
        mock = MagicMock(spec=AnomalyModel)
        mock.score_anomaly.return_value = 0.15
        return mock

    @pytest.fixture
    def mock_score_manager(self) -> MagicMock:
        mock = MagicMock(spec=TrustScoreManager)
        mock.compute_trust_update.return_value = TrustScore(
            score=0.98,
            previous_score=0.95,
            raw_anomaly_score=0.15,
            decay_amount=0.0,
            recovery_amount=0.03,
            session_id="sess_test",
            timestamp=1000.0,
        )
        return mock

    @pytest.fixture
    def mock_extractor(self) -> MagicMock:
        mock = MagicMock(spec=FeatureExtractor)
        mock.extract_features.return_value = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=1.0,
                request_rate_5m=4.0,
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

    def test_evaluate_service(
        self,
        mock_model: MagicMock,
        mock_score_manager: MagicMock,
        mock_extractor: MagicMock,
    ) -> None:
        service = TrustScoringService(
            model=mock_model,
            score_manager=mock_score_manager,
            feature_extractor=mock_extractor,
        )

        context = RequestContext(
            session_id="sess_test",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1000.0,
        )

        trust, feats = service.evaluate(context)

        assert trust.score == 0.98
        assert feats.behavioral.request_rate_1m == 1.0
        mock_extractor.extract_features.assert_called_once_with(context)
        mock_model.score_anomaly.assert_called_once()
        mock_score_manager.compute_trust_update.assert_called_once_with(
            session_id="sess_test",
            raw_anomaly_score=0.15,
            timestamp=1000.0,
        )


class TestTrustEngineAPI:
    """Test FastAPI route handlers for the Trust Engine microservice."""

    @pytest.fixture
    def client(self) -> Generator[TestClient, None, None]:
        # Mock the service dependency
        mock_service = MagicMock(spec=TrustScoringService)
        mock_service.evaluate.return_value = (
            TrustScore(
                score=0.88,
                previous_score=0.90,
                raw_anomaly_score=0.40,
                decay_amount=0.02,
                recovery_amount=0.0,
                session_id="sess_api",
                timestamp=1000.0,
            ),
            FeatureVector(
                behavioral=BehavioralFeatures(
                    request_rate_1m=0.0,
                    request_rate_5m=0.0,
                    geo_velocity_kmh=0.0,
                    device_fingerprint_mismatch=0.0,
                    time_of_day_deviation=0.0,
                ),
                graph=GraphFeatures(
                    hop_count=0,
                    path_novelty_score=0.0,
                    privilege_shortcut_flag=0.0,
                    traversal_path_signature="",
                ),
            ),
        )
        mock_service.score_manager = MagicMock()

        app.dependency_overrides[get_trust_scoring_service] = lambda: mock_service
        yield TestClient(app)
        app.dependency_overrides.clear()

    def test_health_check(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "service": "trust_engine"}

    def test_evaluate_endpoint(self, client: TestClient) -> None:
        payload = {
            "context": {
                "session_id": "sess_api",
                "subject": {"type": "user", "id": "alice"},
                "resource": {"type": "document", "id": "doc1"},
                "timestamp": 1000.0,
            }
        }
        resp = client.post("/evaluate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["trust_score"]["score"] == 0.88
        assert data["trust_score"]["session_id"] == "sess_api"

    def test_reset_endpoint(self, client: TestClient) -> None:
        payload = {"session_id": "sess_api", "new_score": 1.0}
        resp = client.post("/reset", json=payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "reset"
