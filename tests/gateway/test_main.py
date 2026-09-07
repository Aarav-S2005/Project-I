"""Unit and integration tests for the FastAPI Zero-Trust Gateway routes."""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.common.schemas import (
    AuditRecord,
    BehavioralFeatures,
    DecisionAction,
    DecisionResult,
    FeatureVector,
    GraphFeatures,
    RequestContext,
    Resource,
    Subject,
    TrustScore,
)
from app.gateway.auth import create_access_token
from app.gateway.interceptor import ZeroTrustInterceptor
from app.gateway.main import app, get_interceptor


class TestGatewayAPI:
    """Test gateway routing, authentication, and trust band responses."""

    @pytest.fixture
    def mock_interceptor(self) -> MagicMock:
        return MagicMock(spec=ZeroTrustInterceptor)

    @pytest.fixture
    def client(self, mock_interceptor: MagicMock) -> Generator[TestClient, None, None]:
        app.dependency_overrides[get_interceptor] = lambda: mock_interceptor
        yield TestClient(app)
        app.dependency_overrides.clear()

    @pytest.fixture
    def auth_headers(self) -> dict[str, str]:
        token = create_access_token(subject="user:alice", session_id="sess_gw_test")
        return {"Authorization": f"Bearer {token}"}

    def _create_record(
        self,
        action: str,
        score: float,
        reason: str = "Decision made",
    ) -> AuditRecord:
        context = RequestContext(
            session_id="sess_gw_test",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1000.0,
        )
        trust = TrustScore(
            score=score,
            previous_score=0.90,
            raw_anomaly_score=0.10,
            decay_amount=0.0,
            recovery_amount=0.0,
            session_id="sess_gw_test",
            timestamp=1000.0,
        )
        decision = DecisionResult(
            action=action,
            reason=reason,
            trust_score=trust,
            policy_allowed=True,
            narrow_applied=bool(action == DecisionAction.NARROW),
            challenge_required=bool(action == DecisionAction.STEP_UP),
            context=context,
            timestamp=1000.0,
        )
        return AuditRecord(
            record_id="rec_gw_1",
            session_id="sess_gw_test",
            timestamp=1000.0,
            decision=decision,
            feature_vector=FeatureVector(
                behavioral=BehavioralFeatures(
                    request_rate_1m=1.0,
                    request_rate_5m=2.0,
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
            ),
            attributions=[],
            top_anomaly_drivers=["request_rate_1m"]
            if action in {DecisionAction.NARROW, DecisionAction.DENY}
            else [],
        )

    def test_health_check(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_issue_token(self, client: TestClient) -> None:
        resp = client.post(
            "/auth/token",
            json={"subject": "user:bob", "session_id": "sess_bob_token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["subject"] == "user:bob"

    def test_access_resource_allow(
        self,
        client: TestClient,
        mock_interceptor: MagicMock,
        auth_headers: dict[str, str],
    ) -> None:
        mock_interceptor.evaluate_request.return_value = self._create_record(
            action=DecisionAction.ALLOW,
            score=0.92,
        )

        resp = client.get(
            "/api/v1/document/doc1?permission=view",
            headers=auth_headers,
        )

        assert resp.status_code == 200
        assert resp.json()["status"] == "allowed"
        assert resp.headers["X-Decision-Action"] == DecisionAction.ALLOW
        assert resp.headers["X-Trust-Score"] == "0.92"
        assert resp.headers["X-Audit-Record-Id"] == "rec_gw_1"

    def test_access_resource_step_up(
        self,
        client: TestClient,
        mock_interceptor: MagicMock,
        auth_headers: dict[str, str],
    ) -> None:
        mock_interceptor.evaluate_request.return_value = self._create_record(
            action=DecisionAction.STEP_UP,
            score=0.62,
            reason="MFA required",
        )

        resp = client.get(
            "/api/v1/document/doc1?permission=view",
            headers=auth_headers,
        )

        assert resp.status_code == 401
        assert resp.json()["status"] == "step_up_required"
        assert "WWW-Authenticate" in resp.headers
        assert resp.headers["X-Decision-Action"] == DecisionAction.STEP_UP

    def test_access_resource_narrow(
        self,
        client: TestClient,
        mock_interceptor: MagicMock,
        auth_headers: dict[str, str],
    ) -> None:
        mock_interceptor.evaluate_request.return_value = self._create_record(
            action=DecisionAction.NARROW,
            score=0.35,
            reason="Closed-loop narrowing applied",
        )

        resp = client.get(
            "/api/v1/document/doc1?permission=view",
            headers=auth_headers,
        )

        assert resp.status_code == 403
        assert resp.json()["status"] == "narrowed"
        assert resp.headers["X-Narrow-Applied"] == "true"
        assert resp.headers["X-Decision-Action"] == DecisionAction.NARROW

    def test_access_resource_deny(
        self,
        client: TestClient,
        mock_interceptor: MagicMock,
        auth_headers: dict[str, str],
    ) -> None:
        mock_interceptor.evaluate_request.return_value = self._create_record(
            action=DecisionAction.DENY,
            score=0.15,
            reason="Trust collapsed",
        )

        resp = client.get(
            "/api/v1/document/doc1?permission=view",
            headers=auth_headers,
        )

        assert resp.status_code == 403
        assert resp.json()["status"] == "denied"
        assert resp.headers["X-Decision-Action"] == DecisionAction.DENY

    def test_access_resource_unauthenticated(self, client: TestClient) -> None:
        resp = client.get("/api/v1/document/doc1")
        assert resp.status_code == 401
