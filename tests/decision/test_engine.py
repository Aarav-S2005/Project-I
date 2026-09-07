"""Unit tests for the DecisionEngine and closed-loop policy feedback."""

from unittest.mock import MagicMock

import pytest

from app.common.schemas import (
    DecisionAction,
    RequestContext,
    Resource,
    Subject,
    TrustScore,
)
from app.decision.engine import DecisionEngine, DecisionThresholds
from app.policy.client import SpiceDBClient


class TestDecisionEngine:
    """Test decision logic across trust bands and closed-loop SpiceDB write-backs."""

    @pytest.fixture
    def mock_spicedb(self) -> MagicMock:
        return MagicMock(spec=SpiceDBClient)

    @pytest.fixture
    def sample_context(self) -> RequestContext:
        return RequestContext(
            session_id="sess_decision_1",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc100"),
            timestamp=1000.0,
        )

    def test_evaluate_allow(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        trust = TrustScore(
            score=0.92,
            previous_score=0.90,
            raw_anomaly_score=0.10,
            decay_amount=0.0,
            recovery_amount=0.02,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.ALLOW
        assert result.policy_allowed is True
        assert result.challenge_required is False
        assert result.narrow_applied is False
        mock_spicedb.narrow_access.assert_not_called()

    def test_evaluate_step_up(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        trust = TrustScore(
            score=0.62,
            previous_score=0.70,
            raw_anomaly_score=0.45,
            decay_amount=0.08,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.STEP_UP
        assert result.challenge_required is True
        assert result.narrow_applied is False
        mock_spicedb.narrow_access.assert_not_called()

    def test_evaluate_narrow_closed_loop_feedback(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        trust = TrustScore(
            score=0.35,
            previous_score=0.55,
            raw_anomaly_score=0.70,
            decay_amount=0.20,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.NARROW
        assert result.narrow_applied is True
        assert result.challenge_required is False

        # Verify the closed-loop write-back was triggered in SpiceDB
        mock_spicedb.narrow_access.assert_called_once_with(
            subject=sample_context.subject,
            resource=sample_context.resource,
        )

    def test_evaluate_narrow_spicedb_exception(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        mock_spicedb.narrow_access.side_effect = RuntimeError("SpiceDB unreachable")
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        trust = TrustScore(
            score=0.30,
            previous_score=0.50,
            raw_anomaly_score=0.75,
            decay_amount=0.20,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.NARROW
        assert result.narrow_applied is False

    def test_evaluate_deny_trust_collapse(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        trust = TrustScore(
            score=0.12,
            previous_score=0.30,
            raw_anomaly_score=0.90,
            decay_amount=0.18,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.DENY
        mock_spicedb.narrow_access.assert_not_called()

    def test_evaluate_deny_policy_failure(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        engine = DecisionEngine(spicedb_client=mock_spicedb)
        # Perfect trust score, but user lacks ReBAC permission
        trust = TrustScore(
            score=1.0,
            previous_score=1.0,
            raw_anomaly_score=0.0,
            decay_amount=0.0,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=False,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.DENY
        assert result.policy_allowed is False
        mock_spicedb.narrow_access.assert_not_called()

    def test_custom_thresholds(
        self,
        mock_spicedb: MagicMock,
        sample_context: RequestContext,
    ) -> None:
        custom_thresholds = DecisionThresholds(
            allow_threshold=0.85,
            step_up_threshold=0.60,
            narrow_threshold=0.40,
        )
        engine = DecisionEngine(
            spicedb_client=mock_spicedb,
            thresholds=custom_thresholds,
        )

        # Score 0.80 would normally be ALLOW with default 0.75, but STEP_UP with custom 0.85
        trust = TrustScore(
            score=0.80,
            previous_score=0.80,
            raw_anomaly_score=0.20,
            decay_amount=0.0,
            recovery_amount=0.0,
            session_id="sess_decision_1",
            timestamp=1000.0,
        )

        result = engine.evaluate_decision(
            policy_allowed=True,
            trust_score=trust,
            context=sample_context,
        )

        assert result.action == DecisionAction.STEP_UP
