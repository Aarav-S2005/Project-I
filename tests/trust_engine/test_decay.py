"""Unit tests for stateful trust score decay and recovery."""

from unittest.mock import MagicMock

import pytest

from app.trust_engine.decay import TrustScoreManager


class TestTrustScoreManager:
    """Test trust decay, recovery, and session state transitions."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        mock = MagicMock()
        pipe = MagicMock()
        pipe.execute.return_value = [True, True]
        mock.pipeline.return_value = pipe
        mock.get.return_value = None  # initially no previous score
        return mock

    def test_initial_trust_score(self, mock_redis: MagicMock) -> None:
        manager = TrustScoreManager(redis_client=mock_redis)

        # Baseline benign request (anomaly score = 0.10)
        res = manager.compute_trust_update(
            session_id="sess_1",
            raw_anomaly_score=0.10,
            timestamp=1000.0,
        )

        assert res.previous_score == 1.0
        assert res.score == 1.0  # capped at 1.0
        assert res.decay_amount == 0.0
        assert res.recovery_amount > 0.0

    def test_trust_decay_on_anomaly(self, mock_redis: MagicMock) -> None:
        manager = TrustScoreManager(redis_client=mock_redis)
        # Previous score was 0.90
        mock_redis.get.side_effect = lambda key: "0.90" if "trust_score" in key else "1000.0"

        # Anomalous request (anomaly score = 0.80)
        res = manager.compute_trust_update(
            session_id="sess_1",
            raw_anomaly_score=0.80,
            timestamp=1010.0,
        )

        assert res.previous_score == 0.90
        assert res.decay_amount > 0.20
        assert res.score < 0.70
        assert res.recovery_amount == 0.0

    def test_trust_recovery_on_benign_traffic(self, mock_redis: MagicMock) -> None:
        manager = TrustScoreManager(redis_client=mock_redis)
        # Previous score decayed down to 0.40
        mock_redis.get.side_effect = lambda key: "0.40" if "trust_score" in key else "1000.0"

        # Benign request after 300 seconds
        res = manager.compute_trust_update(
            session_id="sess_1",
            raw_anomaly_score=0.10,
            timestamp=1300.0,
        )

        assert res.previous_score == 0.40
        assert res.recovery_amount > 0.02
        assert res.score > 0.42
        assert res.decay_amount == 0.0

    def test_reset_session_trust(self, mock_redis: MagicMock) -> None:
        manager = TrustScoreManager(redis_client=mock_redis)
        manager.reset_session_trust("sess_reset", new_score=1.0)
        mock_redis.setex.assert_called_once()
