"""Stateful trust score decay and recovery logic across user sessions."""

import logging
from typing import Any

import redis

from app.common.config import settings
from app.common.schemas import TrustScore

logger = logging.getLogger(__name__)

INITIAL_TRUST_SCORE = 1.0
ANOMALY_THRESHOLD = 0.45
DECAY_ALPHA = 1.0
DECAY_GAMMA = 1.2
RECOVERY_STEP = 0.05
RECOVERY_TIME_RATE = 0.20 / 600.0  # +0.20 recovery every 10 minutes (600 seconds elapsed)



class TrustScoreManager:
    """Manages continuous, stateful trust score computation, decay, and recovery."""

    def __init__(self, redis_client: Any = None) -> None:
        """Initialize manager with Redis client for state tracking.

        Args:
            redis_client: Injected Redis client instance.
        """
        if redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def compute_trust_update(
        self,
        session_id: str,
        raw_anomaly_score: float,
        timestamp: float,
    ) -> TrustScore:
        """Compute stateful trust score update applying decay or recovery.

        Decay Formula:
            When raw_anomaly_score > ANOMALY_THRESHOLD (0.35):
            decay = DECAY_ALPHA * (raw_anomaly_score - ANOMALY_THRESHOLD) ** DECAY_GAMMA
            trust_score = max(0.0, previous_trust - decay)

        Recovery Formula:
            When raw_anomaly_score <= ANOMALY_THRESHOLD:
            recovery = RECOVERY_STEP + RECOVERY_TIME_RATE * min(time_delta, 3600)
            trust_score = min(1.0, previous_trust + recovery)

        Args:
            session_id: Unique session identifier.
            raw_anomaly_score: Model output score between 0.0 (normal) and 1.0 (anomalous).
            timestamp: Request unix timestamp in seconds.

        Returns:
            TrustScore: Full trust evaluation record.
        """
        score_key = f"session:{session_id}:trust_score"
        time_key = f"session:{session_id}:trust_timestamp"

        prev_score = self._get_previous_score(score_key)
        prev_timestamp = self._get_previous_timestamp(time_key, fallback=timestamp)

        time_delta = max(0.0, timestamp - prev_timestamp)
        decay_amount = 0.0
        recovery_amount = 0.0

        if raw_anomaly_score > ANOMALY_THRESHOLD:
            # Anomalous request triggers trust decay
            excess_anomaly = raw_anomaly_score - ANOMALY_THRESHOLD
            decay_amount = DECAY_ALPHA * (excess_anomaly**DECAY_GAMMA)
            new_score = max(0.0, prev_score - decay_amount)
        else:
            # Benign request triggers trust recovery (+0.20 per 10 mins elapsed)
            time_recovery = RECOVERY_TIME_RATE * min(time_delta, 86400.0)
            recovery_amount = RECOVERY_STEP + time_recovery
            new_score = min(1.0, prev_score + recovery_amount)

        # Persist updated score and timestamp in Redis (24h TTL)
        try:
            pipe = self._redis.pipeline()
            pipe.setex(score_key, 86400, str(new_score))
            pipe.setex(time_key, 86400, str(timestamp))
            pipe.execute()
        except Exception as exc:
            logger.warning("Failed saving trust score state to Redis: %s", exc)

        return TrustScore(
            score=round(new_score, 4),
            previous_score=round(prev_score, 4),
            raw_anomaly_score=round(raw_anomaly_score, 4),
            decay_amount=round(decay_amount, 4),
            recovery_amount=round(recovery_amount, 4),
            session_id=session_id,
            timestamp=timestamp,
        )

    def _get_previous_score(self, score_key: str) -> float:
        """Fetch previous score from Redis, or return INITIAL_TRUST_SCORE."""
        try:
            val = self._redis.get(score_key)
            if val is not None:
                return float(val)
        except Exception as exc:
            logger.warning("Failed reading trust score from Redis: %s", exc)
        return INITIAL_TRUST_SCORE

    def _get_previous_timestamp(self, time_key: str, fallback: float) -> float:
        """Fetch previous timestamp from Redis, or fallback to current timestamp."""
        try:
            val = self._redis.get(time_key)
            if val is not None:
                return float(val)
        except Exception as exc:
            logger.warning("Failed reading trust timestamp from Redis: %s", exc)
        return fallback

    def reset_session_trust(self, session_id: str, new_score: float = INITIAL_TRUST_SCORE) -> None:
        """Reset or override trust score for a session (e.g. after step-up authentication).

        Args:
            session_id: Target session identifier.
            new_score: Trust score to assign (default: 1.0).
        """
        score_key = f"session:{session_id}:trust_score"
        try:
            self._redis.setex(score_key, 86400, str(new_score))
        except Exception as exc:
            logger.warning("Failed resetting session trust in Redis: %s", exc)
