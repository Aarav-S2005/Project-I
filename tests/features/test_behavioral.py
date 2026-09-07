"""Unit tests for behavioral feature extraction."""

from unittest.mock import MagicMock

import pytest

from app.common.schemas import RequestContext, Resource, Subject
from app.features.behavioral import (
    BehavioralFeatureExtractor,
    calculate_geo_velocity,
    calculate_haversine_distance,
    calculate_time_of_day_deviation,
)


class TestDistanceAndVelocityMath:
    """Test mathematical formulas for geo-distance, velocity, and time deviation."""

    def test_haversine_distance_same_point(self) -> None:
        dist = calculate_haversine_distance(37.7749, -122.4194, 37.7749, -122.4194)
        assert dist == pytest.approx(0.0, abs=1e-3)

    def test_haversine_distance_known_cities(self) -> None:
        # London (51.5074, -0.1278) to Paris (48.8566, 2.3522) ~ 343 km
        dist = calculate_haversine_distance(51.5074, -0.1278, 48.8566, 2.3522)
        assert 340.0 < dist < 350.0

    def test_geo_velocity_calculation(self) -> None:
        # Travel ~343 km in 0.5 hours (1800s) = ~686 km/h
        vel = calculate_geo_velocity(
            lat1=51.5074,
            lon1=-0.1278,
            t1=1000.0,
            lat2=48.8566,
            lon2=2.3522,
            t2=2800.0,
        )
        assert 680.0 < vel < 695.0

    def test_geo_velocity_zero_time(self) -> None:
        vel = calculate_geo_velocity(0.0, 0.0, 100.0, 10.0, 10.0, 100.0)
        assert vel == 0.0

    def test_time_of_day_deviation_business_hours(self) -> None:
        # 14:00 UTC (timestamp corresponding to 14:00:00 UTC)
        # 2026-09-07 14:00:00 UTC = 1788789600
        timestamp = 1788789600.0
        dev = calculate_time_of_day_deviation(timestamp, start_hour=8, end_hour=18)
        assert dev == 0.0

    def test_time_of_day_deviation_night_time(self) -> None:
        # 02:00 UTC
        # 2026-09-07 02:00:00 UTC = 1788746400
        timestamp = 1788746400.0
        dev = calculate_time_of_day_deviation(timestamp, start_hour=8, end_hour=18)
        assert dev > 0.5


class TestBehavioralFeatureExtractor:
    """Test BehavioralFeatureExtractor using mocked Redis."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        mock = MagicMock()
        pipe = MagicMock()
        # [zadd, zremrangebyscore, count_1m, count_5m, expire]
        pipe.execute.return_value = [1, 0, 5, 12, True]
        mock.pipeline.return_value = pipe
        mock.get.return_value = None
        return mock

    def test_extract_behavioral_features(self, mock_redis: MagicMock) -> None:
        extractor = BehavioralFeatureExtractor(redis_client=mock_redis)

        context = RequestContext(
            session_id="sess_123",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,  # 14:00 UTC
            latitude=37.7749,
            longitude=-122.4194,
            user_agent="Mozilla/5.0",
            device_id="dev_abc",
        )

        features = extractor.extract(context)

        assert features.request_rate_1m == 5.0
        assert features.request_rate_5m == 12.0
        assert features.geo_velocity_kmh == 0.0  # first location seen
        assert features.device_fingerprint_mismatch == 0.0
        assert features.time_of_day_deviation == 0.0

    def test_device_fingerprint_mismatch(self, mock_redis: MagicMock) -> None:
        extractor = BehavioralFeatureExtractor(redis_client=mock_redis)
        # Mock that baseline was previously set to a different device ID
        mock_redis.get.return_value = "old_device_xyz"

        context = RequestContext(
            session_id="sess_123",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,
            device_id="new_device_compromised",
        )

        features = extractor.extract(context)
        assert features.device_fingerprint_mismatch == 1.0
