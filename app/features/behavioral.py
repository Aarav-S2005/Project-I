"""Behavioral feature extraction: rolling rate, geo-velocity, device shift, time deviation."""

import json
import logging
import math
from datetime import UTC, datetime
from typing import Any

import redis

from app.common.config import settings
from app.common.schemas import BehavioralFeatures, RequestContext

logger = logging.getLogger(__name__)

EARTH_RADIUS_KM = 6371.0


def calculate_haversine_distance(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """Calculate the great-circle distance between two points on Earth in kilometers.

    Args:
        lat1: Latitude of point 1 in degrees.
        lon1: Longitude of point 1 in degrees.
        lat2: Latitude of point 2 in degrees.
        lon2: Longitude of point 2 in degrees.

    Returns:
        float: Distance in kilometers.
    """
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


def calculate_geo_velocity(
    lat1: float,
    lon1: float,
    t1: float,
    lat2: float,
    lon2: float,
    t2: float,
) -> float:
    """Calculate speed in km/h between two timestamped geographic coordinates.

    Args:
        lat1: Latitude of origin.
        lon1: Longitude of origin.
        t1: Timestamp of origin in seconds.
        lat2: Latitude of destination.
        lon2: Longitude of destination.
        t2: Timestamp of destination in seconds.

    Returns:
        float: Velocity in kilometers per hour.
    """
    time_delta_hours = abs(t2 - t1) / 3600.0
    if time_delta_hours <= 0.0:
        return 0.0

    distance_km = calculate_haversine_distance(lat1, lon1, lat2, lon2)
    return distance_km / time_delta_hours


def calculate_time_of_day_deviation(
    timestamp: float,
    start_hour: int = 8,
    end_hour: int = 18,
) -> float:
    """Calculate normalized deviation score (0.0 to 1.0) from typical operating hours.

    Args:
        timestamp: Unix timestamp in seconds.
        start_hour: Start of expected active window (0-23, UTC/local).
        end_hour: End of expected active window (0-23, UTC/local).

    Returns:
        float: 0.0 if within standard window, linearly scaling to 1.0 at furthest point.
    """
    dt = datetime.fromtimestamp(timestamp, tz=UTC)
    hour = dt.hour + dt.minute / 60.0

    if start_hour <= hour <= end_hour:
        return 0.0

    if hour < start_hour:
        diff = start_hour - hour
    else:
        diff = hour - end_hour

    # Max possible distance from working hours is roughly 7 hours (out of 24)
    max_diff = 24.0 - (end_hour - start_hour)
    return min(1.0, round(diff / (max_diff / 2.0), 4))


class BehavioralFeatureExtractor:
    """Extracts rolling behavioral features using Redis as the state store."""

    def __init__(self, redis_client: Any = None) -> None:
        """Initialize extractor with Redis client or fallback connection.

        Args:
            redis_client: Injected Redis client instance (useful for unit testing).
        """
        if redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def extract(self, context: RequestContext) -> BehavioralFeatures:
        """Extract behavioral features for a request context.

        Args:
            context: Captured request context metadata.

        Returns:
            BehavioralFeatures: Computed behavioral metrics.
        """
        now = context.timestamp
        session_id = context.session_id
        subject_key = context.subject.to_string()

        # 1. Rolling Request Rates (1m and 5m windows)
        rate_key = f"rate:{subject_key}"
        rate_1m, rate_5m = self._update_and_get_rates(rate_key, now)

        # 2. Geo-Velocity Calculation
        geo_velocity = 0.0
        if context.latitude is not None and context.longitude is not None:
            geo_velocity = self._compute_and_update_geo_velocity(
                session_id=session_id,
                lat=context.latitude,
                lon=context.longitude,
                timestamp=now,
            )

        # 3. Device / Fingerprint Novelty
        fingerprint_id = context.device_id or context.user_agent
        device_mismatch = self._check_and_update_device_fingerprint(
            session_id=session_id,
            fingerprint=fingerprint_id,
        )

        # 4. Time of Day Deviation
        time_deviation = calculate_time_of_day_deviation(now)

        return BehavioralFeatures(
            request_rate_1m=float(rate_1m),
            request_rate_5m=float(rate_5m),
            geo_velocity_kmh=round(geo_velocity, 2),
            device_fingerprint_mismatch=device_mismatch,
            time_of_day_deviation=time_deviation,
        )

    def _update_and_get_rates(self, rate_key: str, timestamp: float) -> tuple[int, int]:
        """Record request and retrieve counts for 1-minute and 5-minute sliding windows."""
        try:
            # Add current request with timestamp as score and member
            pipe = self._redis.pipeline()
            member = f"{timestamp}:{id(timestamp)}"
            pipe.zadd(rate_key, {member: timestamp})
            # Remove entries older than 5 minutes (300 seconds)
            pipe.zremrangebyscore(rate_key, "-inf", timestamp - 300)
            # Count entries in last 1 minute (60 seconds)
            pipe.zcount(rate_key, timestamp - 60, "+inf")
            # Count entries in last 5 minutes
            pipe.zcard(rate_key)
            pipe.expire(rate_key, 600)
            results = pipe.execute()

            count_1m = int(results[2])
            count_5m = int(results[3])
            return count_1m, count_5m
        except Exception as exc:
            logger.warning("Failed updating request rates in Redis: %s", exc)
            return 1, 1

    def _compute_and_update_geo_velocity(
        self,
        session_id: str,
        lat: float,
        lon: float,
        timestamp: float,
    ) -> float:
        """Calculate velocity against previous session location and update Redis."""
        loc_key = f"session:{session_id}:last_location"
        try:
            raw_last_loc = self._redis.get(loc_key)
            velocity = 0.0
            if raw_last_loc:
                data = json.loads(raw_last_loc)
                prev_lat = float(data["lat"])
                prev_lon = float(data["lon"])
                prev_time = float(data["timestamp"])
                velocity = calculate_geo_velocity(
                    lat1=prev_lat,
                    lon1=prev_lon,
                    t1=prev_time,
                    lat2=lat,
                    lon2=lon,
                    t2=timestamp,
                )

            # Store current location with 1-hour expiration
            payload = json.dumps({"lat": lat, "lon": lon, "timestamp": timestamp})
            self._redis.setex(loc_key, 3600, payload)
            return velocity
        except Exception as exc:
            logger.warning("Failed computing geo-velocity in Redis: %s", exc)
            return 0.0

    def _check_and_update_device_fingerprint(
        self,
        session_id: str,
        fingerprint: str,
    ) -> float:
        """Check if fingerprint matches session baseline, setting baseline if not exists."""
        device_key = f"session:{session_id}:device_baseline"
        try:
            baseline = self._redis.get(device_key)
            if baseline is None:
                self._redis.setex(device_key, 86400, fingerprint)
                return 0.0
            return 0.0 if baseline == fingerprint else 1.0
        except Exception as exc:
            logger.warning("Failed checking device fingerprint in Redis: %s", exc)
            return 0.0
