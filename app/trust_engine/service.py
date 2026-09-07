"""Service orchestrating feature extraction, anomaly modeling, and trust scoring."""

from typing import Any

from app.common.schemas import FeatureVector, RequestContext, TrustScore
from app.features import FeatureExtractor
from app.policy.client import SpiceDBClient
from app.trust_engine.decay import TrustScoreManager
from app.trust_engine.model import AnomalyModel


class TrustScoringService:
    """End-to-end service for evaluating continuous trust scores."""

    def __init__(
        self,
        model: AnomalyModel | None = None,
        score_manager: TrustScoreManager | None = None,
        feature_extractor: FeatureExtractor | None = None,
        spicedb_client: SpiceDBClient | None = None,
        redis_client: Any = None,
    ) -> None:
        """Initialize service with model, decay manager, and feature extractor."""
        self.model = model or AnomalyModel()
        self.score_manager = score_manager or TrustScoreManager(redis_client=redis_client)
        self.feature_extractor = feature_extractor or FeatureExtractor(
            spicedb_client=spicedb_client,
            redis_client=redis_client,
        )

    def evaluate(
        self,
        context: RequestContext,
        feature_vector: FeatureVector | None = None,
    ) -> tuple[TrustScore, FeatureVector]:
        """Evaluate request context and return updated trust score with feature attribution vector.

        Args:
            context: Incoming request context metadata.
            feature_vector: Optional pre-extracted feature vector.

        Returns:
            tuple[TrustScore, FeatureVector]: Computed trust score and active feature vector.
        """
        feats = feature_vector or self.feature_extractor.extract_features(context)
        raw_anomaly = self.model.score_anomaly(feats)
        trust = self.score_manager.compute_trust_update(
            session_id=context.session_id,
            raw_anomaly_score=raw_anomaly,
            timestamp=context.timestamp,
        )
        return trust, feats
