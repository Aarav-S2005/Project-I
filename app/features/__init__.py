"""Features module: Behavioral and graph-structural feature extractors."""

from typing import Any

from app.common.schemas import FeatureVector, RequestContext
from app.features.behavioral import BehavioralFeatureExtractor
from app.features.graph import GraphFeatureExtractor
from app.policy.client import SpiceDBClient


class FeatureExtractor:
    """Unified extractor producing combined FeatureVector payloads for the Trust Engine."""

    def __init__(
        self,
        spicedb_client: SpiceDBClient | None = None,
        redis_client: Any = None,
    ) -> None:
        """Initialize both behavioral and graph feature extractors."""
        self.behavioral_extractor = BehavioralFeatureExtractor(redis_client=redis_client)
        self.graph_extractor = GraphFeatureExtractor(
            spicedb_client=spicedb_client,
            redis_client=redis_client,
        )

    def extract_features(
        self,
        context: RequestContext,
        record_history: bool = True,
    ) -> FeatureVector:
        """Extract all behavioral and graph features for a request context.

        Args:
            context: Request context metadata.
            record_history: Whether to update historical path records in Redis.

        Returns:
            FeatureVector: Combined feature payload.
        """
        behavioral_feats = self.behavioral_extractor.extract(context)
        graph_feats = self.graph_extractor.extract(context, record_history=record_history)
        return FeatureVector(behavioral=behavioral_feats, graph=graph_feats)


__all__ = [
    "BehavioralFeatureExtractor",
    "FeatureExtractor",
    "GraphFeatureExtractor",
]
