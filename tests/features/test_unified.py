"""Unit tests for unified FeatureExtractor pipeline."""

from unittest.mock import MagicMock

from app.common.schemas import (
    BehavioralFeatures,
    FeatureVector,
    GraphFeatures,
    RequestContext,
    Resource,
    Subject,
)
from app.features import FeatureExtractor


class TestUnifiedFeatureExtractor:
    """Test unified feature extraction and vector conversions."""

    def test_feature_vector_conversion(self) -> None:
        fv = FeatureVector(
            behavioral=BehavioralFeatures(
                request_rate_1m=3.0,
                request_rate_5m=10.0,
                geo_velocity_kmh=45.5,
                device_fingerprint_mismatch=0.0,
                time_of_day_deviation=0.2,
            ),
            graph=GraphFeatures(
                hop_count=2,
                path_novelty_score=0.0,
                privilege_shortcut_flag=1.0,
                traversal_path_signature="user:alice->team:eng#member->document:doc1#reader",
            ),
        )

        arr = fv.to_feature_list()
        assert len(arr) == 8
        assert arr == [3.0, 10.0, 45.5, 0.0, 0.2, 2.0, 0.0, 1.0]

        d = fv.to_dict()
        assert len(d) == 8
        assert d["request_rate_1m"] == 3.0
        assert d["hop_count"] == 2.0
        assert d["privilege_shortcut_flag"] == 1.0

    def test_unified_extract_pipeline(self) -> None:
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [1, 0, 2, 8, True]
        mock_redis.pipeline.return_value = mock_pipe
        mock_redis.get.return_value = None
        mock_redis.sismember.return_value = 0

        mock_spicedb = MagicMock()
        mock_spicedb.expand_path.return_value = []

        extractor = FeatureExtractor(
            spicedb_client=mock_spicedb,
            redis_client=mock_redis,
        )

        context = RequestContext(
            session_id="sess_unified",
            subject=Subject(type="user", id="bob"),
            resource=Resource(type="document", id="doc99"),
            timestamp=1788789600.0,
        )

        result = extractor.extract_features(context)
        assert isinstance(result, FeatureVector)
        assert result.behavioral.request_rate_1m == 2.0
        assert result.behavioral.request_rate_5m == 8.0
        assert result.graph.hop_count == -1
