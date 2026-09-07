"""Unit tests for graph-structural feature extraction."""

from unittest.mock import MagicMock

import pytest

from app.common.schemas import GraphNode, GraphPath, RequestContext, Resource, Subject
from app.features.graph import GraphFeatureExtractor
from app.policy.client import SpiceDBClient


class TestGraphFeatureExtractor:
    """Test GraphFeatureExtractor with mocked SpiceDBClient and Redis."""

    @pytest.fixture
    def mock_spicedb_client(self) -> MagicMock:
        return MagicMock(spec=SpiceDBClient)

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        mock = MagicMock()
        mock.sismember.return_value = 0
        return mock

    def test_extract_direct_relationship_path(
        self,
        mock_spicedb_client: MagicMock,
        mock_redis: MagicMock,
    ) -> None:
        mock_spicedb_client.expand_path.return_value = [
            GraphPath(
                nodes=[
                    GraphNode(type="user", id="alice"),
                    GraphNode(type="document", id="doc1", relation="reader"),
                ],
                hop_count=1,
            )
        ]

        extractor = GraphFeatureExtractor(
            spicedb_client=mock_spicedb_client,
            redis_client=mock_redis,
        )

        context = RequestContext(
            session_id="sess_1",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,
        )

        features = extractor.extract(context)

        assert features.hop_count == 1
        assert features.path_novelty_score == 1.0  # newly seen path
        assert features.privilege_shortcut_flag == 0.0
        assert features.traversal_path_signature == "user:alice->document:doc1#reader"
        mock_redis.sadd.assert_called_once()

    def test_extract_nested_team_relationship_path(
        self,
        mock_spicedb_client: MagicMock,
        mock_redis: MagicMock,
    ) -> None:
        mock_spicedb_client.expand_path.return_value = [
            GraphPath(
                nodes=[
                    GraphNode(type="user", id="alice"),
                    GraphNode(type="team", id="eng", relation="member"),
                    GraphNode(type="document", id="doc1", relation="reader"),
                ],
                hop_count=2,
            )
        ]
        # Simulate previously seen path
        mock_redis.sismember.return_value = 1

        extractor = GraphFeatureExtractor(
            spicedb_client=mock_spicedb_client,
            redis_client=mock_redis,
        )

        context = RequestContext(
            session_id="sess_1",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,
        )

        features = extractor.extract(context)

        assert features.hop_count == 2
        assert features.path_novelty_score == 0.0  # previously seen
        assert features.privilege_shortcut_flag == 0.0

    def test_detect_privilege_shortcut(
        self,
        mock_spicedb_client: MagicMock,
        mock_redis: MagicMock,
    ) -> None:
        # Multiple paths available: direct single-hop reader and multi-hop team path
        path_direct = GraphPath(
            nodes=[
                GraphNode(type="user", id="alice"),
                GraphNode(type="document", id="doc1", relation="writer"),
            ],
            hop_count=1,
        )
        path_team = GraphPath(
            nodes=[
                GraphNode(type="user", id="alice"),
                GraphNode(type="team", id="eng", relation="member"),
                GraphNode(type="document", id="doc1", relation="reader"),
            ],
            hop_count=2,
        )
        mock_spicedb_client.expand_path.return_value = [path_direct, path_team]

        extractor = GraphFeatureExtractor(
            spicedb_client=mock_spicedb_client,
            redis_client=mock_redis,
        )

        context = RequestContext(
            session_id="sess_1",
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,
        )

        features = extractor.extract(context)

        assert features.hop_count == 1
        assert features.privilege_shortcut_flag == 1.0  # Detected direct shortcut bypass

    def test_no_relationship_path_found(
        self,
        mock_spicedb_client: MagicMock,
        mock_redis: MagicMock,
    ) -> None:
        mock_spicedb_client.expand_path.return_value = []

        extractor = GraphFeatureExtractor(
            spicedb_client=mock_spicedb_client,
            redis_client=mock_redis,
        )

        context = RequestContext(
            session_id="sess_1",
            subject=Subject(type="user", id="unauthorized_user"),
            resource=Resource(type="document", id="doc1"),
            timestamp=1788789600.0,
        )

        features = extractor.extract(context)

        assert features.hop_count == -1
        assert features.path_novelty_score == 1.0
        assert features.privilege_shortcut_flag == 0.0
        assert features.traversal_path_signature == ""
