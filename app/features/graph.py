"""Graph-structural feature extraction: traversal, novelty, and shortcut detection."""

import logging
from typing import Any

import redis

from app.common.config import settings
from app.common.schemas import GraphFeatures, RequestContext
from app.policy.client import SpiceDBClient, get_spicedb_client

logger = logging.getLogger(__name__)


class GraphFeatureExtractor:
    """Extracts structural features from ReBAC relationship paths using SpiceDB and Redis."""

    def __init__(
        self,
        spicedb_client: SpiceDBClient | None = None,
        redis_client: Any = None,
    ) -> None:
        """Initialize extractor with SpiceDB and Redis clients.

        Args:
            spicedb_client: Injected SpiceDB client instance.
            redis_client: Injected Redis client instance.
        """
        self._spicedb = spicedb_client or get_spicedb_client()
        if redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    def extract(
        self,
        context: RequestContext,
        record_history: bool = True,
    ) -> GraphFeatures:
        """Extract graph-structural features for a given access context.

        Args:
            context: Request context containing subject, resource, and permission.
            record_history: Whether to add newly discovered paths to user's history in Redis.

        Returns:
            GraphFeatures: Extracted structural metrics.
        """
        paths = self._spicedb.expand_path(
            subject=context.subject,
            resource=context.resource,
            permission=context.permission,
        )

        if not paths:
            # No valid relationship path found
            return GraphFeatures(
                hop_count=-1,
                path_novelty_score=1.0,
                privilege_shortcut_flag=0.0,
                traversal_path_signature="",
            )

        # Primary path is the shortest hop count path
        primary_path = paths[0]
        hop_count = primary_path.hop_count
        path_nodes = primary_path.to_string_path()
        signature = "->".join(path_nodes)

        # 1. Path Novelty Check
        novelty_score = self._check_path_novelty(
            subject_key=context.subject.to_string(),
            signature=signature,
            record=record_history,
        )

        # 2. Privilege Escalation Shortcut Check
        # A shortcut occurs when a direct single-hop relation is used for a resource
        # where multi-hop organizational/team paths exist or direct role assignment is unusual
        shortcut_flag = 0.0
        if hop_count == 1 and len(paths) > 1:
            # Multiple paths exist, but accessed via a direct single-hop override
            has_team_path = any(p.hop_count > 1 for p in paths)
            if has_team_path:
                shortcut_flag = 1.0

        return GraphFeatures(
            hop_count=hop_count,
            path_novelty_score=novelty_score,
            privilege_shortcut_flag=shortcut_flag,
            traversal_path_signature=signature,
        )

    def _check_path_novelty(
        self,
        subject_key: str,
        signature: str,
        record: bool,
    ) -> float:
        """Check if path signature is novel for the subject using Redis set."""
        history_key = f"user:{subject_key}:known_paths"
        try:
            is_known = bool(self._redis.sismember(history_key, signature))
            if not is_known:
                if record:
                    self._redis.sadd(history_key, signature)
                return 1.0
            return 0.0
        except Exception as exc:
            logger.warning("Failed checking path novelty in Redis: %s", exc)
            return 0.0
