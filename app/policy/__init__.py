"""Policy module: ReBAC client, SpiceDB schema, and policy checks."""

from app.policy.client import (
    SpiceDBClient,
    check_access,
    expand_path,
    get_spicedb_client,
)

__all__ = [
    "SpiceDBClient",
    "check_access",
    "expand_path",
    "get_spicedb_client",
]
