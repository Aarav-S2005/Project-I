"""SpiceDB ReBAC client wrapper for access checks, path expansion, and policy management."""

import logging
from collections.abc import Sequence
from typing import Any

from authzed.api.v1 import (
    CheckPermissionRequest,
    CheckPermissionResponse,
    Consistency,
    ExpandPermissionTreeRequest,
    ExpandPermissionTreeResponse,
    InsecureClient,
    ObjectReference,
    PermissionRelationshipTree,
    Relationship,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
    WriteSchemaRequest,
)

from app.common.config import settings
from app.common.schemas import GraphNode, GraphPath, RelationshipTuple, Resource, Subject

logger = logging.getLogger(__name__)


def _normalize_subject(subject: str | Subject) -> Subject:
    """Ensure subject is a Subject instance."""
    if isinstance(subject, str):
        return Subject.from_string(subject)
    return subject


def _normalize_resource(resource: str | Resource) -> Resource:
    """Ensure resource is a Resource instance."""
    if isinstance(resource, str):
        return Resource.from_string(resource)
    return resource


class SpiceDBClient:
    """Client wrapper for interacting with SpiceDB ReBAC service."""

    def __init__(
        self,
        endpoint: str | None = None,
        preshared_key: str | None = None,
        insecure: bool | None = None,
        client: Any = None,
    ) -> None:
        """Initialize SpiceDB client connection.

        Args:
            endpoint: SpiceDB gRPC host and port (e.g. 'localhost:50051').
            preshared_key: Pre-shared key for authentication.
            insecure: Whether to connect without TLS encryption.
            client: Optional injected authzed client instance (useful for mocking).
        """
        self.endpoint = endpoint or settings.spicedb_endpoint
        self.preshared_key = preshared_key or settings.spicedb_preshared_key
        self.insecure = insecure if insecure is not None else settings.spicedb_insecure

        if client is not None:
            self._client = client
        else:
            self._client = InsecureClient(
                target=self.endpoint,
                token=self.preshared_key,
            )

    @property
    def client(self) -> Any:
        """Get the underlying authzed client."""
        return self._client

    def _call_write_schema(self, request: WriteSchemaRequest) -> Any:
        """Call WriteSchema on either direct client or schema_service stub."""
        if hasattr(self._client, "schema_service"):
            return self._client.schema_service.WriteSchema(request)
        return self._client.WriteSchema(request)

    def _call_write_relationships(self, request: WriteRelationshipsRequest) -> Any:
        """Call WriteRelationships on either direct client or permissions_service stub."""
        if hasattr(self._client, "permissions_service"):
            return self._client.permissions_service.WriteRelationships(request)
        return self._client.WriteRelationships(request)

    def _call_check_permission(self, request: CheckPermissionRequest) -> CheckPermissionResponse:
        """Call CheckPermission on either direct client or permissions_service stub."""
        if hasattr(self._client, "permissions_service"):
            return self._client.permissions_service.CheckPermission(request)  # type: ignore[no-any-return]
        return self._client.CheckPermission(request)  # type: ignore[no-any-return]

    def _call_expand_permission_tree(
        self, request: ExpandPermissionTreeRequest
    ) -> ExpandPermissionTreeResponse:
        """Call ExpandPermissionTree on either direct client or permissions_service stub."""
        if hasattr(self._client, "permissions_service"):
            return self._client.permissions_service.ExpandPermissionTree(request)  # type: ignore[no-any-return]
        return self._client.ExpandPermissionTree(request)  # type: ignore[no-any-return]

    def write_schema(self, schema_text: str) -> None:
        """Write and apply a Zed schema definition in SpiceDB.

        Args:
            schema_text: Full Zed schema definition string.
        """
        request = WriteSchemaRequest(schema=schema_text)
        self._call_write_schema(request)

    def write_relationships(self, relationships: Sequence[RelationshipTuple]) -> None:
        """Create or touch relationship tuples in SpiceDB.

        Args:
            relationships: List of RelationshipTuple objects to write.
        """
        updates = [
            RelationshipUpdate(
                operation=RelationshipUpdate.Operation.OPERATION_TOUCH,
                relationship=Relationship(
                    resource=ObjectReference(
                        object_type=rel.resource.type,
                        object_id=rel.resource.id,
                    ),
                    relation=rel.relation,
                    subject=SubjectReference(
                        object=ObjectReference(
                            object_type=rel.subject.type,
                            object_id=rel.subject.id,
                        ),
                        optional_relation=rel.subject.relation or "",
                    ),
                ),
            )
            for rel in relationships
        ]
        request = WriteRelationshipsRequest(updates=updates)
        self._call_write_relationships(request)

    def delete_relationships(self, relationships: Sequence[RelationshipTuple]) -> None:
        """Delete relationship tuples in SpiceDB.

        Args:
            relationships: List of RelationshipTuple objects to delete.
        """
        updates = [
            RelationshipUpdate(
                operation=RelationshipUpdate.Operation.OPERATION_DELETE,
                relationship=Relationship(
                    resource=ObjectReference(
                        object_type=rel.resource.type,
                        object_id=rel.resource.id,
                    ),
                    relation=rel.relation,
                    subject=SubjectReference(
                        object=ObjectReference(
                            object_type=rel.subject.type,
                            object_id=rel.subject.id,
                        ),
                        optional_relation=rel.subject.relation or "",
                    ),
                ),
            )
            for rel in relationships
        ]
        request = WriteRelationshipsRequest(updates=updates)
        self._call_write_relationships(request)

    def narrow_access(self, subject: str | Subject, resource: str | Resource) -> None:
        """Write a restricted relationship to temporarily quarantine/narrow access.

        This implements the closed-loop policy feedback mechanism where anomalous
        trust decay triggers an automated write-back into the ReBAC graph.

        Args:
            subject: Target subject to restrict.
            resource: Target resource to restrict access to.
        """
        subj = _normalize_subject(subject)
        res = _normalize_resource(resource)
        self.write_relationships(
            [
                RelationshipTuple(
                    resource=res,
                    relation="restricted",
                    subject=subj,
                )
            ]
        )

    def remove_restriction(self, subject: str | Subject, resource: str | Resource) -> None:
        """Remove a previously applied restricted relationship.

        Args:
            subject: Target subject whose restriction should be removed.
            resource: Target resource.
        """
        subj = _normalize_subject(subject)
        res = _normalize_resource(resource)
        self.delete_relationships(
            [
                RelationshipTuple(
                    resource=res,
                    relation="restricted",
                    subject=subj,
                )
            ]
        )

    def check_access(
        self,
        subject: str | Subject,
        relation: str,
        resource: str | Resource,
    ) -> bool:
        """Check if a subject has a specified permission or relation on a resource.

        Args:
            subject: Subject identifier (string or Subject schema).
            relation: Permission or relation to verify (e.g. 'view', 'edit').
            resource: Resource identifier (string or Resource schema).

        Returns:
            bool: True if access is permitted by ReBAC rules, False otherwise.
        """
        subj = _normalize_subject(subject)
        res = _normalize_resource(resource)

        request = CheckPermissionRequest(
            resource=ObjectReference(
                object_type=res.type,
                object_id=res.id,
            ),
            permission=relation,
            subject=SubjectReference(
                object=ObjectReference(
                    object_type=subj.type,
                    object_id=subj.id,
                ),
                optional_relation=subj.relation or "",
            ),
            consistency=Consistency(fully_consistent=True),
        )

        try:
            response: CheckPermissionResponse = self._call_check_permission(request)
            return (
                response.permissionship
                == CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
            )
        except Exception as exc:
            logger.warning("SpiceDB CheckPermission failed: %s", exc)
            # Default allow in simulation if local docker is not running, or return False
            return False

    def expand_path(
        self,
        subject: str | Subject,
        resource: str | Resource,
        permission: str = "view",
        max_depth: int = 5,
    ) -> list[GraphPath]:
        """Expand the permission tree and extract relationship paths from subject to resource.

        Traverses SpiceDB permission trees and resolves intermediate subject sets
        (such as team memberships) to construct concrete graph traversal paths.

        Args:
            subject: Target subject seeking access.
            resource: Target resource being accessed.
            permission: Permission/relation being evaluated (default: 'view').
            max_depth: Maximum recursion depth for nested subject sets.

        Returns:
            list[GraphPath]: List of valid relationship paths found connecting the subject
                             to the resource, ordered by hop count.
        """
        subj = _normalize_subject(subject)
        res = _normalize_resource(resource)
        visited_resources: set[str] = set()

        paths = self._expand_tree_paths(
            target_subject=subj,
            current_resource=res,
            permission=permission,
            current_depth=0,
            max_depth=max_depth,
            visited_resources=visited_resources,
        )

        # Sort paths by hop count (shortest path first)
        paths.sort(key=lambda p: p.hop_count)
        return paths

    def _expand_tree_paths(
        self,
        target_subject: Subject,
        current_resource: Resource,
        permission: str,
        current_depth: int,
        max_depth: int,
        visited_resources: set[str],
    ) -> list[GraphPath]:
        """Internal recursive helper to traverse tree nodes and build paths."""
        res_key = f"{current_resource.type}:{current_resource.id}#{permission}"
        if res_key in visited_resources or current_depth > max_depth:
            return []

        visited_resources.add(res_key)

        request = ExpandPermissionTreeRequest(
            resource=ObjectReference(
                object_type=current_resource.type,
                object_id=current_resource.id,
            ),
            permission=permission,
            consistency=Consistency(fully_consistent=True),
        )

        try:
            response: ExpandPermissionTreeResponse = self._call_expand_permission_tree(request)
        except Exception as exc:
            logger.warning("ExpandPermissionTree failed for %s: %s", res_key, exc)
            return []

        if not response.tree_root:
            return []

        paths: list[GraphPath] = []
        self._traverse_node(
            tree=response.tree_root,
            target_subject=target_subject,
            current_depth=current_depth,
            max_depth=max_depth,
            visited_resources=visited_resources,
            paths=paths,
        )
        return paths

    def _traverse_node(
        self,
        tree: PermissionRelationshipTree,
        target_subject: Subject,
        current_depth: int,
        max_depth: int,
        visited_resources: set[str],
        paths: list[GraphPath],
    ) -> None:
        """Traverse a PermissionRelationshipTree node (leaf or intermediate)."""
        node_res = (
            Resource(
                type=tree.expanded_object.object_type,
                id=tree.expanded_object.object_id,
            )
            if tree.expanded_object and tree.expanded_object.object_type
            else None
        )
        node_relation = tree.expanded_relation or ""

        # Leaf node check
        if tree.HasField("leaf") and tree.leaf:
            for s_ref in tree.leaf.subjects:
                subj_type = s_ref.object.object_type
                subj_id = s_ref.object.object_id
                subj_rel = s_ref.optional_relation or None

                # Direct match with target subject
                if (
                    subj_type == target_subject.type
                    and subj_id == target_subject.id
                    and (target_subject.relation is None or subj_rel == target_subject.relation)
                ):
                    nodes = [
                        GraphNode(
                            type=target_subject.type,
                            id=target_subject.id,
                            relation=subj_rel,
                        )
                    ]
                    if node_res:
                        nodes.append(
                            GraphNode(
                                type=node_res.type,
                                id=node_res.id,
                                relation=node_relation,
                            )
                        )
                    paths.append(GraphPath(nodes=nodes, hop_count=len(nodes) - 1))

                # Intermediate subject set (e.g. team:eng#member)
                elif subj_rel and current_depth < max_depth:
                    intermediate_res = Resource(type=subj_type, id=subj_id)
                    sub_paths = self._expand_tree_paths(
                        target_subject=target_subject,
                        current_resource=intermediate_res,
                        permission=subj_rel,
                        current_depth=current_depth + 1,
                        max_depth=max_depth,
                        visited_resources=visited_resources,
                    )
                    for sub_path in sub_paths:
                        # Append the current resource hop to the end of the sub-path
                        stitched_nodes = list(sub_path.nodes)
                        if node_res:
                            stitched_nodes.append(
                                GraphNode(
                                    type=node_res.type,
                                    id=node_res.id,
                                    relation=node_relation,
                                )
                            )
                        paths.append(
                            GraphPath(
                                nodes=stitched_nodes,
                                hop_count=len(stitched_nodes) - 1,
                            )
                        )

        # Intermediate node (algebraic union / intersection / exclusion)
        if tree.HasField("intermediate") and tree.intermediate:
            for child in tree.intermediate.children:
                self._traverse_node(
                    tree=child,
                    target_subject=target_subject,
                    current_depth=current_depth,
                    max_depth=max_depth,
                    visited_resources=visited_resources,
                    paths=paths,
                )


_global_client: SpiceDBClient | None = None


def get_spicedb_client() -> SpiceDBClient:
    """Get or create singleton SpiceDB client instance."""
    global _global_client
    if _global_client is None:
        _global_client = SpiceDBClient()
    return _global_client


def check_access(
    subject: str | Subject,
    relation: str,
    resource: str | Resource,
    client: SpiceDBClient | None = None,
) -> bool:
    """Module-level function to check access against SpiceDB.

    Args:
        subject: Subject identifier.
        relation: Permission or relation to verify.
        resource: Resource identifier.
        client: Optional SpiceDBClient instance (defaults to singleton).

    Returns:
        bool: True if allowed, False otherwise.
    """
    cli = client or get_spicedb_client()
    return cli.check_access(subject=subject, relation=relation, resource=resource)


def expand_path(
    subject: str | Subject,
    resource: str | Resource,
    permission: str = "view",
    client: SpiceDBClient | None = None,
) -> list[GraphPath]:
    """Module-level function to expand relationship traversal path in SpiceDB.

    Args:
        subject: Target subject.
        resource: Target resource.
        permission: Permission or relation being checked.
        client: Optional SpiceDBClient instance (defaults to singleton).

    Returns:
        list[GraphPath]: List of discovered relationship paths.
    """
    cli = client or get_spicedb_client()
    return cli.expand_path(subject=subject, resource=resource, permission=permission)
