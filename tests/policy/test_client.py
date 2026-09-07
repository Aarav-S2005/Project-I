"""Unit tests for the SpiceDB policy client wrapper."""

from unittest.mock import MagicMock

import pytest
from authzed.api.v1 import (
    AlgebraicSubjectSet,
    CheckPermissionRequest,
    CheckPermissionResponse,
    DirectSubjectSet,
    ExpandPermissionTreeRequest,
    ExpandPermissionTreeResponse,
    ObjectReference,
    PermissionRelationshipTree,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
    WriteSchemaRequest,
)

from app.common.schemas import RelationshipTuple, Resource, Subject
from app.policy.client import (
    SpiceDBClient,
    _normalize_resource,
    _normalize_subject,
    check_access,
    expand_path,
)


@pytest.fixture
def mock_authzed_client() -> MagicMock:
    """Create a mock authzed client with permissions and schema service stubs."""
    mock = MagicMock()
    mock.permissions_service = MagicMock()
    mock.schema_service = MagicMock()
    return mock


@pytest.fixture
def policy_client(mock_authzed_client: MagicMock) -> SpiceDBClient:
    """Create a SpiceDBClient instance using the mocked authzed client."""
    return SpiceDBClient(client=mock_authzed_client)


class TestSchemaAndNormalizers:
    """Test normalization and basic model helper methods."""

    def test_normalize_subject_string(self) -> None:
        subj = _normalize_subject("user:alice")
        assert subj.type == "user"
        assert subj.id == "alice"
        assert subj.relation is None

        subj_with_rel = _normalize_subject("team:eng#member")
        assert subj_with_rel.type == "team"
        assert subj_with_rel.id == "eng"
        assert subj_with_rel.relation == "member"

    def test_normalize_resource_string(self) -> None:
        res = _normalize_resource("document:doc123")
        assert res.type == "document"
        assert res.id == "doc123"

    def test_subject_to_string(self) -> None:
        s1 = Subject(type="user", id="bob")
        assert s1.to_string() == "user:bob"
        assert str(s1) == "user:bob"

        s2 = Subject(type="team", id="security", relation="admin")
        assert s2.to_string() == "team:security#admin"
        assert str(s2) == "team:security#admin"

    def test_resource_to_string(self) -> None:
        r = Resource(type="document", id="financials")
        assert r.to_string() == "document:financials"
        assert str(r) == "document:financials"


class TestCheckAccess:
    """Test check_access function and SpiceDBClient.check_access."""

    def test_check_access_allowed(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        mock_authzed_client.permissions_service.CheckPermission.return_value = (
            CheckPermissionResponse(
                permissionship=CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
            )
        )

        result = policy_client.check_access(
            subject="user:alice",
            relation="view",
            resource="document:doc1",
        )

        assert result is True
        mock_authzed_client.permissions_service.CheckPermission.assert_called_once()
        req: CheckPermissionRequest = (
            mock_authzed_client.permissions_service.CheckPermission.call_args[0][0]
        )
        assert req.resource.object_type == "document"
        assert req.resource.object_id == "doc1"
        assert req.permission == "view"
        assert req.subject.object.object_type == "user"
        assert req.subject.object.object_id == "alice"

    def test_check_access_denied(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        mock_authzed_client.permissions_service.CheckPermission.return_value = (
            CheckPermissionResponse(
                permissionship=CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION
            )
        )

        result = policy_client.check_access(
            subject=Subject(type="user", id="mallory"),
            relation="edit",
            resource=Resource(type="document", id="doc1"),
        )

        assert result is False

    def test_module_level_check_access(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        mock_authzed_client.permissions_service.CheckPermission.return_value = (
            CheckPermissionResponse(
                permissionship=CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
            )
        )

        result = check_access(
            subject="user:alice",
            relation="view",
            resource="document:doc1",
            client=policy_client,
        )
        assert result is True


class TestExpandPath:
    """Test expand_path function and SpiceDBClient.expand_path."""

    def test_expand_path_direct_leaf(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        tree = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="reader",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="alice"),
                    ),
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="bob"),
                    ),
                ]
            ),
        )
        mock_authzed_client.permissions_service.ExpandPermissionTree.return_value = (
            ExpandPermissionTreeResponse(tree_root=tree)
        )

        paths = policy_client.expand_path(
            subject="user:alice",
            resource="document:doc1",
            permission="view",
        )

        assert len(paths) == 1
        assert paths[0].hop_count == 1
        assert paths[0].to_string_path() == ["user:alice", "document:doc1#reader"]

    def test_expand_path_nested_team_membership(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        # First tree: document:doc1 has team:eng#member as reader
        doc_tree = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="reader",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="team", object_id="eng"),
                        optional_relation="member",
                    )
                ]
            ),
        )

        # Second tree: team:eng has user:alice as member
        team_tree = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="team", object_id="eng"),
            expanded_relation="member",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="alice"),
                    )
                ]
            ),
        )

        def expand_side_effect(
            request: ExpandPermissionTreeRequest,
        ) -> ExpandPermissionTreeResponse:
            if request.resource.object_type == "document":
                return ExpandPermissionTreeResponse(tree_root=doc_tree)
            elif request.resource.object_type == "team":
                return ExpandPermissionTreeResponse(tree_root=team_tree)
            return ExpandPermissionTreeResponse()

        mock_authzed_client.permissions_service.ExpandPermissionTree.side_effect = (
            expand_side_effect
        )

        paths = expand_path(
            subject="user:alice",
            resource="document:doc1",
            permission="view",
            client=policy_client,
        )

        assert len(paths) == 1
        assert paths[0].hop_count == 2
        assert paths[0].to_string_path() == [
            "user:alice",
            "team:eng#member",
            "document:doc1#reader",
        ]

    def test_expand_path_intermediate_algebraic_nodes(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        child1 = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="reader",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="bob"),
                    )
                ]
            ),
        )
        child2 = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="writer",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="alice"),
                    )
                ]
            ),
        )
        root_tree = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="view",
            intermediate=AlgebraicSubjectSet(
                operation=AlgebraicSubjectSet.Operation.OPERATION_UNION,
                children=[child1, child2],
            ),
        )
        mock_authzed_client.permissions_service.ExpandPermissionTree.return_value = (
            ExpandPermissionTreeResponse(tree_root=root_tree)
        )

        paths = policy_client.expand_path(
            subject="user:alice",
            resource="document:doc1",
            permission="view",
        )

        assert len(paths) == 1
        assert paths[0].hop_count == 1
        assert paths[0].to_string_path() == ["user:alice", "document:doc1#writer"]

    def test_expand_path_not_found(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        tree = PermissionRelationshipTree(
            expanded_object=ObjectReference(object_type="document", object_id="doc1"),
            expanded_relation="reader",
            leaf=DirectSubjectSet(
                subjects=[
                    SubjectReference(
                        object=ObjectReference(object_type="user", object_id="bob"),
                    )
                ]
            ),
        )
        mock_authzed_client.permissions_service.ExpandPermissionTree.return_value = (
            ExpandPermissionTreeResponse(tree_root=tree)
        )

        paths = policy_client.expand_path(
            subject="user:charlie",
            resource="document:doc1",
            permission="view",
        )

        assert paths == []


class TestPolicyManagementAndNarrow:
    """Test schema write and closed-loop narrow/feedback methods."""

    def test_write_schema(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        schema_text = "definition user {}\ndefinition document {}"
        policy_client.write_schema(schema_text)

        mock_authzed_client.schema_service.WriteSchema.assert_called_once()
        req: WriteSchemaRequest = mock_authzed_client.schema_service.WriteSchema.call_args[0][0]
        assert req.schema == schema_text

    def test_write_relationships(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        rels = [
            RelationshipTuple(
                resource=Resource(type="document", id="doc1"),
                relation="reader",
                subject=Subject(type="user", id="alice"),
            )
        ]
        policy_client.write_relationships(rels)

        mock_authzed_client.permissions_service.WriteRelationships.assert_called_once()
        req: WriteRelationshipsRequest = (
            mock_authzed_client.permissions_service.WriteRelationships.call_args[0][0]
        )
        assert len(req.updates) == 1
        assert req.updates[0].operation == RelationshipUpdate.Operation.OPERATION_TOUCH
        assert req.updates[0].relationship.resource.object_type == "document"
        assert req.updates[0].relationship.resource.object_id == "doc1"
        assert req.updates[0].relationship.relation == "reader"
        assert req.updates[0].relationship.subject.object.object_id == "alice"

    def test_narrow_access(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        policy_client.narrow_access(
            subject="user:alice",
            resource="document:doc1",
        )

        mock_authzed_client.permissions_service.WriteRelationships.assert_called_once()
        req: WriteRelationshipsRequest = (
            mock_authzed_client.permissions_service.WriteRelationships.call_args[0][0]
        )
        assert len(req.updates) == 1
        assert req.updates[0].operation == RelationshipUpdate.Operation.OPERATION_TOUCH
        assert req.updates[0].relationship.relation == "restricted"
        assert req.updates[0].relationship.subject.object.object_id == "alice"

    def test_remove_restriction(
        self, policy_client: SpiceDBClient, mock_authzed_client: MagicMock
    ) -> None:
        policy_client.remove_restriction(
            subject="user:alice",
            resource="document:doc1",
        )

        mock_authzed_client.permissions_service.WriteRelationships.assert_called_once()
        req: WriteRelationshipsRequest = (
            mock_authzed_client.permissions_service.WriteRelationships.call_args[0][0]
        )
        assert len(req.updates) == 1
        assert req.updates[0].operation == RelationshipUpdate.Operation.OPERATION_DELETE
        assert req.updates[0].relationship.relation == "restricted"
