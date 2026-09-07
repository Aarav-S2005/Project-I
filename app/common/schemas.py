"""Common Pydantic schemas for data crossing module boundaries."""

from typing import Any, ClassVar, Self

from pydantic import BaseModel, Field


class Subject(BaseModel):
    """Represents a subject in the ReBAC model (e.g. user:alice or team:eng#member)."""

    type: str = Field(..., description="Subject type, e.g. 'user' or 'team'")
    id: str = Field(..., description="Subject identifier, e.g. 'alice' or 'eng'")
    relation: str | None = Field(
        default=None,
        description="Optional relation for subject sets, e.g. 'member' in team:eng#member",
    )

    @classmethod
    def from_string(cls, raw: str) -> Self:
        """Parse a string into a Subject model.

        Examples:
            'user:alice' -> Subject(type='user', id='alice', relation=None)
            'team:eng#member' -> Subject(type='team', id='eng', relation='member')
        """
        raw = raw.strip()
        relation = None
        if "#" in raw:
            raw, relation = raw.split("#", 1)
        if ":" in raw:
            obj_type, obj_id = raw.split(":", 1)
        else:
            obj_type, obj_id = "user", raw
        return cls(type=obj_type, id=obj_id, relation=relation)

    def to_string(self) -> str:
        """Convert subject to standard string representation."""
        base = f"{self.type}:{self.id}"
        if self.relation:
            return f"{base}#{self.relation}"
        return base

    def __str__(self) -> str:
        return self.to_string()


class Resource(BaseModel):
    """Represents a resource in the ReBAC model (e.g. document:doc123)."""

    type: str = Field(..., description="Resource type, e.g. 'document' or 'team'")
    id: str = Field(..., description="Resource identifier, e.g. 'doc123' or 'eng'")

    @classmethod
    def from_string(cls, raw: str) -> Self:
        """Parse a string into a Resource model.

        Examples:
            'document:doc123' -> Resource(type='document', id='doc123')
            'team:eng' -> Resource(type='team', id='eng')
        """
        raw = raw.strip()
        if ":" in raw:
            obj_type, obj_id = raw.split(":", 1)
        else:
            obj_type, obj_id = "document", raw
        return cls(type=obj_type, id=obj_id)

    def to_string(self) -> str:
        """Convert resource to standard string representation."""
        return f"{self.type}:{self.id}"

    def __str__(self) -> str:
        return self.to_string()


class AccessCheckRequest(BaseModel):
    """Request payload for an access check."""

    subject: Subject
    relation: str = Field(..., description="Permission or relation name to verify, e.g. 'view'")
    resource: Resource


class AccessCheckResult(BaseModel):
    """Result of an access check evaluated by the policy engine."""

    allowed: bool
    subject: Subject
    relation: str
    resource: Resource


class GraphNode(BaseModel):
    """A node in a ReBAC authorization relationship path."""

    type: str
    id: str
    relation: str | None = None

    def to_string(self) -> str:
        """Convert node to standard string representation."""
        base = f"{self.type}:{self.id}"
        if self.relation:
            return f"{base}#{self.relation}"
        return base

    def __str__(self) -> str:
        return self.to_string()


class GraphPath(BaseModel):
    """Represents a path in the ReBAC graph from a subject to a target resource."""

    nodes: list[GraphNode] = Field(
        default_factory=list,
        description="Sequence of nodes from subject to resource or vice-versa",
    )
    hop_count: int = Field(0, description="Total relationship hops traversed")

    def to_string_path(self) -> list[str]:
        """Return path as list of string node representations."""
        return [node.to_string() for node in self.nodes]


class RelationshipTuple(BaseModel):
    """Represents a relationship tuple in SpiceDB."""

    resource: Resource
    relation: str
    subject: Subject


class RequestContext(BaseModel):
    """Contextual metadata captured for an incoming API request."""

    session_id: str
    subject: Subject
    resource: Resource
    permission: str = "view"
    ip_address: str = "127.0.0.1"
    latitude: float | None = None
    longitude: float | None = None
    timestamp: float = Field(
        ...,
        description="Unix timestamp (in seconds) when the request was received",
    )
    user_agent: str = "Unknown"
    device_id: str | None = None


class BehavioralFeatures(BaseModel):
    """Behavioral feature stream extracted from rolling request patterns."""

    request_rate_1m: float = Field(
        0.0, description="Number of requests in the last 1-minute window"
    )
    request_rate_5m: float = Field(
        0.0, description="Number of requests in the last 5-minute window"
    )
    geo_velocity_kmh: float = Field(
        0.0,
        description="Calculated travel speed (km/h) since last request location",
    )
    device_fingerprint_mismatch: float = Field(
        0.0,
        description="1.0 if device/user-agent deviates from session baseline, else 0.0",
    )
    time_of_day_deviation: float = Field(
        0.0,
        description="Normalized deviation score (0.0-1.0) from typical operating hours",
    )


class GraphFeatures(BaseModel):
    """Graph-structural feature stream extracted from ReBAC traversal."""

    hop_count: int = Field(0, description="Shortest relationship path hop count")
    path_novelty_score: float = Field(
        0.0,
        description="1.0 if relationship path is novel for subject, else 0.0",
    )
    privilege_shortcut_flag: float = Field(
        0.0,
        description="1.0 if request bypasses usual team hierarchy, else 0.0",
    )
    traversal_path_signature: str = Field(
        "",
        description="String signature of the traversed path (e.g. 'user:a->team:t#member->doc:d')",
    )


class FeatureVector(BaseModel):
    """Combined feature vector consumed by the anomaly detection / trust engine."""

    FEATURE_NAMES: ClassVar[list[str]] = [
        "request_rate_1m",
        "request_rate_5m",
        "geo_velocity_kmh",
        "device_fingerprint_mismatch",
        "time_of_day_deviation",
        "hop_count",
        "path_novelty_score",
        "privilege_shortcut_flag",
    ]

    behavioral: BehavioralFeatures
    graph: GraphFeatures

    def to_feature_list(self) -> list[float]:
        """Convert feature streams to an ordered list of numeric values."""
        return [
            float(self.behavioral.request_rate_1m),
            float(self.behavioral.request_rate_5m),
            float(self.behavioral.geo_velocity_kmh),
            float(self.behavioral.device_fingerprint_mismatch),
            float(self.behavioral.time_of_day_deviation),
            float(self.graph.hop_count),
            float(self.graph.path_novelty_score),
            float(self.graph.privilege_shortcut_flag),
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary keyed by standard feature names."""
        values = self.to_feature_list()
        return dict(zip(self.FEATURE_NAMES, values, strict=True))


class TrustScore(BaseModel):
    """Continuous, decaying trust score evaluated across a session."""

    score: float = Field(..., description="Current trust score between 0.0 and 1.0")
    previous_score: float = Field(..., description="Previous trust score prior to evaluation")
    raw_anomaly_score: float = Field(
        ..., description="Raw anomaly probability/severity score (0.0=normal, 1.0=anomaly)"
    )
    decay_amount: float = Field(0.0, description="Amount deducted due to anomalous behavior")
    recovery_amount: float = Field(0.0, description="Amount restored due to normal behavior")
    session_id: str = Field(..., description="Active session identifier")
    timestamp: float = Field(..., description="Timestamp of evaluation")


class DecisionAction(str):
    """Possible response actions decided by the Decision Engine."""

    ALLOW = "allow"
    STEP_UP = "step_up"
    NARROW = "narrow"
    DENY = "deny"


class DecisionResult(BaseModel):
    """Final decision output mapping trust band to gateway response and policy feedback."""

    action: str = Field(..., description="Decision action: allow, step_up, narrow, or deny")
    reason: str = Field(..., description="Human-readable rationale for the decision")
    trust_score: TrustScore
    policy_allowed: bool = Field(..., description="Whether initial ReBAC check passed")
    narrow_applied: bool = Field(
        default=False,
        description="Whether a closed-loop restriction was written into SpiceDB",
    )
    challenge_required: bool = Field(
        default=False,
        description="Whether step-up authentication (MFA) challenge is required",
    )
    context: RequestContext
    timestamp: float


class FeatureAttribution(BaseModel):
    """Feature-level explainability attribution (e.g. SHAP value)."""

    feature_name: str = Field(..., description="Name of the evaluated feature")
    feature_value: float = Field(..., description="Observed numeric value of the feature")
    shap_value: float = Field(
        ...,
        description="Raw SHAP value (negative indicates anomalous pull in IsolationForest)",
    )
    contribution_score: float = Field(
        ...,
        description="Normalized anomaly contribution magnitude (0.0=benign, 1.0=primary driver)",
    )
    direction: str = Field(
        ...,
        description="'anomalous' if pushing towards threat, 'benign' if supporting normal behavior",
    )


class AuditRecord(BaseModel):
    """Immutable audit record logging access decision with full feature-level attribution."""

    record_id: str = Field(..., description="Unique audit record UUID")
    session_id: str = Field(..., description="Session identifier")
    timestamp: float = Field(..., description="Unix timestamp of decision")
    decision: DecisionResult = Field(..., description="Decision Engine evaluation result")
    feature_vector: FeatureVector = Field(..., description="Extracted feature vector")
    attributions: list[FeatureAttribution] = Field(
        default_factory=list,
        description="SHAP feature attributions ranked by influence",
    )
    top_anomaly_drivers: list[str] = Field(
        default_factory=list,
        description="Top features driving anomaly score and trust decay",
    )
