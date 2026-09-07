"""Decision Engine mapping trust score bands to gateway responses and policy feedback."""

import logging
from dataclasses import dataclass

from app.common.schemas import DecisionAction, DecisionResult, RequestContext, TrustScore
from app.policy.client import SpiceDBClient, get_spicedb_client

logger = logging.getLogger(__name__)


@dataclass
class DecisionThresholds:
    """Configurable thresholds for mapping trust score bands to actions."""

    allow_threshold: float = 0.75
    step_up_threshold: float = 0.50
    narrow_threshold: float = 0.25


class DecisionEngine:
    """Evaluates policy state and trust score to decide allow, step_up, narrow, or deny."""

    def __init__(
        self,
        spicedb_client: SpiceDBClient | None = None,
        thresholds: DecisionThresholds | None = None,
    ) -> None:
        """Initialize DecisionEngine with SpiceDB client and score-band thresholds.

        Args:
            spicedb_client: Injected SpiceDB client instance for closed-loop write-back.
            thresholds: Custom threshold bands if overriding defaults.
        """
        self.spicedb_client = spicedb_client or get_spicedb_client()
        self.thresholds = thresholds or DecisionThresholds()

    def evaluate_decision(
        self,
        policy_allowed: bool,
        trust_score: TrustScore,
        context: RequestContext,
    ) -> DecisionResult:
        """Map trust score and policy check result to an actionable gateway decision.

        Actions:
            - DENY: Policy check failed or trust score < narrow_threshold (0.25).
            - NARROW: Trust score in [0.25, 0.50). Writes a temporary `restricted` relation
                      back into SpiceDB (closed-loop policy feedback) to quarantine access.
            - STEP_UP: Trust score in [0.50, 0.75). Prompts for multi-factor re-authentication.
            - ALLOW: Trust score >= allow_threshold (0.75). Access granted.

        Args:
            policy_allowed: Result of the initial ReBAC permission check.
            trust_score: Evaluated continuous trust score.
            context: Request context metadata.

        Returns:
            DecisionResult: Final decision record with action, reason, and feedback flags.
        """
        now = context.timestamp

        # 1. Base ReBAC check failure
        if not policy_allowed:
            return DecisionResult(
                action=DecisionAction.DENY,
                reason="ReBAC authorization check failed: subject lacks required permission",
                trust_score=trust_score,
                policy_allowed=False,
                narrow_applied=False,
                challenge_required=False,
                context=context,
                timestamp=now,
            )

        score = trust_score.score

        # 2. Allow band
        if score >= self.thresholds.allow_threshold:
            return DecisionResult(
                action=DecisionAction.ALLOW,
                reason=f"Trust score ({score:.2f}) meets allow threshold",
                trust_score=trust_score,
                policy_allowed=True,
                narrow_applied=False,
                challenge_required=False,
                context=context,
                timestamp=now,
            )

        # 3. Step-Up band
        if score >= self.thresholds.step_up_threshold:
            return DecisionResult(
                action=DecisionAction.STEP_UP,
                reason=f"Trust score ({score:.2f}) degraded: step-up MFA challenge required",
                trust_score=trust_score,
                policy_allowed=True,
                narrow_applied=False,
                challenge_required=True,
                context=context,
                timestamp=now,
            )

        # 4. Narrow band (Closed-Loop Feedback write-back to SpiceDB)
        if score >= self.thresholds.narrow_threshold:
            logger.warning(
                "Anomalous trust (%s) for session %s on %s - applying closed-loop narrow",
                score,
                context.session_id,
                context.resource,
            )
            try:
                self.spicedb_client.narrow_access(
                    subject=context.subject,
                    resource=context.resource,
                )
                narrow_applied = True
            except Exception as exc:
                logger.error("Failed to write narrow relation into SpiceDB: %s", exc)
                narrow_applied = False

            return DecisionResult(
                action=DecisionAction.NARROW,
                reason=(
                    f"Trust score ({score:.2f}) indicates anomaly: "
                    "closed-loop access narrowing restriction applied in ReBAC store"
                ),
                trust_score=trust_score,
                policy_allowed=True,
                narrow_applied=narrow_applied,
                challenge_required=False,
                context=context,
                timestamp=now,
            )

        # 5. Deny band (Severe Trust Collapse)
        return DecisionResult(
            action=DecisionAction.DENY,
            reason=f"Severe trust score collapse ({score:.2f}): request blocked",
            trust_score=trust_score,
            policy_allowed=True,
            narrow_applied=False,
            challenge_required=False,
            context=context,
            timestamp=now,
        )
