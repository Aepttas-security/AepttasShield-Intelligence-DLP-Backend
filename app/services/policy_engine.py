from dataclasses import dataclass

from app.models.policy import Policy
from app.models.dlp_event import DLPEvent


@dataclass
class PolicyDecision:

    policy_id: int | None

    policy_name: str

    action: str

    matched: bool

    reason: str


def normalize(value: str | None) -> str:

    if value is None:
        return ""

    return (
        value
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def policy_matches_event(
    policy: Policy,
    event: DLPEvent,
) -> bool:

    # Data classification
    if normalize(policy.data_classification) not in (
        "",
        "*",
        normalize(event.data_classification),
    ):
        return False

    # Channel
    if normalize(policy.channel) not in (
        "",
        "*",
        normalize(event.channel),
    ):
        return False

    # Destination
    if policy.destination_type:

        if normalize(policy.destination_type) not in (
            "*",
            normalize(event.destination),
        ):
            return False

    # Severity
    if policy.severity:

        if normalize(policy.severity) not in (
            "*",
            normalize(event.severity),
        ):
            return False

    # Volume condition
    if (
        policy.minimum_volume is not None
        and event.volume is not None
        and event.volume < policy.minimum_volume
    ):
        return False

    return True


def calculate_specificity(
    policy: Policy
) -> int:

    score = 0

    if policy.data_classification:
        score += 1

    if policy.channel:
        score += 1

    if policy.destination_type:
        score += 1

    if policy.severity:
        score += 1

    if policy.minimum_volume:
        score += 1

    if policy.required_device_trust:
        score += 1

    return score


def evaluate_policy(
    event: DLPEvent,
    policies: list[Policy],
) -> PolicyDecision:

    matching_policies = []

    for policy in policies:

        if not policy.is_active:
            continue

        if policy_matches_event(
            policy,
            event
        ):
            matching_policies.append(policy)

    if not matching_policies:

        return PolicyDecision(
            policy_id=None,
            policy_name="NO_MATCHING_POLICY",
            action="MONITOR",
            matched=False,
            reason="No active policy matched the DLP event.",
        )

    # Most specific policy first.
    # If specificity is equal, priority decides.
    matching_policies.sort(
        key=lambda p: (
            calculate_specificity(p),
            -(p.priority or 100)
        ),
        reverse=True
    )

    selected = matching_policies[0]

    return PolicyDecision(
        policy_id=selected.id,
        policy_name=selected.policy_name,
        action=selected.action,
        matched=True,
        reason=(
            f"Policy '{selected.policy_name}' matched "
            f"the event."
        ),
    )