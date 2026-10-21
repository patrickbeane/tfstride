from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsMessagingTopologyDestructionOperation = Literal[
    "sqs:DeleteQueue",
    "sns:DeleteTopic",
]
AwsMessagingTopologyDestructionOperationClass = Literal[
    "queue_deletion",
    "topic_deletion",
]
AwsMessagingTopologyDestructionInternalOperation = Literal[
    "delete_queue",
    "delete_topic",
]
AwsMessagingTopologyDestructionTargetGranularity = Literal[
    "queue_topology",
    "topic_topology",
]
AwsSqsQueueResourceScope = Literal["exact_queue", "queue_pattern"]
AwsSnsTopicResourceScope = Literal["exact_topic", "topic_pattern"]
AwsMessagingTopologyDestructionAuthorizationBasis = Literal[
    "identity_policy",
    "queue_policy_direct",
    "topic_policy_direct",
]


class AwsMessagingTopologyPolicyStatementEvidenceCommon(TypedDict):
    source_address: str
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    principals: list[str]
    principal_match: Literal["role", "account", "wildcard"] | None
    conditions: list[Never]
    conditional: Literal[False]


class AwsSqsQueueDeletionPolicyStatementEvidence(
    AwsMessagingTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["identity_policy", "queue_policy"]
    matched_actions: list[Literal["sqs:DeleteQueue"]]
    resource_scopes: list[AwsSqsQueueResourceScope]


class AwsSnsTopicDeletionPolicyStatementEvidence(
    AwsMessagingTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["identity_policy", "topic_policy"]
    matched_actions: list[Literal["sns:DeleteTopic"]]
    resource_scopes: list[AwsSnsTopicResourceScope]


class AwsMessagingTopologyDestructionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_messaging_topology_deletion_authority"]
    successful_deletion_observed: Literal[False]
    recovery_state: Literal["not_established_by_modeled_aws_messaging_topology_evidence"]
    descendant_impact_evaluated: Literal[False]
    out_of_plan_topology_evaluated: Literal[False]
    uncertainties: list[str]


class AwsEcsMessagingTopologyDestructionPathCommon(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    task_definition_arn: str | None
    internet_facing_load_balancers: list[str]
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_reference: str
    role_arn: str | None
    same_account: Literal[True]
    messaging_resource_address: str
    messaging_resource_type: str
    messaging_resource_name: str
    messaging_resource_arn: str
    target_model_evidence_addresses: list[str]
    management_effect: Literal["disruption"]
    authorization_source_addresses: list[str]
    evaluation_basis: Literal["modeled_identity_and_messaging_resource_policies"]
    authorization_state: Literal["allowed"]
    identity_policy_complete: Literal[True]
    resource_policy_complete: Literal[True]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["compatible"]
    outcome_evidence: AwsMessagingTopologyDestructionOutcomeEvidence
    posture_uncertainties: list[str]


class AwsEcsSqsQueueDeletionPath(
    AwsEcsMessagingTopologyDestructionPathCommon,
):
    messaging_service: Literal["sqs"]
    operation: Literal["sqs:DeleteQueue"]
    operation_class: Literal["queue_deletion"]
    internal_operation: Literal["delete_queue"]
    target_granularity: Literal["queue_topology"]
    target_scope: Literal["exact_sqs_queue"]
    queue_address: str
    queue_name: str
    queue_arn: str
    queue_url: str | None
    topic_address: None
    topic_name: None
    topic_arn: None
    authorization_bases: list[Literal["identity_policy", "queue_policy_direct"]]
    matched_actions: list[Literal["sqs:DeleteQueue"]]
    authorization_statements: list[AwsSqsQueueDeletionPolicyStatementEvidence]


class AwsEcsSnsTopicDeletionPath(
    AwsEcsMessagingTopologyDestructionPathCommon,
):
    messaging_service: Literal["sns"]
    operation: Literal["sns:DeleteTopic"]
    operation_class: Literal["topic_deletion"]
    internal_operation: Literal["delete_topic"]
    target_granularity: Literal["topic_topology"]
    target_scope: Literal["exact_sns_topic"]
    queue_address: None
    queue_name: None
    queue_arn: None
    queue_url: None
    topic_address: str
    topic_name: str
    topic_arn: str
    authorization_bases: list[Literal["identity_policy", "topic_policy_direct"]]
    matched_actions: list[Literal["sns:DeleteTopic"]]
    authorization_statements: list[AwsSnsTopicDeletionPolicyStatementEvidence]


AwsEcsMessagingTopologyDestructionPath = AwsEcsSqsQueueDeletionPath | AwsEcsSnsTopicDeletionPath
AwsEcsMessagingTopologyDestructionEvidence = AwsEcsMessagingTopologyDestructionPath
