from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

from tfstride.providers.aws.kms_dependency_evidence import AwsKmsEncryptionDependency
from tfstride.providers.aws.kms_evidence import AwsEcsKmsOperationPath

AwsS3AccessClass = Literal["read", "write", "delete", "administrative"]
AwsS3AccessState = Literal["allowed", "denied", "unknown", "not_modeled"]
AwsS3ResourceScope = Literal[
    "all_resources",
    "exact_bucket",
    "all_bucket_objects",
    "object_prefix",
    "exact_object",
]


class AwsS3ScopeEvaluation(TypedDict):
    """Modeled authorization for one action and one original allow resource scope."""

    action: str
    resource: str
    modeled_access_state: AwsS3AccessState
    reason: Literal[
        "unconditional_allow",
        "explicit_deny",
        "conditional_allow",
        "conditional_deny",
        "partial_deny",
        "unsupported_resource_scope",
    ]
    overlapping_deny_resources: list[str]
    conditional_deny_resources: list[str]
    conditional_evaluation_required: bool


class AwsS3PolicyConditionEvidence(TypedDict):
    operator: str
    key: str
    values: list[str]


class AwsS3PolicyStatementEvidence(TypedDict):
    effect: Literal["allow", "deny"]
    actions: list[str]
    matched_actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    resource_scopes: list[AwsS3ResourceScope]
    access_classes: list[AwsS3AccessClass]
    conditions: list[AwsS3PolicyConditionEvidence]
    conditional: bool


class AwsEcsS3AccessPath(TypedDict):
    workload_address: str
    workload_type: str
    bucket_address: str
    bucket_name: str
    bucket_arn: str
    role_kind: Literal["ecs_task_role"]
    credential_context: Literal["workload_runtime"]
    role_address: str
    role_arn: str | None
    role_policy_complete: bool
    evaluation_basis: Literal["modeled_identity_policy"]
    modeled_access_state: AwsS3AccessState
    access_state: AwsS3AccessState
    access_classes: list[AwsS3AccessClass]
    denied_access_classes: list[AwsS3AccessClass]
    unknown_access_classes: list[AwsS3AccessClass]
    matched_actions: list[str]
    denied_actions: list[str]
    unknown_actions: list[str]
    explicit_deny: bool
    conditional_evaluation_required: bool
    policy_action_patterns: list[str]
    policy_resources: list[str]
    deny_action_patterns: list[str]
    deny_policy_resources: list[str]
    resource_scopes: list[AwsS3ResourceScope]
    policy_statements: list[AwsS3PolicyStatementEvidence]
    scope_evaluations: list[AwsS3ScopeEvaluation]
    task_definition_address: NotRequired[str]
    task_definition_arn: NotRequired[str | None]
    internet_facing_load_balancers: NotRequired[list[str]]


class AwsEcsS3ProtectedDataConvergence(TypedDict):
    workload_address: str
    workload_type: str
    task_definition_address: str
    role_address: str
    role_arn: str
    bucket_address: str
    bucket_arn: str
    key_address: str
    key_arn: str
    operation: Literal["kms:Decrypt"]
    access_class: Literal["read"]
    runtime_identity_match: Literal[True]
    protected_resource_match: Literal[True]
    key_identity_match: Literal[True]
    convergence_state: Literal["resolved"]
    evaluation_basis: Literal["exact_s3_access_kms_dependency_and_decrypt_authority"]
    access_path: AwsEcsS3AccessPath
    key_operation_path: AwsEcsKmsOperationPath
    encryption_dependency: AwsKmsEncryptionDependency
    posture_uncertainties: list[str]
