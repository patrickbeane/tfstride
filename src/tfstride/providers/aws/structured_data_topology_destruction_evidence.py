from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsDynamoDbTableTopologyDestructionOperation = Literal["dynamodb:DeleteTable"]
AwsDynamoDbTableTopologyDestructionOperationClass = Literal["table_deletion"]
AwsDynamoDbTableTopologyDestructionInternalOperation = Literal["delete_table"]
AwsDynamoDbTableTopologyDestructionTargetGranularity = Literal["table_topology"]
AwsDynamoDbTableResourceScope = Literal["exact_table", "table_pattern"]
AwsDynamoDbTableTopologyDestructionAuthorizationBasis = Literal[
    "identity_policy",
    "table_policy_direct",
]
AwsDynamoDbTableTopologyDestructionGrantBasis = Literal[
    "same_account_identity_policy",
    "same_account_table_policy_direct",
    "same_account_combined",
    "cross_account_identity_and_table_policy",
]


class AwsDynamoDbTableTopologyPolicyStatementEvidenceCommon(TypedDict):
    source_address: str
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    matched_actions: list[Literal["dynamodb:DeleteTable"]]
    resources: list[str]
    matching_resources: list[str]
    resource_scopes: list[AwsDynamoDbTableResourceScope]
    conditions: list[Never]
    conditional: Literal[False]


class AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence(
    AwsDynamoDbTableTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["identity_policy"]
    principals: list[Never]
    principal_match: None


class AwsDynamoDbTableTopologyResourcePolicyStatementEvidence(
    AwsDynamoDbTableTopologyPolicyStatementEvidenceCommon,
):
    source_kind: Literal["table_policy"]
    principals: list[str]
    principal_match: Literal["role", "account", "wildcard"]


AwsDynamoDbTableTopologyPolicyStatementEvidence = (
    AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence | AwsDynamoDbTableTopologyResourcePolicyStatementEvidence
)


class AwsDynamoDbTableDeletionProtectionEnabled(TypedDict):
    constraint_evidence_scope: Literal["dynamodb_table_deletion_protection"]
    deletion_protection_state: Literal["enabled"]
    deletion_protection_enabled: Literal[True]
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["blocked"]
    uncertainties: list[Never]


class AwsDynamoDbTableDeletionProtectionDisabled(TypedDict):
    constraint_evidence_scope: Literal["dynamodb_table_deletion_protection"]
    deletion_protection_state: Literal["disabled"]
    deletion_protection_enabled: Literal[False]
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class AwsDynamoDbTableDeletionProtectionProviderDefault(TypedDict):
    constraint_evidence_scope: Literal["dynamodb_table_deletion_protection"]
    deletion_protection_state: Literal["not_configured"]
    deletion_protection_enabled: Literal[False]
    provider_default_applied: Literal[True]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class AwsDynamoDbTableDeletionProtectionUnknown(TypedDict):
    constraint_evidence_scope: Literal["dynamodb_table_deletion_protection"]
    deletion_protection_state: Literal["unknown"]
    deletion_protection_enabled: None
    provider_default_applied: Literal[False]
    deletion_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


AwsDynamoDbTableDeletionConstraintEvidence = (
    AwsDynamoDbTableDeletionProtectionEnabled
    | AwsDynamoDbTableDeletionProtectionDisabled
    | AwsDynamoDbTableDeletionProtectionProviderDefault
    | AwsDynamoDbTableDeletionProtectionUnknown
)
AwsDynamoDbTableDeletionCompatibleConstraintEvidence = (
    AwsDynamoDbTableDeletionProtectionDisabled | AwsDynamoDbTableDeletionProtectionProviderDefault
)


class AwsDynamoDbTableTopologyRecoveryEvidenceCommon(TypedDict):
    recovery_evidence_scope: Literal["dynamodb_table_deletion_and_point_in_time_recovery"]
    successful_deletion_observed: Literal[False]
    restoration_observed: Literal[False]
    runtime_table_state_evaluated: Literal[False]
    descendant_impact_evaluated: Literal[False]
    out_of_plan_table_topology_evaluated: Literal[False]
    uncertainties: list[str]


class AwsDynamoDbTablePitrEnabledRecoveryEvidence(
    AwsDynamoDbTableTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["enabled"]
    pitr_enabled: Literal[True]
    pitr_recovery_period_days: int | None
    restore_target_kind: Literal["new_table"]
    table_recovery_state: Literal["pitr_restore_to_new_table_configured"]


class AwsDynamoDbTablePitrDisabledRecoveryEvidence(
    AwsDynamoDbTableTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["disabled"]
    pitr_enabled: Literal[False]
    pitr_recovery_period_days: None
    restore_target_kind: None
    table_recovery_state: Literal["not_established_by_modeled_aws_dynamodb_table_evidence"]


class AwsDynamoDbTablePitrProviderDefaultRecoveryEvidence(
    AwsDynamoDbTableTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["not_configured"]
    pitr_enabled: Literal[False]
    pitr_recovery_period_days: None
    restore_target_kind: None
    table_recovery_state: Literal["not_established_by_modeled_aws_dynamodb_table_evidence"]


class AwsDynamoDbTablePitrUnknownRecoveryEvidence(
    AwsDynamoDbTableTopologyRecoveryEvidenceCommon,
):
    pitr_state: Literal["unknown"]
    pitr_enabled: None
    pitr_recovery_period_days: None
    restore_target_kind: None
    table_recovery_state: Literal["unknown"]


AwsDynamoDbTableTopologyDestructionRecoveryEvidence = (
    AwsDynamoDbTablePitrEnabledRecoveryEvidence
    | AwsDynamoDbTablePitrDisabledRecoveryEvidence
    | AwsDynamoDbTablePitrProviderDefaultRecoveryEvidence
    | AwsDynamoDbTablePitrUnknownRecoveryEvidence
)


class AwsEcsDynamoDbTableTopologyDestructionPathCommon(TypedDict):
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
    role_account_id: str
    role_provider_config_key: str | None
    table_address: str
    table_resource_type: str
    table_name: str
    table_reference: str
    table_arn: str | None
    table_account_id: str
    table_provider_config_key: str | None
    operation: Literal["dynamodb:DeleteTable"]
    operation_class: Literal["table_deletion"]
    internal_operation: Literal["delete_table"]
    management_effect: Literal["disruption"]
    target_granularity: Literal["table_topology"]
    target_scope: Literal["exact_dynamodb_table"]
    target_model_evidence_addresses: list[str]
    authorization_source_addresses: list[str]
    authorization_state: Literal["allowed"]
    evaluation_basis: Literal["modeled_identity_and_table_resource_policies"]
    matched_actions: list[Literal["dynamodb:DeleteTable"]]
    identity_policy_complete: Literal[True]
    table_policy_complete: Literal[True]
    identity_policy_source_addresses: list[str]
    table_policy_source_addresses: list[str]
    authorization_statements: list[AwsDynamoDbTableTopologyPolicyStatementEvidence]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["compatible"]
    deletion_constraint_evidence: AwsDynamoDbTableDeletionCompatibleConstraintEvidence
    recovery_evidence: AwsDynamoDbTableTopologyDestructionRecoveryEvidence
    posture_uncertainties: list[str]


class AwsEcsDynamoDbSameAccountIdentityTableDeletionPath(
    AwsEcsDynamoDbTableTopologyDestructionPathCommon,
):
    account_relationship: Literal["same_account"]
    same_account: Literal[True]
    grant_basis: Literal["same_account_identity_policy"]
    identity_policy_allow_required: Literal[True]
    table_policy_allow_required: Literal[False]
    resource_policy_principal_match: None


class AwsEcsDynamoDbSameAccountTablePolicyDeletionPath(
    AwsEcsDynamoDbTableTopologyDestructionPathCommon,
):
    account_relationship: Literal["same_account"]
    same_account: Literal[True]
    grant_basis: Literal["same_account_table_policy_direct"]
    identity_policy_allow_required: Literal[False]
    table_policy_allow_required: Literal[True]
    resource_policy_principal_match: Literal["role"]


class AwsEcsDynamoDbSameAccountCombinedTableDeletionPath(
    AwsEcsDynamoDbTableTopologyDestructionPathCommon,
):
    account_relationship: Literal["same_account"]
    same_account: Literal[True]
    grant_basis: Literal["same_account_combined"]
    identity_policy_allow_required: Literal[True]
    table_policy_allow_required: Literal[True]
    resource_policy_principal_match: Literal["role", "account", "wildcard"]


class AwsEcsDynamoDbCrossAccountTableDeletionPath(
    AwsEcsDynamoDbTableTopologyDestructionPathCommon,
):
    account_relationship: Literal["cross_account"]
    same_account: Literal[False]
    grant_basis: Literal["cross_account_identity_and_table_policy"]
    identity_policy_allow_required: Literal[True]
    table_policy_allow_required: Literal[True]
    resource_policy_principal_match: Literal["role", "account", "wildcard"]


AwsEcsDynamoDbTableTopologyDestructionPath = (
    AwsEcsDynamoDbSameAccountIdentityTableDeletionPath
    | AwsEcsDynamoDbSameAccountTablePolicyDeletionPath
    | AwsEcsDynamoDbSameAccountCombinedTableDeletionPath
    | AwsEcsDynamoDbCrossAccountTableDeletionPath
)
AwsEcsDynamoDbTableTopologyDestructionEvidence = AwsEcsDynamoDbTableTopologyDestructionPath
