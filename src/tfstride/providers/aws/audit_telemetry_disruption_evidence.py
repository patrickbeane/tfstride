from __future__ import annotations

from typing import Literal, Never, TypedDict

AwsCloudTrailAuditTelemetryDisruptionOperation = Literal[
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
]
AwsCloudTrailAuditTelemetryDisruptionOperationClass = Literal[
    "trail_logging_stop",
    "trail_deletion",
]
AwsCloudTrailAuditTelemetryDisruptionInternalOperation = Literal[
    "stop_trail_logging",
    "delete_trail",
]
AwsCloudTrailAuditTelemetryDisruptionTargetGranularity = Literal[
    "trail_logging_control",
    "trail_configuration",
]
AwsCloudTrailResourceScope = Literal["exact_trail", "trail_pattern"]


class AwsCloudTrailAuditTelemetryPolicyStatementEvidenceCommon(TypedDict):
    source_address: str
    source_kind: Literal["identity_policy"]
    effect: Literal["allow"]
    actions: list[str]
    matching_action_patterns: list[str]
    resources: list[str]
    matching_resources: list[str]
    resource_scopes: list[AwsCloudTrailResourceScope]
    principals: list[Never]
    principal_match: None
    conditions: list[Never]
    conditional: Literal[False]


class AwsCloudTrailStopLoggingPolicyStatementEvidence(
    AwsCloudTrailAuditTelemetryPolicyStatementEvidenceCommon,
):
    matched_actions: list[Literal["cloudtrail:StopLogging"]]


class AwsCloudTrailDeleteTrailPolicyStatementEvidence(
    AwsCloudTrailAuditTelemetryPolicyStatementEvidenceCommon,
):
    matched_actions: list[Literal["cloudtrail:DeleteTrail"]]


AwsCloudTrailAuditTelemetryPolicyStatementEvidence = (
    AwsCloudTrailStopLoggingPolicyStatementEvidence | AwsCloudTrailDeleteTrailPolicyStatementEvidence
)


class AwsCloudTrailActiveStandardTrailLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_cloudtrail_logging_state"]
    logging_state: Literal["enabled"]
    enable_logging: Literal[True]
    organization_trail_state: Literal["disabled"]
    is_organization_trail: Literal[False]
    lifecycle_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class AwsCloudTrailInactiveStandardTrailLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_cloudtrail_logging_state"]
    logging_state: Literal["disabled"]
    enable_logging: Literal[False]
    organization_trail_state: Literal["disabled"]
    is_organization_trail: Literal[False]
    lifecycle_compatibility_state: Literal["not_currently_disruptive"]
    uncertainties: list[Never]


class AwsCloudTrailUnknownStandardTrailLoggingEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_cloudtrail_logging_state"]
    logging_state: Literal["unknown"]
    enable_logging: None
    organization_trail_state: Literal["disabled"]
    is_organization_trail: Literal[False]
    lifecycle_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


class AwsCloudTrailOrganizationTrailLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_cloudtrail_logging_state"]
    logging_state: Literal["enabled", "disabled", "unknown"]
    enable_logging: bool | None
    organization_trail_state: Literal["enabled"]
    is_organization_trail: Literal[True]
    lifecycle_compatibility_state: Literal["unsupported_organization_trail"]
    uncertainties: list[str]


class AwsCloudTrailUnknownLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_cloudtrail_logging_state"]
    logging_state: Literal["enabled", "disabled", "unknown"]
    enable_logging: bool | None
    organization_trail_state: Literal["unknown"]
    is_organization_trail: None
    lifecycle_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


AwsCloudTrailAuditTelemetryLifecycleEvidence = (
    AwsCloudTrailActiveStandardTrailLifecycleEvidence
    | AwsCloudTrailInactiveStandardTrailLifecycleEvidence
    | AwsCloudTrailUnknownStandardTrailLoggingEvidence
    | AwsCloudTrailOrganizationTrailLifecycleEvidence
    | AwsCloudTrailUnknownLifecycleEvidence
)


class AwsCloudTrailAuditTelemetryDisruptionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_cloudtrail_control_authority"]
    successful_operation_observed: Literal[False]
    historical_log_object_deletion_authorized_by_operation: Literal[False]
    historical_log_object_deletion_observed: Literal[False]
    logging_destination_deletion_authorized_by_operation: Literal[False]
    logging_destination_deletion_observed: Literal[False]
    all_account_audit_trails_evaluated: Literal[False]
    out_of_plan_trails_evaluated: Literal[False]
    telemetry_recovery_state: Literal["not_established_by_modeled_aws_cloudtrail_evidence"]
    restoration_observed: Literal[False]
    uncertainties: list[str]


class AwsEcsCloudTrailAuditTelemetryDisruptionPathCommon(TypedDict):
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
    role_provider_config_key: str
    caller_identity_address: str
    caller_account_id: str
    caller_provider_config_key: str
    trail_address: str
    trail_resource_type: str
    trail_name: str
    trail_reference: str
    trail_arn: str | None
    trail_account_id: str
    trail_provider_config_key: str
    same_account: Literal[True]
    provider_configuration_match: Literal[True]
    management_effect: Literal["audit_telemetry_disruption"]
    target_scope: Literal["exact_cloudtrail_trail"]
    target_model_evidence_addresses: list[str]
    authorization_source_addresses: list[str]
    authorization_state: Literal["allowed"]
    evaluation_basis: Literal["modeled_ecs_task_role_identity_policy"]
    identity_policy_complete: Literal[True]
    identity_policy_source_addresses: list[str]
    explicit_deny: Literal[False]
    conditional_evaluation_required: Literal[False]
    lifecycle_compatibility_state: Literal["compatible"]
    lifecycle_evidence: AwsCloudTrailActiveStandardTrailLifecycleEvidence
    outcome_evidence: AwsCloudTrailAuditTelemetryDisruptionOutcomeEvidence
    posture_uncertainties: list[str]


class AwsEcsCloudTrailStopLoggingPath(
    AwsEcsCloudTrailAuditTelemetryDisruptionPathCommon,
):
    operation: Literal["cloudtrail:StopLogging"]
    operation_class: Literal["trail_logging_stop"]
    internal_operation: Literal["stop_trail_logging"]
    target_granularity: Literal["trail_logging_control"]
    matched_actions: list[Literal["cloudtrail:StopLogging"]]
    authorization_statements: list[AwsCloudTrailStopLoggingPolicyStatementEvidence]
    trail_configuration_deletion_authorized: Literal[False]


class AwsEcsCloudTrailDeleteTrailPath(
    AwsEcsCloudTrailAuditTelemetryDisruptionPathCommon,
):
    operation: Literal["cloudtrail:DeleteTrail"]
    operation_class: Literal["trail_deletion"]
    internal_operation: Literal["delete_trail"]
    target_granularity: Literal["trail_configuration"]
    matched_actions: list[Literal["cloudtrail:DeleteTrail"]]
    authorization_statements: list[AwsCloudTrailDeleteTrailPolicyStatementEvidence]
    trail_configuration_deletion_authorized: Literal[True]


AwsEcsCloudTrailAuditTelemetryDisruptionPath = AwsEcsCloudTrailStopLoggingPath | AwsEcsCloudTrailDeleteTrailPath
AwsEcsCloudTrailAuditTelemetryDisruptionEvidence = AwsEcsCloudTrailAuditTelemetryDisruptionPath
