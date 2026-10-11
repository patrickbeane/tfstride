from __future__ import annotations

from typing import Literal, Never, TypedDict

GcpLoggingSinkAuditTelemetryDisruptionOperation = Literal["logging.sinks.delete"]
GcpLoggingSinkAuditTelemetryDisruptionOperationClass = Literal["project_sink_deletion"]
GcpLoggingSinkAuditTelemetryDisruptionInternalOperation = Literal["delete_project_logging_sink"]
GcpLoggingSinkAuditTelemetryDisruptionTargetGranularity = Literal["project_logging_sink"]
GcpLoggingSinkActiveCustomRoleStage = Literal[
    "ALPHA",
    "BETA",
    "DEPRECATED",
    "EAP",
    "GA",
]


class GcpLoggingSinkBuiltInRoleEvidence(TypedDict):
    role_kind: Literal[
        "owner",
        "logging_admin",
        "logging_config_writer",
        "iam_devops",
        "iam_infrastructure_admin",
        "iam_network_admin",
    ]
    role_definition_address: None
    custom_role_permissions: list[Never]
    custom_role_stage: None
    custom_role_deleted: None
    custom_role_wildcard_permissions_present: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["not_applicable"]


class GcpLoggingSinkCustomRoleEvidence(TypedDict):
    role_kind: Literal["custom"]
    role_definition_address: str
    custom_role_permissions: list[str]
    custom_role_stage: GcpLoggingSinkActiveCustomRoleStage
    custom_role_deleted: Literal[False]
    custom_role_wildcard_permissions_present: Literal[False]
    custom_role_grant_scope_compatibility_state: Literal["compatible"]


GcpLoggingSinkRoleEvidence = GcpLoggingSinkBuiltInRoleEvidence | GcpLoggingSinkCustomRoleEvidence


class GcpLoggingSinkActiveExplicitLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_logging_sink_state"]
    disabled_configuration_state: Literal["configured"]
    sink_disabled: Literal[False]
    provider_default_applied: Literal[False]
    sink_lifecycle_state: Literal["active"]
    lifecycle_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class GcpLoggingSinkActiveProviderDefaultLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_logging_sink_state"]
    disabled_configuration_state: Literal["not_configured"]
    sink_disabled: Literal[False]
    provider_default_applied: Literal[True]
    sink_lifecycle_state: Literal["active"]
    lifecycle_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class GcpLoggingSinkDisabledLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_logging_sink_state"]
    disabled_configuration_state: Literal["configured"]
    sink_disabled: Literal[True]
    provider_default_applied: Literal[False]
    sink_lifecycle_state: Literal["disabled"]
    lifecycle_compatibility_state: Literal["not_currently_disruptive"]
    uncertainties: list[Never]


class GcpLoggingSinkUnknownLifecycleEvidence(TypedDict):
    lifecycle_evidence_scope: Literal["plan_local_logging_sink_state"]
    disabled_configuration_state: Literal["unknown"]
    sink_disabled: None
    provider_default_applied: Literal[False]
    sink_lifecycle_state: Literal["unknown"]
    lifecycle_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


GcpLoggingSinkLifecycleEvidence = (
    GcpLoggingSinkActiveExplicitLifecycleEvidence
    | GcpLoggingSinkActiveProviderDefaultLifecycleEvidence
    | GcpLoggingSinkDisabledLifecycleEvidence
    | GcpLoggingSinkUnknownLifecycleEvidence
)
GcpLoggingSinkActiveLifecycleEvidence = (
    GcpLoggingSinkActiveExplicitLifecycleEvidence | GcpLoggingSinkActiveProviderDefaultLifecycleEvidence
)


class GcpLoggingSinkUserManagedDeletionConstraintEvidence(TypedDict):
    constraint_evidence_scope: Literal["gcp_logging_system_sink_deletion"]
    sink_kind: Literal["user_managed"]
    system_sink_name: None
    api_deletion_supported: Literal[True]
    deletion_compatibility_state: Literal["compatible"]
    uncertainties: list[Never]


class GcpLoggingSinkSystemManagedDeletionConstraintEvidence(TypedDict):
    constraint_evidence_scope: Literal["gcp_logging_system_sink_deletion"]
    sink_kind: Literal["system_managed"]
    system_sink_name: Literal["_Default", "_Required"]
    api_deletion_supported: Literal[False]
    deletion_compatibility_state: Literal["blocked"]
    uncertainties: list[Never]


class GcpLoggingSinkUnknownDeletionConstraintEvidence(TypedDict):
    constraint_evidence_scope: Literal["gcp_logging_system_sink_deletion"]
    sink_kind: Literal["unknown"]
    system_sink_name: str | None
    api_deletion_supported: None
    deletion_compatibility_state: Literal["unknown"]
    uncertainties: list[str]


GcpLoggingSinkDeletionConstraintEvidence = (
    GcpLoggingSinkUserManagedDeletionConstraintEvidence
    | GcpLoggingSinkSystemManagedDeletionConstraintEvidence
    | GcpLoggingSinkUnknownDeletionConstraintEvidence
)


class GcpLoggingSinkAllLogsRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_logging_sink_filter_and_destination"]
    filter_state: Literal["not_configured"]
    sink_filter: None
    relevance_basis: Literal["all_logs"]
    matched_audit_security_filter_signal: None
    matched_audit_security_filter_signals: list[Never]
    audit_telemetry_relevance_state: Literal["established"]
    uncertainties: list[Never]


class GcpLoggingSinkAuditFilterRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_logging_sink_filter_and_destination"]
    filter_state: Literal["configured"]
    sink_filter: str
    relevance_basis: Literal["audit_security_filter"]
    matched_audit_security_filter_signal: str
    matched_audit_security_filter_signals: list[str]
    audit_telemetry_relevance_state: Literal["established"]
    uncertainties: list[Never]


class GcpLoggingSinkNarrowedAuditFilterRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_logging_sink_filter_and_destination"]
    filter_state: Literal["configured"]
    sink_filter: str
    relevance_basis: Literal["narrowed_audit_security_filter"]
    matched_audit_security_filter_signal: str
    matched_audit_security_filter_signals: list[str]
    audit_telemetry_relevance_state: Literal["established"]
    uncertainties: list[Never]


class GcpLoggingSinkIrrelevantFilterEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_logging_sink_filter_and_destination"]
    filter_state: Literal["configured"]
    sink_filter: str
    relevance_basis: Literal["no_audit_security_filter_signal"]
    matched_audit_security_filter_signal: None
    matched_audit_security_filter_signals: list[Never]
    audit_telemetry_relevance_state: Literal["not_established"]
    uncertainties: list[Never]


class GcpLoggingSinkUnknownRelevanceEvidence(TypedDict):
    relevance_evidence_scope: Literal["plan_local_logging_sink_filter_and_destination"]
    filter_state: Literal["unknown"]
    sink_filter: None
    relevance_basis: Literal["unknown"]
    matched_audit_security_filter_signal: None
    matched_audit_security_filter_signals: list[Never]
    audit_telemetry_relevance_state: Literal["unknown"]
    uncertainties: list[str]


GcpLoggingSinkAuditTelemetryRelevanceEvidence = (
    GcpLoggingSinkAllLogsRelevanceEvidence
    | GcpLoggingSinkAuditFilterRelevanceEvidence
    | GcpLoggingSinkNarrowedAuditFilterRelevanceEvidence
    | GcpLoggingSinkIrrelevantFilterEvidence
    | GcpLoggingSinkUnknownRelevanceEvidence
)
GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence = (
    GcpLoggingSinkAllLogsRelevanceEvidence
    | GcpLoggingSinkAuditFilterRelevanceEvidence
    | GcpLoggingSinkNarrowedAuditFilterRelevanceEvidence
)


class GcpLoggingSinkAuditTelemetryDisruptionOutcomeEvidence(TypedDict):
    outcome_evidence_scope: Literal["plan_local_project_logging_sink_deletion_authority"]
    successful_operation_observed: Literal[False]
    historical_log_entry_deletion_authorized_by_operation: Literal[False]
    historical_log_entry_deletion_observed: Literal[False]
    destination_resource_deletion_authorized_by_operation: Literal[False]
    destination_resource_deletion_observed: Literal[False]
    unique_writer_identity_side_effect_evaluated: Literal[False]
    all_project_audit_sinks_evaluated: Literal[False]
    out_of_plan_sinks_evaluated: Literal[False]
    telemetry_recovery_state: Literal["not_established_by_modeled_gcp_logging_sink_evidence"]
    restoration_observed: Literal[False]
    uncertainties: list[str]


class GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath(TypedDict):
    workload_address: str
    workload_type: str
    service_account_email: str
    service_account_member: str
    identity_kind: Literal["cloud_run_service_account"]
    credential_context: Literal["workload_runtime"]
    logging_sink_address: str
    logging_sink_resource_type: str
    logging_sink_name: str
    logging_sink_resource_name: str
    logging_sink_project: str
    logging_sink_destination: str
    logging_sink_writer_identity: str | None
    logging_sink_unique_writer_identity: bool | None
    operation: Literal["logging.sinks.delete"]
    operation_class: Literal["project_sink_deletion"]
    internal_operation: Literal["delete_project_logging_sink"]
    management_effect: Literal["audit_telemetry_disruption"]
    target_granularity: Literal["project_logging_sink"]
    target_scope: Literal["exact_project_logging_sink"]
    target_model_evidence_addresses: list[str]
    iam_resource_address: str
    iam_resource_type: str
    iam_source_addresses: list[str]
    role: str
    role_evidence: GcpLoggingSinkRoleEvidence
    scope_type: Literal["project"]
    scope: str
    resource_scope: Literal["logging_project"]
    grant_basis: Literal["logging_project_iam"]
    matched_permissions: list[Literal["logging.sinks.delete"]]
    authorization_state: Literal["granted"]
    policy_complete: Literal[True]
    iam_manager_ambiguity_state: Literal["not_detected"]
    condition: None
    condition_state: Literal["not_configured"]
    condition_evaluation: Literal["not_configured"]
    lifecycle_compatibility_state: Literal["compatible"]
    lifecycle_evidence: GcpLoggingSinkActiveLifecycleEvidence
    deletion_constraint_evidence: GcpLoggingSinkUserManagedDeletionConstraintEvidence
    audit_telemetry_relevance_evidence: GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence
    outcome_evidence: GcpLoggingSinkAuditTelemetryDisruptionOutcomeEvidence
    posture_uncertainties: list[str]


GcpCloudRunLoggingSinkAuditTelemetryDisruptionEvidence = GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath
