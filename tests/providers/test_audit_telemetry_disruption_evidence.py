from __future__ import annotations

import types
import unittest
from typing import Literal, Never, get_args, get_type_hints

from tfstride.providers.aws.audit_telemetry_disruption_evidence import (
    AwsCloudTrailActiveStandardTrailLifecycleEvidence,
    AwsCloudTrailAuditTelemetryDisruptionOutcomeEvidence,
    AwsCloudTrailAuditTelemetryLifecycleEvidence,
    AwsCloudTrailDeleteTrailPolicyStatementEvidence,
    AwsCloudTrailInactiveStandardTrailLifecycleEvidence,
    AwsCloudTrailOrganizationTrailLifecycleEvidence,
    AwsCloudTrailStopLoggingPolicyStatementEvidence,
    AwsCloudTrailUnknownLifecycleEvidence,
    AwsCloudTrailUnknownStandardTrailLoggingEvidence,
    AwsEcsCloudTrailAuditTelemetryDisruptionPath,
    AwsEcsCloudTrailDeleteTrailPath,
    AwsEcsCloudTrailStopLoggingPath,
)
from tfstride.providers.azure.audit_telemetry_disruption_evidence import (
    AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath,
    AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence,
    AzureDiagnosticSettingAuditCategoryRelevanceEvidence,
    AzureDiagnosticSettingAuditTelemetryDisruptionOutcomeEvidence,
    AzureDiagnosticSettingAuditTelemetryRelevanceEvidence,
    AzureDiagnosticSettingBuiltInRoleEvidence,
    AzureDiagnosticSettingConfiguredDestinationEvidence,
    AzureDiagnosticSettingCustomRoleEvidence,
    AzureDiagnosticSettingDeletionAuthorizationGrant,
    AzureDiagnosticSettingDestinationEvidence,
    AzureDiagnosticSettingEventHubDestinationEvidence,
    AzureDiagnosticSettingIrrelevantCategoriesEvidence,
    AzureDiagnosticSettingLogAnalyticsDestinationEvidence,
    AzureDiagnosticSettingManagementLockBlocking,
    AzureDiagnosticSettingManagementLockEvidence,
    AzureDiagnosticSettingManagementLockNotObserved,
    AzureDiagnosticSettingManagementLockUnknown,
    AzureDiagnosticSettingMarketplaceDestinationEvidence,
    AzureDiagnosticSettingStorageDestinationEvidence,
    AzureDiagnosticSettingUnknownCategoriesEvidence,
    AzureDiagnosticSettingUnknownDestinationEvidence,
)
from tfstride.providers.gcp.audit_telemetry_disruption_evidence import (
    GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath,
    GcpLoggingSinkActiveExplicitLifecycleEvidence,
    GcpLoggingSinkActiveLifecycleEvidence,
    GcpLoggingSinkActiveProviderDefaultLifecycleEvidence,
    GcpLoggingSinkAllLogsRelevanceEvidence,
    GcpLoggingSinkAuditFilterRelevanceEvidence,
    GcpLoggingSinkAuditTelemetryDisruptionOutcomeEvidence,
    GcpLoggingSinkAuditTelemetryRelevanceEvidence,
    GcpLoggingSinkBuiltInRoleEvidence,
    GcpLoggingSinkCustomRoleEvidence,
    GcpLoggingSinkDeletionConstraintEvidence,
    GcpLoggingSinkDisabledLifecycleEvidence,
    GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence,
    GcpLoggingSinkIrrelevantFilterEvidence,
    GcpLoggingSinkLifecycleEvidence,
    GcpLoggingSinkSystemManagedDeletionConstraintEvidence,
    GcpLoggingSinkUnknownDeletionConstraintEvidence,
    GcpLoggingSinkUnknownLifecycleEvidence,
    GcpLoggingSinkUnknownRelevanceEvidence,
    GcpLoggingSinkUserManagedDeletionConstraintEvidence,
)


class AuditTelemetryDisruptionEvidenceTests(unittest.TestCase):
    def test_aws_contract_discriminates_stop_logging_and_trail_deletion(
        self,
    ) -> None:
        stop_hints = get_type_hints(AwsEcsCloudTrailStopLoggingPath)
        delete_hints = get_type_hints(AwsEcsCloudTrailDeleteTrailPath)
        stop_statement_hints = get_type_hints(AwsCloudTrailStopLoggingPolicyStatementEvidence)
        delete_statement_hints = get_type_hints(AwsCloudTrailDeleteTrailPolicyStatementEvidence)

        self.assertEqual(
            set(get_args(AwsEcsCloudTrailAuditTelemetryDisruptionPath)),
            {
                AwsEcsCloudTrailStopLoggingPath,
                AwsEcsCloudTrailDeleteTrailPath,
            },
        )
        self.assertEqual(stop_hints["operation"], Literal["cloudtrail:StopLogging"])
        self.assertEqual(
            stop_hints["operation_class"],
            Literal["trail_logging_stop"],
        )
        self.assertEqual(
            stop_hints["target_granularity"],
            Literal["trail_logging_control"],
        )
        self.assertEqual(
            stop_hints["trail_configuration_deletion_authorized"],
            Literal[False],
        )
        self.assertEqual(delete_hints["operation"], Literal["cloudtrail:DeleteTrail"])
        self.assertEqual(
            delete_hints["operation_class"],
            Literal["trail_deletion"],
        )
        self.assertEqual(
            delete_hints["target_granularity"],
            Literal["trail_configuration"],
        )
        self.assertEqual(
            delete_hints["trail_configuration_deletion_authorized"],
            Literal[True],
        )
        self.assertEqual(
            stop_statement_hints["matched_actions"],
            list[Literal["cloudtrail:StopLogging"]],
        )
        self.assertEqual(
            delete_statement_hints["matched_actions"],
            list[Literal["cloudtrail:DeleteTrail"]],
        )
        self.assertEqual(stop_statement_hints["conditions"], list[Never])

    def test_aws_cloudtrail_statement_evidence_distinguishes_grant_breadth(self) -> None:
        for statement_type in (
            AwsCloudTrailStopLoggingPolicyStatementEvidence,
            AwsCloudTrailDeleteTrailPolicyStatementEvidence,
        ):
            with self.subTest(statement_type=statement_type.__name__):
                self.assertEqual(
                    get_type_hints(statement_type)["resource_scopes"],
                    list[Literal["exact_trail", "trail_pattern"]],
                )

    def test_aws_path_requires_exact_runtime_same_account_authority(self) -> None:
        hints = get_type_hints(AwsEcsCloudTrailStopLoggingPath)

        self.assertEqual(hints["role_kind"], Literal["ecs_task_role"])
        self.assertEqual(hints["credential_context"], Literal["workload_runtime"])
        self.assertEqual(hints["same_account"], Literal[True])
        self.assertEqual(hints["provider_configuration_match"], Literal[True])
        self.assertEqual(hints["target_scope"], Literal["exact_cloudtrail_trail"])
        self.assertEqual(hints["authorization_state"], Literal["allowed"])
        self.assertEqual(hints["identity_policy_complete"], Literal[True])
        self.assertEqual(hints["explicit_deny"], Literal[False])
        self.assertEqual(
            hints["conditional_evaluation_required"],
            Literal[False],
        )
        self.assertEqual(
            hints["lifecycle_evidence"],
            AwsCloudTrailActiveStandardTrailLifecycleEvidence,
        )
        self.assertEqual(hints["role_provider_config_key"], str)
        self.assertEqual(hints["trail_provider_config_key"], str)
        self.assertEqual(hints["caller_provider_config_key"], str)

    def test_aws_lifecycle_and_outcome_contracts_do_not_overclaim(self) -> None:
        active_hints = get_type_hints(AwsCloudTrailActiveStandardTrailLifecycleEvidence)
        inactive_hints = get_type_hints(AwsCloudTrailInactiveStandardTrailLifecycleEvidence)
        standard_unknown_hints = get_type_hints(AwsCloudTrailUnknownStandardTrailLoggingEvidence)
        organization_hints = get_type_hints(AwsCloudTrailOrganizationTrailLifecycleEvidence)
        unknown_hints = get_type_hints(AwsCloudTrailUnknownLifecycleEvidence)
        outcome_hints = get_type_hints(AwsCloudTrailAuditTelemetryDisruptionOutcomeEvidence)

        self.assertEqual(
            set(get_args(AwsCloudTrailAuditTelemetryLifecycleEvidence)),
            {
                AwsCloudTrailActiveStandardTrailLifecycleEvidence,
                AwsCloudTrailInactiveStandardTrailLifecycleEvidence,
                AwsCloudTrailUnknownStandardTrailLoggingEvidence,
                AwsCloudTrailOrganizationTrailLifecycleEvidence,
                AwsCloudTrailUnknownLifecycleEvidence,
            },
        )
        self.assertEqual(active_hints["enable_logging"], Literal[True])
        self.assertEqual(active_hints["is_organization_trail"], Literal[False])
        self.assertEqual(
            active_hints["lifecycle_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            inactive_hints["lifecycle_compatibility_state"],
            Literal["not_currently_disruptive"],
        )
        self.assertEqual(standard_unknown_hints["enable_logging"], types.NoneType)
        self.assertEqual(
            organization_hints["lifecycle_compatibility_state"],
            Literal["unsupported_organization_trail"],
        )
        self.assertEqual(unknown_hints["is_organization_trail"], types.NoneType)
        self.assertEqual(
            outcome_hints["successful_operation_observed"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["historical_log_object_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["logging_destination_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["all_account_audit_trails_evaluated"],
            Literal[False],
        )
        self.assertEqual(outcome_hints["restoration_observed"], Literal[False])

    def test_gcp_path_requires_project_iam_and_exact_active_relevant_sink(
        self,
    ) -> None:
        hints = get_type_hints(GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath)
        built_in_hints = get_type_hints(GcpLoggingSinkBuiltInRoleEvidence)
        custom_hints = get_type_hints(GcpLoggingSinkCustomRoleEvidence)

        self.assertEqual(hints["operation"], Literal["logging.sinks.delete"])
        self.assertEqual(
            hints["operation_class"],
            Literal["project_sink_deletion"],
        )
        self.assertEqual(hints["identity_kind"], Literal["cloud_run_service_account"])
        self.assertEqual(hints["credential_context"], Literal["workload_runtime"])
        self.assertEqual(hints["target_scope"], Literal["exact_project_logging_sink"])
        self.assertEqual(hints["scope_type"], Literal["project"])
        self.assertEqual(hints["resource_scope"], Literal["logging_project"])
        self.assertEqual(hints["grant_basis"], Literal["logging_project_iam"])
        self.assertEqual(
            hints["matched_permissions"],
            list[Literal["logging.sinks.delete"]],
        )
        self.assertEqual(hints["policy_complete"], Literal[True])
        self.assertEqual(
            hints["iam_manager_ambiguity_state"],
            Literal["not_detected"],
        )
        self.assertEqual(hints["condition"], types.NoneType)
        self.assertEqual(hints["condition_state"], Literal["not_configured"])
        self.assertEqual(
            hints["lifecycle_evidence"],
            GcpLoggingSinkActiveLifecycleEvidence,
        )
        self.assertEqual(
            hints["audit_telemetry_relevance_evidence"],
            GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence,
        )
        self.assertEqual(
            hints["deletion_constraint_evidence"],
            GcpLoggingSinkUserManagedDeletionConstraintEvidence,
        )
        self.assertEqual(
            built_in_hints["role_kind"],
            Literal[
                "owner",
                "logging_admin",
                "logging_config_writer",
                "iam_devops",
                "iam_infrastructure_admin",
                "iam_network_admin",
            ],
        )
        self.assertEqual(custom_hints["custom_role_deleted"], Literal[False])
        self.assertEqual(
            custom_hints["custom_role_wildcard_permissions_present"],
            Literal[False],
        )
        self.assertEqual(
            custom_hints["custom_role_grant_scope_compatibility_state"],
            Literal["compatible"],
        )

    def test_gcp_lifecycle_and_relevance_variants_exclude_ineligible_sinks(
        self,
    ) -> None:
        explicit_hints = get_type_hints(GcpLoggingSinkActiveExplicitLifecycleEvidence)
        default_hints = get_type_hints(GcpLoggingSinkActiveProviderDefaultLifecycleEvidence)
        disabled_hints = get_type_hints(GcpLoggingSinkDisabledLifecycleEvidence)
        unknown_hints = get_type_hints(GcpLoggingSinkUnknownLifecycleEvidence)
        all_logs_hints = get_type_hints(GcpLoggingSinkAllLogsRelevanceEvidence)
        filtered_hints = get_type_hints(GcpLoggingSinkAuditFilterRelevanceEvidence)
        irrelevant_hints = get_type_hints(GcpLoggingSinkIrrelevantFilterEvidence)
        relevance_unknown_hints = get_type_hints(GcpLoggingSinkUnknownRelevanceEvidence)

        self.assertEqual(
            set(get_args(GcpLoggingSinkLifecycleEvidence)),
            {
                GcpLoggingSinkActiveExplicitLifecycleEvidence,
                GcpLoggingSinkActiveProviderDefaultLifecycleEvidence,
                GcpLoggingSinkDisabledLifecycleEvidence,
                GcpLoggingSinkUnknownLifecycleEvidence,
            },
        )
        self.assertEqual(
            set(get_args(GcpLoggingSinkActiveLifecycleEvidence)),
            {
                GcpLoggingSinkActiveExplicitLifecycleEvidence,
                GcpLoggingSinkActiveProviderDefaultLifecycleEvidence,
            },
        )
        self.assertEqual(explicit_hints["sink_disabled"], Literal[False])
        self.assertEqual(explicit_hints["provider_default_applied"], Literal[False])
        self.assertEqual(default_hints["provider_default_applied"], Literal[True])
        self.assertEqual(disabled_hints["sink_disabled"], Literal[True])
        self.assertEqual(
            disabled_hints["lifecycle_compatibility_state"],
            Literal["not_currently_disruptive"],
        )
        self.assertEqual(unknown_hints["sink_disabled"], types.NoneType)

        self.assertEqual(
            set(get_args(GcpLoggingSinkAuditTelemetryRelevanceEvidence)),
            {
                GcpLoggingSinkAllLogsRelevanceEvidence,
                GcpLoggingSinkAuditFilterRelevanceEvidence,
                GcpLoggingSinkIrrelevantFilterEvidence,
                GcpLoggingSinkUnknownRelevanceEvidence,
            },
        )
        self.assertEqual(all_logs_hints["sink_filter"], types.NoneType)
        self.assertEqual(all_logs_hints["relevance_basis"], Literal["all_logs"])
        self.assertEqual(filtered_hints["sink_filter"], str)
        self.assertEqual(
            filtered_hints["matched_audit_security_filter_signal"],
            str,
        )
        self.assertEqual(
            filtered_hints["audit_telemetry_relevance_state"],
            Literal["established"],
        )
        self.assertEqual(
            irrelevant_hints["audit_telemetry_relevance_state"],
            Literal["not_established"],
        )
        self.assertEqual(
            relevance_unknown_hints["audit_telemetry_relevance_state"],
            Literal["unknown"],
        )

    def test_gcp_outcome_contract_does_not_claim_log_or_destination_deletion(
        self,
    ) -> None:
        hints = get_type_hints(GcpLoggingSinkAuditTelemetryDisruptionOutcomeEvidence)

        self.assertEqual(hints["successful_operation_observed"], Literal[False])
        self.assertEqual(
            hints["historical_log_entry_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            hints["destination_resource_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            hints["unique_writer_identity_side_effect_evaluated"],
            Literal[False],
        )
        self.assertEqual(hints["all_project_audit_sinks_evaluated"], Literal[False])
        self.assertEqual(hints["restoration_observed"], Literal[False])

    def test_gcp_system_managed_sinks_cannot_form_disruption_paths(self) -> None:
        user_hints = get_type_hints(GcpLoggingSinkUserManagedDeletionConstraintEvidence)
        system_hints = get_type_hints(GcpLoggingSinkSystemManagedDeletionConstraintEvidence)
        unknown_hints = get_type_hints(GcpLoggingSinkUnknownDeletionConstraintEvidence)

        self.assertEqual(
            set(get_args(GcpLoggingSinkDeletionConstraintEvidence)),
            {
                GcpLoggingSinkUserManagedDeletionConstraintEvidence,
                GcpLoggingSinkSystemManagedDeletionConstraintEvidence,
                GcpLoggingSinkUnknownDeletionConstraintEvidence,
            },
        )
        self.assertEqual(user_hints["api_deletion_supported"], Literal[True])
        self.assertEqual(
            user_hints["deletion_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            system_hints["system_sink_name"],
            Literal["_Default", "_Required"],
        )
        self.assertEqual(
            system_hints["api_deletion_supported"],
            Literal[False],
        )
        self.assertEqual(
            system_hints["deletion_compatibility_state"],
            Literal["blocked"],
        )
        self.assertEqual(
            unknown_hints["api_deletion_supported"],
            types.NoneType,
        )

    def test_azure_path_requires_exact_actions_rbac_and_modeled_ancestry(
        self,
    ) -> None:
        path_hints = get_type_hints(AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath)
        grant_hints = get_type_hints(AzureDiagnosticSettingDeletionAuthorizationGrant)
        built_in_hints = get_type_hints(AzureDiagnosticSettingBuiltInRoleEvidence)
        custom_hints = get_type_hints(AzureDiagnosticSettingCustomRoleEvidence)

        self.assertEqual(
            path_hints["operation"],
            Literal["Microsoft.Insights/DiagnosticSettings/Delete"],
        )
        self.assertEqual(
            path_hints["operation_class"],
            Literal["diagnostic_setting_deletion"],
        )
        self.assertEqual(
            path_hints["target_scope"],
            Literal["exact_monitor_diagnostic_setting"],
        )
        self.assertEqual(
            path_hints["authorization_evidence_kind"],
            Literal["azure_rbac_action"],
        )
        self.assertEqual(path_hints["credential_context"], Literal["workload_runtime"])
        self.assertEqual(path_hints["diagnostic_setting_reference"], str)
        self.assertEqual(
            set(get_args(path_hints["diagnostic_setting_id"])),
            {str, types.NoneType},
        )
        self.assertEqual(path_hints["diagnostic_setting_arm_id"], str)
        self.assertEqual(path_hints["monitored_resource_address"], str)
        self.assertEqual(path_hints["modeled_allow_evidence_complete"], Literal[True])
        self.assertEqual(path_hints["condition"], types.NoneType)
        self.assertEqual(path_hints["condition_state"], Literal["not_configured"])
        self.assertEqual(
            grant_hints["requested_actions"],
            list[Literal["Microsoft.Insights/DiagnosticSettings/Delete"]],
        )
        self.assertEqual(grant_hints["matched_actions"], grant_hints["requested_actions"])
        self.assertEqual(grant_hints["excluded_actions"], list[Never])
        self.assertEqual(grant_hints["assignment_condition"], types.NoneType)
        self.assertEqual(
            grant_hints["diagnostic_settings_data_actions_authorization_effect"],
            Literal["not_used_for_arm_diagnostic_setting_deletion"],
        )
        self.assertEqual(
            built_in_hints["role_resolution_state"],
            Literal["modeled_subset"],
        )
        self.assertEqual(
            custom_hints["assignable_scope_compatibility_state"],
            Literal["resolved"],
        )

    def test_azure_destination_relevance_and_lock_variants_are_discriminated(
        self,
    ) -> None:
        log_analytics_hints = get_type_hints(AzureDiagnosticSettingLogAnalyticsDestinationEvidence)
        storage_hints = get_type_hints(AzureDiagnosticSettingStorageDestinationEvidence)
        eventhub_hints = get_type_hints(AzureDiagnosticSettingEventHubDestinationEvidence)
        marketplace_hints = get_type_hints(AzureDiagnosticSettingMarketplaceDestinationEvidence)
        unknown_destination_hints = get_type_hints(AzureDiagnosticSettingUnknownDestinationEvidence)
        category_hints = get_type_hints(AzureDiagnosticSettingAuditCategoryRelevanceEvidence)
        group_hints = get_type_hints(AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence)
        irrelevant_hints = get_type_hints(AzureDiagnosticSettingIrrelevantCategoriesEvidence)
        unknown_category_hints = get_type_hints(AzureDiagnosticSettingUnknownCategoriesEvidence)
        lock_clear_hints = get_type_hints(AzureDiagnosticSettingManagementLockNotObserved)
        lock_blocking_hints = get_type_hints(AzureDiagnosticSettingManagementLockBlocking)
        lock_unknown_hints = get_type_hints(AzureDiagnosticSettingManagementLockUnknown)

        self.assertEqual(
            set(get_args(AzureDiagnosticSettingDestinationEvidence)),
            {
                AzureDiagnosticSettingLogAnalyticsDestinationEvidence,
                AzureDiagnosticSettingStorageDestinationEvidence,
                AzureDiagnosticSettingEventHubDestinationEvidence,
                AzureDiagnosticSettingMarketplaceDestinationEvidence,
                AzureDiagnosticSettingUnknownDestinationEvidence,
            },
        )
        self.assertEqual(
            set(get_args(AzureDiagnosticSettingConfiguredDestinationEvidence)),
            {
                AzureDiagnosticSettingLogAnalyticsDestinationEvidence,
                AzureDiagnosticSettingStorageDestinationEvidence,
                AzureDiagnosticSettingEventHubDestinationEvidence,
                AzureDiagnosticSettingMarketplaceDestinationEvidence,
            },
        )
        self.assertEqual(log_analytics_hints["log_analytics_workspace_id"], str)
        self.assertEqual(storage_hints["storage_account_id"], str)
        self.assertEqual(eventhub_hints["eventhub_authorization_rule_id"], str)
        self.assertEqual(
            marketplace_hints["marketplace_partner_resource_id"],
            str,
        )
        self.assertEqual(
            unknown_destination_hints["destination_state"],
            Literal["unknown"],
        )

        self.assertEqual(
            set(get_args(AzureDiagnosticSettingAuditTelemetryRelevanceEvidence)),
            {
                AzureDiagnosticSettingAuditCategoryRelevanceEvidence,
                AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence,
                AzureDiagnosticSettingIrrelevantCategoriesEvidence,
                AzureDiagnosticSettingUnknownCategoriesEvidence,
            },
        )
        self.assertEqual(category_hints["matched_audit_security_category"], str)
        self.assertEqual(
            group_hints["matched_audit_security_category_group"],
            str,
        )
        self.assertEqual(
            irrelevant_hints["audit_telemetry_relevance_state"],
            Literal["not_established"],
        )
        self.assertEqual(
            unknown_category_hints["audit_telemetry_relevance_state"],
            Literal["unknown"],
        )

        self.assertEqual(
            set(get_args(AzureDiagnosticSettingManagementLockEvidence)),
            {
                AzureDiagnosticSettingManagementLockNotObserved,
                AzureDiagnosticSettingManagementLockBlocking,
                AzureDiagnosticSettingManagementLockUnknown,
            },
        )
        self.assertEqual(
            lock_clear_hints["deletion_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            lock_blocking_hints["blocking_lock_level"],
            Literal["CanNotDelete", "ReadOnly"],
        )
        self.assertEqual(
            lock_unknown_hints["deletion_compatibility_state"],
            Literal["unknown"],
        )

    def test_azure_path_admits_only_configured_relevant_unlocked_evidence(
        self,
    ) -> None:
        hints = get_type_hints(AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath)
        outcome_hints = get_type_hints(AzureDiagnosticSettingAuditTelemetryDisruptionOutcomeEvidence)

        self.assertEqual(
            hints["destination_evidence"],
            AzureDiagnosticSettingConfiguredDestinationEvidence,
        )
        self.assertEqual(
            hints["audit_telemetry_relevance_evidence"],
            (
                AzureDiagnosticSettingAuditCategoryRelevanceEvidence
                | AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence
            ),
        )
        self.assertEqual(
            hints["management_lock_evidence"],
            AzureDiagnosticSettingManagementLockNotObserved,
        )
        self.assertEqual(
            hints["lifecycle_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            outcome_hints["successful_operation_observed"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["historical_log_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["destination_resource_deletion_authorized_by_operation"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["all_resource_diagnostic_settings_evaluated"],
            Literal[False],
        )
        self.assertEqual(
            outcome_hints["restoration_observed"],
            Literal[False],
        )


if __name__ == "__main__":
    unittest.main()
