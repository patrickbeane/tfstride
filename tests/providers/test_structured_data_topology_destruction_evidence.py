from __future__ import annotations

import types
import unittest
from typing import Literal, Never, get_args, get_type_hints

from tfstride.providers.aws.structured_data_topology_destruction_evidence import (
    AwsDynamoDbTableDeletionCompatibleConstraintEvidence,
    AwsDynamoDbTableDeletionConstraintEvidence,
    AwsDynamoDbTableDeletionProtectionDisabled,
    AwsDynamoDbTableDeletionProtectionEnabled,
    AwsDynamoDbTableDeletionProtectionProviderDefault,
    AwsDynamoDbTableDeletionProtectionUnknown,
    AwsDynamoDbTablePitrDisabledRecoveryEvidence,
    AwsDynamoDbTablePitrEnabledRecoveryEvidence,
    AwsDynamoDbTablePitrProviderDefaultRecoveryEvidence,
    AwsDynamoDbTablePitrUnknownRecoveryEvidence,
    AwsDynamoDbTableTopologyDestructionRecoveryEvidence,
    AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence,
    AwsDynamoDbTableTopologyPolicyStatementEvidence,
    AwsDynamoDbTableTopologyResourcePolicyStatementEvidence,
    AwsEcsDynamoDbCrossAccountTableDeletionPath,
    AwsEcsDynamoDbSameAccountCombinedTableDeletionPath,
    AwsEcsDynamoDbSameAccountIdentityTableDeletionPath,
    AwsEcsDynamoDbSameAccountTablePolicyDeletionPath,
    AwsEcsDynamoDbTableTopologyDestructionPath,
)
from tfstride.providers.azure.structured_data_topology_destruction_evidence import (
    AzureAppServiceCosmosDbAccountTopologyDeletionPath,
    AzureAppServiceCosmosDbContainerTopologyDeletionPath,
    AzureAppServiceCosmosDbDatabaseTopologyDeletionPath,
    AzureAppServiceCosmosDbTopologyDestructionPath,
    AzureCosmosDbAccountDeletionAuthorizationGrant,
    AzureCosmosDbContainerDeletionAuthorizationGrant,
    AzureCosmosDbDatabaseDeletionAuthorizationGrant,
    AzureCosmosDbTopologyBuiltInRoleEvidence,
    AzureCosmosDbTopologyContinuousBackupRecoveryEvidence,
    AzureCosmosDbTopologyCustomRoleEvidence,
    AzureCosmosDbTopologyDestructionRecoveryEvidence,
    AzureCosmosDbTopologyManagementLockBlocking,
    AzureCosmosDbTopologyManagementLockEvidence,
    AzureCosmosDbTopologyManagementLockNotObserved,
    AzureCosmosDbTopologyManagementLockUnknown,
    AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence,
    AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence,
    AzureCosmosDbTopologyUnknownBackupRecoveryEvidence,
)
from tfstride.providers.gcp.structured_data_topology_destruction_evidence import (
    GcpCloudRunFirestoreDatabaseTopologyDestructionPath,
    GcpCloudRunFirestoreExactDatabaseTopologyDeletionPath,
    GcpCloudRunFirestoreProjectDatabaseTopologyDeletionPath,
    GcpFirestoreDatabaseDeleteProtectionDisabled,
    GcpFirestoreDatabaseDeleteProtectionEnabled,
    GcpFirestoreDatabaseDeleteProtectionProviderDefault,
    GcpFirestoreDatabaseDeleteProtectionUnknown,
    GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence,
    GcpFirestoreDatabaseDeletionConstraintEvidence,
    GcpFirestoreDatabasePitrDisabledRecoveryEvidence,
    GcpFirestoreDatabasePitrEnabledRecoveryEvidence,
    GcpFirestoreDatabasePitrProviderDefaultRecoveryEvidence,
    GcpFirestoreDatabasePitrUnknownRecoveryEvidence,
    GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence,
    GcpFirestoreTerraformDeletionPolicyConfigured,
    GcpFirestoreTerraformDeletionPolicyEvidence,
    GcpFirestoreTerraformDeletionPolicyNotConfigured,
    GcpFirestoreTerraformDeletionPolicyUnknown,
    GcpFirestoreTopologyCustomRoleEvidence,
    GcpFirestoreTopologyDatabaseBuiltInRoleEvidence,
    GcpFirestoreTopologyProjectBuiltInRoleEvidence,
)


class StructuredDataTopologyDestructionEvidenceTests(unittest.TestCase):
    def test_aws_contract_discriminates_same_and_cross_account_proofs(
        self,
    ) -> None:
        same_identity_hints = get_type_hints(AwsEcsDynamoDbSameAccountIdentityTableDeletionPath)
        same_policy_hints = get_type_hints(AwsEcsDynamoDbSameAccountTablePolicyDeletionPath)
        same_combined_hints = get_type_hints(AwsEcsDynamoDbSameAccountCombinedTableDeletionPath)
        cross_account_hints = get_type_hints(AwsEcsDynamoDbCrossAccountTableDeletionPath)
        identity_statement_hints = get_type_hints(AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence)
        resource_statement_hints = get_type_hints(AwsDynamoDbTableTopologyResourcePolicyStatementEvidence)

        self.assertEqual(
            set(get_args(AwsEcsDynamoDbTableTopologyDestructionPath)),
            {
                AwsEcsDynamoDbSameAccountIdentityTableDeletionPath,
                AwsEcsDynamoDbSameAccountTablePolicyDeletionPath,
                AwsEcsDynamoDbSameAccountCombinedTableDeletionPath,
                AwsEcsDynamoDbCrossAccountTableDeletionPath,
            },
        )
        self.assertEqual(
            same_identity_hints["operation"],
            Literal["dynamodb:DeleteTable"],
        )
        self.assertEqual(
            same_identity_hints["target_granularity"],
            Literal["table_topology"],
        )
        self.assertEqual(
            same_identity_hints["target_scope"],
            Literal["exact_dynamodb_table"],
        )
        self.assertEqual(
            same_identity_hints["deletion_constraint_evidence"],
            AwsDynamoDbTableDeletionCompatibleConstraintEvidence,
        )
        self.assertEqual(
            same_identity_hints["credential_context"],
            Literal["workload_runtime"],
        )
        self.assertEqual(
            same_identity_hints["grant_basis"],
            Literal["same_account_identity_policy"],
        )
        self.assertEqual(same_identity_hints["same_account"], Literal[True])
        self.assertEqual(
            same_identity_hints["table_policy_allow_required"],
            Literal[False],
        )
        self.assertIs(
            same_identity_hints["resource_policy_principal_match"],
            types.NoneType,
        )

        self.assertEqual(
            same_policy_hints["grant_basis"],
            Literal["same_account_table_policy_direct"],
        )
        self.assertEqual(
            same_policy_hints["identity_policy_allow_required"],
            Literal[False],
        )
        self.assertEqual(
            same_policy_hints["resource_policy_principal_match"],
            Literal["role"],
        )
        self.assertEqual(
            same_combined_hints["grant_basis"],
            Literal["same_account_combined"],
        )
        self.assertEqual(
            cross_account_hints["account_relationship"],
            Literal["cross_account"],
        )
        self.assertEqual(cross_account_hints["same_account"], Literal[False])
        self.assertEqual(
            cross_account_hints["grant_basis"],
            Literal["cross_account_identity_and_table_policy"],
        )
        self.assertEqual(
            cross_account_hints["identity_policy_allow_required"],
            Literal[True],
        )
        self.assertEqual(
            cross_account_hints["table_policy_allow_required"],
            Literal[True],
        )

        self.assertEqual(
            set(get_args(AwsDynamoDbTableTopologyPolicyStatementEvidence)),
            {
                AwsDynamoDbTableTopologyIdentityPolicyStatementEvidence,
                AwsDynamoDbTableTopologyResourcePolicyStatementEvidence,
            },
        )
        for statement_hints in (identity_statement_hints, resource_statement_hints):
            self.assertEqual(
                statement_hints["resource_scopes"],
                list[Literal["exact_table", "table_pattern"]],
            )
        self.assertEqual(
            identity_statement_hints["source_kind"],
            Literal["identity_policy"],
        )
        self.assertEqual(
            identity_statement_hints["principals"],
            list[Never],
        )
        self.assertEqual(
            resource_statement_hints["source_kind"],
            Literal["table_policy"],
        )
        self.assertEqual(
            resource_statement_hints["principal_match"],
            Literal["role", "account", "wildcard"],
        )

    def test_aws_constraints_and_recovery_do_not_admit_protected_paths(
        self,
    ) -> None:
        enabled_hints = get_type_hints(AwsDynamoDbTableDeletionProtectionEnabled)
        disabled_hints = get_type_hints(AwsDynamoDbTableDeletionProtectionDisabled)
        default_hints = get_type_hints(AwsDynamoDbTableDeletionProtectionProviderDefault)
        unknown_hints = get_type_hints(AwsDynamoDbTableDeletionProtectionUnknown)
        pitr_hints = get_type_hints(AwsDynamoDbTablePitrEnabledRecoveryEvidence)

        self.assertEqual(
            set(get_args(AwsDynamoDbTableDeletionConstraintEvidence)),
            {
                AwsDynamoDbTableDeletionProtectionEnabled,
                AwsDynamoDbTableDeletionProtectionDisabled,
                AwsDynamoDbTableDeletionProtectionProviderDefault,
                AwsDynamoDbTableDeletionProtectionUnknown,
            },
        )
        self.assertEqual(
            set(get_args(AwsDynamoDbTableDeletionCompatibleConstraintEvidence)),
            {
                AwsDynamoDbTableDeletionProtectionDisabled,
                AwsDynamoDbTableDeletionProtectionProviderDefault,
            },
        )
        self.assertEqual(
            enabled_hints["deletion_compatibility_state"],
            Literal["blocked"],
        )
        self.assertEqual(
            disabled_hints["deletion_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            default_hints["deletion_protection_enabled"],
            Literal[False],
        )
        self.assertEqual(default_hints["provider_default_applied"], Literal[True])
        self.assertEqual(
            unknown_hints["deletion_compatibility_state"],
            Literal["unknown"],
        )

        self.assertEqual(
            set(get_args(AwsDynamoDbTableTopologyDestructionRecoveryEvidence)),
            {
                AwsDynamoDbTablePitrEnabledRecoveryEvidence,
                AwsDynamoDbTablePitrDisabledRecoveryEvidence,
                AwsDynamoDbTablePitrProviderDefaultRecoveryEvidence,
                AwsDynamoDbTablePitrUnknownRecoveryEvidence,
            },
        )
        self.assertEqual(
            pitr_hints["restore_target_kind"],
            Literal["new_table"],
        )
        self.assertEqual(
            pitr_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(pitr_hints["restoration_observed"], Literal[False])
        self.assertEqual(
            pitr_hints["runtime_table_state_evaluated"],
            Literal[False],
        )

    def test_gcp_contract_discriminates_project_and_exact_database_scope(
        self,
    ) -> None:
        project_hints = get_type_hints(GcpCloudRunFirestoreProjectDatabaseTopologyDeletionPath)
        database_hints = get_type_hints(GcpCloudRunFirestoreExactDatabaseTopologyDeletionPath)
        project_role_hints = get_type_hints(GcpFirestoreTopologyProjectBuiltInRoleEvidence)
        database_role_hints = get_type_hints(GcpFirestoreTopologyDatabaseBuiltInRoleEvidence)
        custom_role_hints = get_type_hints(GcpFirestoreTopologyCustomRoleEvidence)

        self.assertEqual(
            set(get_args(GcpCloudRunFirestoreDatabaseTopologyDestructionPath)),
            {
                GcpCloudRunFirestoreProjectDatabaseTopologyDeletionPath,
                GcpCloudRunFirestoreExactDatabaseTopologyDeletionPath,
            },
        )
        self.assertEqual(
            project_hints["operation"],
            Literal["datastore.databases.delete"],
        )
        self.assertEqual(project_hints["scope_type"], Literal["project"])
        self.assertEqual(
            project_hints["grant_basis"],
            Literal["firestore_project_iam"],
        )
        self.assertIs(project_hints["condition"], types.NoneType)
        self.assertEqual(database_hints["scope_type"], Literal["database"])
        self.assertEqual(
            database_hints["condition_evaluation"],
            Literal["exact_database_scope_match"],
        )
        self.assertEqual(
            database_hints["target_scope"],
            Literal["exact_firestore_database"],
        )
        self.assertEqual(
            project_hints["iam_manager_ambiguity_state"],
            Literal["not_detected"],
        )
        self.assertEqual(
            project_hints["matched_permissions"],
            list[Literal["datastore.databases.delete"]],
        )
        self.assertEqual(
            project_hints["deletion_constraint_evidence"],
            GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence,
        )

        self.assertEqual(
            project_role_hints["role_kind"],
            Literal[
                "owner",
                "datastore_owner",
                "datastore_admin",
                "firebase_admin",
                "firebase_develop_admin",
            ],
        )
        self.assertEqual(
            database_role_hints["role_kind"],
            Literal[
                "datastore_owner",
                "datastore_admin",
                "firebase_admin",
                "firebase_develop_admin",
            ],
        )
        self.assertEqual(
            custom_role_hints["custom_role_deleted"],
            Literal[False],
        )
        self.assertEqual(
            custom_role_hints["custom_role_wildcard_permissions_present"],
            Literal[False],
        )
        self.assertEqual(
            custom_role_hints["custom_role_grant_scope_compatibility_state"],
            Literal["compatible"],
        )

    def test_gcp_constraints_recovery_and_terraform_policy_remain_separate(
        self,
    ) -> None:
        enabled_hints = get_type_hints(GcpFirestoreDatabaseDeleteProtectionEnabled)
        default_hints = get_type_hints(GcpFirestoreDatabaseDeleteProtectionProviderDefault)
        pitr_hints = get_type_hints(GcpFirestoreDatabasePitrEnabledRecoveryEvidence)
        policy_hints = get_type_hints(GcpFirestoreTerraformDeletionPolicyConfigured)

        self.assertEqual(
            set(get_args(GcpFirestoreDatabaseDeletionConstraintEvidence)),
            {
                GcpFirestoreDatabaseDeleteProtectionEnabled,
                GcpFirestoreDatabaseDeleteProtectionDisabled,
                GcpFirestoreDatabaseDeleteProtectionProviderDefault,
                GcpFirestoreDatabaseDeleteProtectionUnknown,
            },
        )
        self.assertEqual(
            set(get_args(GcpFirestoreDatabaseDeletionCompatibleConstraintEvidence)),
            {
                GcpFirestoreDatabaseDeleteProtectionDisabled,
                GcpFirestoreDatabaseDeleteProtectionProviderDefault,
            },
        )
        self.assertEqual(
            enabled_hints["deletion_compatibility_state"],
            Literal["blocked"],
        )
        self.assertEqual(
            default_hints["delete_protection_enabled"],
            Literal[False],
        )
        self.assertEqual(default_hints["provider_default_applied"], Literal[True])

        self.assertEqual(
            set(get_args(GcpFirestoreDatabaseTopologyDestructionRecoveryEvidence)),
            {
                GcpFirestoreDatabasePitrEnabledRecoveryEvidence,
                GcpFirestoreDatabasePitrDisabledRecoveryEvidence,
                GcpFirestoreDatabasePitrProviderDefaultRecoveryEvidence,
                GcpFirestoreDatabasePitrUnknownRecoveryEvidence,
            },
        )
        self.assertEqual(
            pitr_hints["database_recovery_state"],
            Literal["not_established_by_modeled_firestore_pitr_evidence"],
        )
        self.assertEqual(
            pitr_hints["app_engine_search_and_blob_entity_prerequisite_state"],
            Literal["not_established"],
        )
        self.assertEqual(
            pitr_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(pitr_hints["restoration_observed"], Literal[False])

        self.assertEqual(
            set(get_args(GcpFirestoreTerraformDeletionPolicyEvidence)),
            {
                GcpFirestoreTerraformDeletionPolicyConfigured,
                GcpFirestoreTerraformDeletionPolicyNotConfigured,
                GcpFirestoreTerraformDeletionPolicyUnknown,
            },
        )
        self.assertEqual(
            policy_hints["policy"],
            Literal["ABANDON", "DELETE"],
        )
        self.assertEqual(
            policy_hints["runtime_api_authorization_effect"],
            Literal["none"],
        )

    def test_azure_contract_discriminates_every_arm_topology_target(
        self,
    ) -> None:
        account_hints = get_type_hints(AzureAppServiceCosmosDbAccountTopologyDeletionPath)
        database_hints = get_type_hints(AzureAppServiceCosmosDbDatabaseTopologyDeletionPath)
        container_hints = get_type_hints(AzureAppServiceCosmosDbContainerTopologyDeletionPath)
        built_in_hints = get_type_hints(AzureCosmosDbTopologyBuiltInRoleEvidence)
        custom_hints = get_type_hints(AzureCosmosDbTopologyCustomRoleEvidence)

        self.assertEqual(
            set(get_args(AzureAppServiceCosmosDbTopologyDestructionPath)),
            {
                AzureAppServiceCosmosDbAccountTopologyDeletionPath,
                AzureAppServiceCosmosDbDatabaseTopologyDeletionPath,
                AzureAppServiceCosmosDbContainerTopologyDeletionPath,
            },
        )
        cases = (
            (
                account_hints,
                Literal["Microsoft.DocumentDB/databaseAccounts/delete"],
                Literal["account_deletion"],
                Literal["account_topology"],
                AzureCosmosDbAccountDeletionAuthorizationGrant,
            ),
            (
                database_hints,
                Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete"],
                Literal["database_deletion"],
                Literal["database_topology"],
                AzureCosmosDbDatabaseDeletionAuthorizationGrant,
            ),
            (
                container_hints,
                Literal["Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"],
                Literal["container_deletion"],
                Literal["container_topology"],
                AzureCosmosDbContainerDeletionAuthorizationGrant,
            ),
        )
        for (
            hints,
            operation,
            operation_class,
            granularity,
            grant_type,
        ) in cases:
            with self.subTest(operation=operation):
                self.assertEqual(hints["operation"], operation)
                self.assertEqual(hints["operation_class"], operation_class)
                self.assertEqual(hints["target_granularity"], granularity)
                self.assertEqual(hints["authorization_grant"], grant_type)
                self.assertEqual(
                    hints["authorization_evidence_kind"],
                    Literal["azure_rbac_action"],
                )
                self.assertEqual(
                    hints["lifecycle_compatibility_state"],
                    Literal["compatible"],
                )

        self.assertIs(account_hints["cosmosdb_database_address"], types.NoneType)
        self.assertIs(account_hints["cosmosdb_container_address"], types.NoneType)
        self.assertEqual(database_hints["cosmosdb_database_address"], str)
        self.assertIs(database_hints["cosmosdb_container_address"], types.NoneType)
        self.assertEqual(container_hints["cosmosdb_database_address"], str)
        self.assertEqual(container_hints["cosmosdb_container_address"], str)
        self.assertEqual(
            built_in_hints["role_resolution_state"],
            Literal["modeled_subset"],
        )
        self.assertIs(
            built_in_hints["role_definition_address"],
            types.NoneType,
        )
        self.assertEqual(
            custom_hints["assignable_scope_compatibility_state"],
            Literal["resolved"],
        )

    def test_azure_locks_and_backup_do_not_claim_outcomes(self) -> None:
        account_grant_hints = get_type_hints(AzureCosmosDbAccountDeletionAuthorizationGrant)
        no_lock_hints = get_type_hints(AzureCosmosDbTopologyManagementLockNotObserved)
        blocking_hints = get_type_hints(AzureCosmosDbTopologyManagementLockBlocking)
        unknown_lock_hints = get_type_hints(AzureCosmosDbTopologyManagementLockUnknown)
        continuous_hints = get_type_hints(AzureCosmosDbTopologyContinuousBackupRecoveryEvidence)
        default_hints = get_type_hints(AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence)

        self.assertEqual(
            account_grant_hints["requested_actions"],
            list[Literal["Microsoft.DocumentDB/databaseAccounts/delete"]],
        )
        self.assertEqual(account_grant_hints["excluded_actions"], list[Never])
        self.assertEqual(
            account_grant_hints["cosmosdb_native_data_actions_authorization_effect"],
            Literal["not_used_for_arm_topology_deletion"],
        )

        self.assertEqual(
            set(get_args(AzureCosmosDbTopologyManagementLockEvidence)),
            {
                AzureCosmosDbTopologyManagementLockNotObserved,
                AzureCosmosDbTopologyManagementLockBlocking,
                AzureCosmosDbTopologyManagementLockUnknown,
            },
        )
        account_path_hints = get_type_hints(AzureAppServiceCosmosDbAccountTopologyDeletionPath)
        self.assertEqual(
            account_path_hints["management_lock_evidence"],
            AzureCosmosDbTopologyManagementLockNotObserved,
        )
        self.assertEqual(
            no_lock_hints["deletion_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            no_lock_hints["applicable_lock_addresses"],
            list[Never],
        )
        self.assertEqual(
            blocking_hints["blocking_lock_level"],
            Literal["CanNotDelete", "ReadOnly"],
        )
        self.assertEqual(
            blocking_hints["deletion_compatibility_state"],
            Literal["blocked"],
        )
        self.assertEqual(
            unknown_lock_hints["deletion_compatibility_state"],
            Literal["unknown"],
        )

        self.assertEqual(
            set(get_args(AzureCosmosDbTopologyDestructionRecoveryEvidence)),
            {
                AzureCosmosDbTopologyContinuousBackupRecoveryEvidence,
                AzureCosmosDbTopologyPeriodicBackupRecoveryEvidence,
                AzureCosmosDbTopologyProviderDefaultBackupRecoveryEvidence,
                AzureCosmosDbTopologyUnknownBackupRecoveryEvidence,
            },
        )
        self.assertEqual(
            continuous_hints["topology_recovery_state"],
            Literal["continuous_backup_recovery_configured"],
        )
        self.assertEqual(
            continuous_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(
            continuous_hints["restoration_observed"],
            Literal[False],
        )
        self.assertEqual(
            continuous_hints["immediate_restoration_established"],
            Literal[False],
        )
        self.assertEqual(
            default_hints["backup_posture_state"],
            Literal["provider_default_periodic"],
        )
        self.assertEqual(default_hints["backup_interval_minutes"], Literal[240])
        self.assertEqual(default_hints["backup_retention_hours"], Literal[8])


if __name__ == "__main__":
    unittest.main()
