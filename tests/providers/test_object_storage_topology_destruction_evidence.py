from __future__ import annotations

import types
import unittest
from typing import Literal, Never, get_args, get_type_hints

from tfstride.providers.aws.object_storage_topology_destruction_evidence import (
    AwsEcsS3BucketTopologyDestructionPath,
    AwsS3BucketTopologyDestructionAuthorizationBasis,
    AwsS3BucketTopologyDestructionRecoveryEvidence,
    AwsS3BucketTopologyIdentityPolicyStatementEvidence,
    AwsS3BucketTopologyPolicyStatementEvidence,
    AwsS3BucketTopologyResourcePolicyStatementEvidence,
)
from tfstride.providers.azure.object_storage_topology_destruction_evidence import (
    AzureAppServiceStorageContainerTopologyDestructionCompatiblePath,
    AzureAppServiceStorageContainerTopologyDestructionPath,
    AzureAppServiceStorageContainerTopologyDestructionUnknownPath,
    AzureStorageContainerSoftDeleteDisabledRecoveryEvidence,
    AzureStorageContainerSoftDeleteEnabledRecoveryEvidence,
    AzureStorageContainerSoftDeleteUnknownRecoveryEvidence,
    AzureStorageContainerTopologyBuiltInRoleEvidence,
    AzureStorageContainerTopologyCustomRoleEvidence,
    AzureStorageContainerTopologyDeletionConstraintEvidence,
    AzureStorageContainerTopologyDeletionConstraintsBlocking,
    AzureStorageContainerTopologyDeletionConstraintsCompatible,
    AzureStorageContainerTopologyDeletionConstraintsUnknown,
    AzureStorageContainerTopologyDeletionImmutabilityBlocking,
    AzureStorageContainerTopologyDeletionLegalHoldBlocking,
    AzureStorageContainerTopologyDestructionAuthorizationGrant,
    AzureStorageContainerTopologyDestructionRecoveryEvidence,
)
from tfstride.providers.gcp.object_storage_topology_destruction_evidence import (
    GcpCloudRunGcsAncestorBucketTopologyDestructionPath,
    GcpCloudRunGcsBucketTopologyDestructionPath,
    GcpCloudRunGcsExactBucketTopologyDestructionPath,
    GcpCloudRunGcsProjectBucketTopologyDestructionPath,
    GcpGcsBucketSoftDeleteDisabledRecoveryEvidence,
    GcpGcsBucketSoftDeleteEnabledRecoveryEvidence,
    GcpGcsBucketSoftDeleteNotObservedRecoveryEvidence,
    GcpGcsBucketSoftDeleteUnknownRecoveryEvidence,
    GcpGcsBucketTopologyBucketBuiltInRoleEvidence,
    GcpGcsBucketTopologyCustomRoleEvidence,
    GcpGcsBucketTopologyDestructionRecoveryEvidence,
    GcpGcsBucketTopologyProjectBuiltInRoleEvidence,
)


class ObjectStorageTopologyDestructionEvidenceTests(unittest.TestCase):
    def test_aws_contract_requires_exact_same_account_bucket_authority(
        self,
    ) -> None:
        path_hints = get_type_hints(AwsEcsS3BucketTopologyDestructionPath)
        identity_hints = get_type_hints(AwsS3BucketTopologyIdentityPolicyStatementEvidence)
        resource_hints = get_type_hints(AwsS3BucketTopologyResourcePolicyStatementEvidence)

        self.assertEqual(path_hints["operation"], Literal["s3:DeleteBucket"])
        self.assertEqual(path_hints["operation_class"], Literal["bucket_deletion"])
        self.assertEqual(path_hints["target_granularity"], Literal["bucket_topology"])
        self.assertEqual(path_hints["target_scope"], Literal["exact_s3_bucket"])
        self.assertEqual(path_hints["same_account"], Literal[True])
        self.assertEqual(
            set(get_args(AwsS3BucketTopologyDestructionAuthorizationBasis)),
            {"identity_policy", "bucket_policy_direct"},
        )
        self.assertEqual(
            set(get_args(path_hints["role_arn"])),
            {str, types.NoneType},
        )
        self.assertEqual(path_hints["authorization_state"], Literal["allowed"])
        self.assertEqual(path_hints["identity_policy_complete"], Literal[True])
        self.assertEqual(path_hints["bucket_policy_complete"], Literal[True])
        self.assertEqual(path_hints["explicit_deny"], Literal[False])
        self.assertEqual(
            path_hints["conditional_evaluation_required"],
            Literal[False],
        )
        self.assertEqual(
            path_hints["lifecycle_compatibility_state"],
            Literal["bucket_emptiness_not_established"],
        )

        self.assertEqual(
            set(get_args(AwsS3BucketTopologyPolicyStatementEvidence)),
            {
                AwsS3BucketTopologyIdentityPolicyStatementEvidence,
                AwsS3BucketTopologyResourcePolicyStatementEvidence,
            },
        )
        self.assertEqual(identity_hints["source_kind"], Literal["identity_policy"])
        self.assertEqual(identity_hints["conditions"], list[Never])
        self.assertEqual(resource_hints["source_kind"], Literal["bucket_policy"])
        self.assertEqual(
            resource_hints["principal_match"],
            Literal["role", "account", "wildcard"],
        )

    def test_aws_recovery_contract_does_not_infer_emptiness_or_outcome(
        self,
    ) -> None:
        hints = get_type_hints(AwsS3BucketTopologyDestructionRecoveryEvidence)

        self.assertEqual(hints["bucket_emptiness_required"], Literal[True])
        self.assertEqual(hints["bucket_emptiness_state"], Literal["not_established"])
        self.assertEqual(
            hints["out_of_plan_object_inventory_evaluated"],
            Literal[False],
        )
        self.assertEqual(hints["successful_deletion_observed"], Literal[False])
        self.assertEqual(hints["recovery_observed"], Literal[False])
        self.assertEqual(
            hints["bucket_recovery_state"],
            Literal["not_established_by_modeled_aws_s3_bucket_evidence"],
        )

    def test_gcp_contract_discriminates_project_and_bucket_iam_scope(
        self,
    ) -> None:
        ancestor_hints = get_type_hints(GcpCloudRunGcsAncestorBucketTopologyDestructionPath)
        self.assertEqual(ancestor_hints["scope_type"], Literal["folder", "organization"])
        self.assertEqual(ancestor_hints["grant_basis"], Literal["gcs_folder_iam", "gcs_organization_iam"])
        self.assertEqual(ancestor_hints["resource_scope"], Literal["gcs_folder", "gcs_organization"])
        self.assertEqual(ancestor_hints["role_evidence"], GcpGcsBucketTopologyBucketBuiltInRoleEvidence)
        project_hints = get_type_hints(GcpCloudRunGcsProjectBucketTopologyDestructionPath)
        bucket_hints = get_type_hints(GcpCloudRunGcsExactBucketTopologyDestructionPath)
        project_role_hints = get_type_hints(GcpGcsBucketTopologyProjectBuiltInRoleEvidence)
        bucket_role_hints = get_type_hints(GcpGcsBucketTopologyBucketBuiltInRoleEvidence)
        custom_role_hints = get_type_hints(GcpGcsBucketTopologyCustomRoleEvidence)

        self.assertEqual(
            set(get_args(GcpCloudRunGcsBucketTopologyDestructionPath)),
            {
                GcpCloudRunGcsProjectBucketTopologyDestructionPath,
                GcpCloudRunGcsExactBucketTopologyDestructionPath,
                GcpCloudRunGcsAncestorBucketTopologyDestructionPath,
            },
        )
        self.assertEqual(
            project_hints["operation"],
            Literal["storage.buckets.delete"],
        )
        self.assertEqual(project_hints["scope_type"], Literal["project"])
        self.assertEqual(project_hints["grant_basis"], Literal["gcs_project_iam"])
        self.assertEqual(bucket_hints["scope_type"], Literal["bucket"])
        self.assertEqual(bucket_hints["grant_basis"], Literal["gcs_bucket_iam"])
        self.assertEqual(
            project_hints["matched_permissions"],
            list[Literal["storage.buckets.delete"]],
        )
        self.assertEqual(project_hints["authorization_state"], Literal["granted"])
        self.assertEqual(project_hints["policy_complete"], Literal[True])
        self.assertEqual(
            project_hints["iam_manager_ambiguity_state"],
            Literal["not_detected"],
        )
        self.assertEqual(
            project_role_hints["role_kind"],
            Literal["owner", "editor", "storage_admin", "storage_editor"],
        )
        self.assertEqual(
            bucket_role_hints["role_kind"],
            Literal["storage_admin", "storage_editor"],
        )
        self.assertEqual(custom_role_hints["custom_role_deleted"], Literal[False])
        self.assertEqual(
            custom_role_hints["custom_role_grant_scope_compatibility_state"],
            Literal["compatible"],
        )

    def test_gcp_recovery_contract_preserves_native_soft_delete_states(
        self,
    ) -> None:
        enabled_hints = get_type_hints(GcpGcsBucketSoftDeleteEnabledRecoveryEvidence)
        disabled_hints = get_type_hints(GcpGcsBucketSoftDeleteDisabledRecoveryEvidence)
        unknown_hints = get_type_hints(GcpGcsBucketSoftDeleteUnknownRecoveryEvidence)
        not_observed_hints = get_type_hints(GcpGcsBucketSoftDeleteNotObservedRecoveryEvidence)

        self.assertEqual(
            set(get_args(GcpGcsBucketTopologyDestructionRecoveryEvidence)),
            {
                GcpGcsBucketSoftDeleteEnabledRecoveryEvidence,
                GcpGcsBucketSoftDeleteDisabledRecoveryEvidence,
                GcpGcsBucketSoftDeleteUnknownRecoveryEvidence,
                GcpGcsBucketSoftDeleteNotObservedRecoveryEvidence,
            },
        )
        self.assertEqual(enabled_hints["soft_delete_state"], Literal["enabled"])
        self.assertEqual(
            enabled_hints["bucket_recovery_state"],
            Literal["soft_delete_recovery_configured"],
        )
        self.assertEqual(disabled_hints["soft_delete_state"], Literal["disabled"])
        self.assertEqual(
            disabled_hints["soft_delete_retention_duration_seconds"],
            Literal[0],
        )
        self.assertEqual(unknown_hints["bucket_recovery_state"], Literal["unknown"])
        self.assertEqual(
            not_observed_hints["bucket_recovery_state"],
            Literal["unknown"],
        )
        self.assertEqual(
            enabled_hints["bucket_emptiness_state"],
            Literal["not_established"],
        )
        self.assertEqual(
            enabled_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(enabled_hints["restoration_observed"], Literal[False])

    def test_azure_contract_requires_rbac_action_authority_and_exact_container(
        self,
    ) -> None:
        compatible_hints = get_type_hints(AzureAppServiceStorageContainerTopologyDestructionCompatiblePath)
        unknown_hints = get_type_hints(AzureAppServiceStorageContainerTopologyDestructionUnknownPath)
        grant_hints = get_type_hints(AzureStorageContainerTopologyDestructionAuthorizationGrant)
        built_in_hints = get_type_hints(AzureStorageContainerTopologyBuiltInRoleEvidence)
        custom_hints = get_type_hints(AzureStorageContainerTopologyCustomRoleEvidence)

        self.assertEqual(
            set(get_args(AzureAppServiceStorageContainerTopologyDestructionPath)),
            {
                AzureAppServiceStorageContainerTopologyDestructionCompatiblePath,
                AzureAppServiceStorageContainerTopologyDestructionUnknownPath,
            },
        )
        self.assertEqual(
            compatible_hints["operation"],
            Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"],
        )
        self.assertEqual(
            compatible_hints["authorization_evidence_kind"],
            Literal["azure_rbac_action"],
        )
        self.assertEqual(
            compatible_hints["target_scope"],
            Literal["exact_storage_container"],
        )
        self.assertEqual(
            compatible_hints["lifecycle_compatibility_state"],
            Literal["compatible"],
        )
        self.assertEqual(
            unknown_hints["lifecycle_compatibility_state"],
            Literal["unknown"],
        )
        self.assertEqual(
            grant_hints["requested_actions"],
            list[Literal["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]],
        )
        self.assertEqual(grant_hints["excluded_actions"], list[Never])
        self.assertEqual(
            grant_hints["evaluation_basis"],
            Literal["modeled_azure_rbac_action_authority"],
        )
        self.assertEqual(grant_hints["assignment_condition"], types.NoneType)
        self.assertEqual(
            grant_hints["assignment_condition_state"],
            Literal["not_configured"],
        )
        self.assertEqual(
            built_in_hints["role_resolution_state"],
            Literal["modeled_subset"],
        )
        self.assertEqual(
            custom_hints["assignable_scope_compatibility_state"],
            Literal["resolved"],
        )

    def test_azure_constraints_and_recovery_do_not_claim_outcomes(
        self,
    ) -> None:
        immutability_blocking_hints = get_type_hints(AzureStorageContainerTopologyDeletionImmutabilityBlocking)
        legal_hold_blocking_hints = get_type_hints(AzureStorageContainerTopologyDeletionLegalHoldBlocking)
        compatible_hints = get_type_hints(AzureStorageContainerTopologyDeletionConstraintsCompatible)
        unknown_hints = get_type_hints(AzureStorageContainerTopologyDeletionConstraintsUnknown)
        enabled_hints = get_type_hints(AzureStorageContainerSoftDeleteEnabledRecoveryEvidence)
        disabled_hints = get_type_hints(AzureStorageContainerSoftDeleteDisabledRecoveryEvidence)
        recovery_unknown_hints = get_type_hints(AzureStorageContainerSoftDeleteUnknownRecoveryEvidence)

        self.assertEqual(
            set(get_args(AzureStorageContainerTopologyDeletionConstraintEvidence)),
            {
                AzureStorageContainerTopologyDeletionConstraintsCompatible,
                AzureStorageContainerTopologyDeletionImmutabilityBlocking,
                AzureStorageContainerTopologyDeletionLegalHoldBlocking,
                AzureStorageContainerTopologyDeletionConstraintsUnknown,
            },
        )
        self.assertEqual(
            set(get_args(AzureStorageContainerTopologyDeletionConstraintsBlocking)),
            {
                AzureStorageContainerTopologyDeletionImmutabilityBlocking,
                AzureStorageContainerTopologyDeletionLegalHoldBlocking,
            },
        )
        self.assertEqual(compatible_hints["has_immutability_policy"], Literal[False])
        self.assertEqual(compatible_hints["has_legal_hold"], Literal[False])
        self.assertEqual(
            compatible_hints["protected_content_emptiness_required"],
            Literal[False],
        )
        self.assertEqual(
            compatible_hints["protected_content_emptiness_state"],
            Literal["not_applicable"],
        )
        self.assertEqual(
            compatible_hints["arm_management_lock_applicability"],
            Literal["not_applicable_to_storage_container_deletion"],
        )
        self.assertEqual(
            immutability_blocking_hints["constraint_state"],
            Literal["blocking"],
        )
        self.assertEqual(
            immutability_blocking_hints["has_immutability_policy"],
            Literal[True],
        )
        self.assertEqual(immutability_blocking_hints["has_legal_hold"], bool)
        self.assertEqual(
            legal_hold_blocking_hints["has_immutability_policy"],
            Literal[False],
        )
        self.assertEqual(
            legal_hold_blocking_hints["has_legal_hold"],
            Literal[True],
        )
        self.assertEqual(
            legal_hold_blocking_hints["uncertainties"],
            list[Never],
        )
        self.assertEqual(
            unknown_hints["constraint_state"],
            Literal["protected_content_emptiness_not_established", "unknown"],
        )
        self.assertEqual(
            unknown_hints["protected_content_emptiness_required"],
            bool | None,
        )
        self.assertEqual(
            unknown_hints["protected_content_emptiness_state"],
            Literal["not_established", "unknown"],
        )

        self.assertEqual(
            set(get_args(AzureStorageContainerTopologyDestructionRecoveryEvidence)),
            {
                AzureStorageContainerSoftDeleteEnabledRecoveryEvidence,
                AzureStorageContainerSoftDeleteDisabledRecoveryEvidence,
                AzureStorageContainerSoftDeleteUnknownRecoveryEvidence,
            },
        )
        self.assertEqual(
            enabled_hints["container_recovery_state"],
            Literal["soft_delete_recovery_configured"],
        )
        self.assertEqual(
            disabled_hints["container_recovery_state"],
            Literal["not_established_by_modeled_azure_storage_container_evidence"],
        )
        self.assertEqual(
            recovery_unknown_hints["container_recovery_state"],
            Literal["unknown"],
        )
        self.assertEqual(
            enabled_hints["successful_deletion_observed"],
            Literal[False],
        )
        self.assertEqual(enabled_hints["restoration_observed"], Literal[False])
        self.assertEqual(
            enabled_hints["storage_account_deletion_evaluated"],
            Literal[False],
        )


if __name__ == "__main__":
    unittest.main()
