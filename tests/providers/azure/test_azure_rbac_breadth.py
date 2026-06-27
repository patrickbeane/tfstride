from __future__ import annotations

import unittest

from tfstride.providers.azure.rbac_breadth import (
    AUTHORIZATION_MANAGEMENT,
    COMPUTE_MANAGEMENT,
    KEY_VAULT_DATA_PLANE,
    NETWORK_MANAGEMENT,
    OWNER_LIKE_OR_WILDCARD,
    RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
    ROLE_ASSIGNMENT_CAPABLE,
    STORAGE_DATA_PLANE,
    UNKNOWN_CUSTOM_WILDCARD,
    classify_role_definition_breadth,
)


class AzureRbacBreadthClassifierTests(unittest.TestCase):
    def test_owner_wildcard_preserves_not_actions_as_mitigating_evidence(self) -> None:
        breadth = classify_role_definition_breadth(
            actions=["*"],
            not_actions=["Microsoft.Authorization/elevateAccess/Action"],
            data_actions=["*"],
            not_data_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
        )

        self.assertEqual(breadth.signals, (OWNER_LIKE_OR_WILDCARD,))
        self.assertEqual(breadth.mitigating_actions, ("Microsoft.Authorization/elevateAccess/Action",))
        self.assertEqual(
            breadth.mitigating_data_actions,
            ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",),
        )
        self.assertEqual(
            breadth.mitigations,
            (
                "not_action=Microsoft.Authorization/elevateAccess/Action",
                "not_data_action=Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            ),
        )

    def test_authorization_wildcard_is_role_assignment_capable(self) -> None:
        breadth = classify_role_definition_breadth(actions=["Microsoft.Authorization/*"])

        self.assertEqual(breadth.signals, (AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE))

    def test_role_assignment_write_is_role_assignment_capable(self) -> None:
        breadth = classify_role_definition_breadth(actions=["Microsoft.Authorization/roleAssignments/write"])

        self.assertEqual(breadth.signals, (AUTHORIZATION_MANAGEMENT, ROLE_ASSIGNMENT_CAPABLE))

    def test_storage_container_read_is_storage_data_plane_not_authorization_management(self) -> None:
        breadth = classify_role_definition_breadth(
            actions=["Microsoft.Storage/storageAccounts/blobServices/containers/read"]
        )

        self.assertEqual(breadth.signals, (STORAGE_DATA_PLANE,))
        self.assertNotIn(AUTHORIZATION_MANAGEMENT, breadth.signals)
        self.assertNotIn(ROLE_ASSIGNMENT_CAPABLE, breadth.signals)

    def test_key_vault_data_action_is_key_vault_data_plane(self) -> None:
        breadth = classify_role_definition_breadth(
            data_actions=["Microsoft.KeyVault/vaults/secrets/readMetadata/action"]
        )

        self.assertEqual(breadth.signals, (KEY_VAULT_DATA_PLANE,))

    def test_compute_network_and_resource_scope_management_are_classified(self) -> None:
        breadth = classify_role_definition_breadth(
            actions=[
                "Microsoft.Compute/virtualMachines/*",
                "Microsoft.Network/networkSecurityGroups/*",
                "Microsoft.Resources/subscriptions/resourceGroups/*",
            ]
        )

        self.assertEqual(
            breadth.signals,
            (
                COMPUTE_MANAGEMENT,
                NETWORK_MANAGEMENT,
                RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT,
            ),
        )

    def test_unknown_custom_wildcard_is_classified_without_overmapping(self) -> None:
        breadth = classify_role_definition_breadth(actions=["Contoso.Custom/widgets/*"])

        self.assertEqual(breadth.signals, (UNKNOWN_CUSTOM_WILDCARD,))


if __name__ == "__main__":
    unittest.main()
