from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.identity_normalizers import normalize_federated_identity_credential
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    values: dict[str, object],
    *,
    name: str = "github",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL}.{name}",
        mode="managed",
        resource_type=AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzureFederatedIdentityCredentialNormalizerTests(unittest.TestCase):
    def test_federated_identity_credential_normalizes_trust_attributes(self) -> None:
        credential = normalize_federated_identity_credential(
            _resource(
                {
                    "id": (
                        "/subscriptions/sub-0001/resourceGroups/app/providers/"
                        "Microsoft.ManagedIdentity/userAssignedIdentities/deploy/federatedIdentityCredentials/github"
                    ),
                    "name": "github",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:tfstride/tfstride:ref:refs/heads/main",
                    "audiences": ["api://AzureADTokenExchange"],
                    "parent_id": "azurerm_user_assigned_identity.deploy.id",
                }
            )
        )
        facts = azure_facts(credential)

        self.assertEqual(credential.category, ResourceCategory.IAM)
        self.assertEqual(
            credential.identifier,
            (
                "/subscriptions/sub-0001/resourceGroups/app/providers/"
                "Microsoft.ManagedIdentity/userAssignedIdentities/deploy/federatedIdentityCredentials/github"
            ),
        )
        self.assertEqual(facts.federated_identity_credential_issuer, "https://token.actions.githubusercontent.com")
        self.assertEqual(
            facts.federated_identity_credential_subject,
            "repo:tfstride/tfstride:ref:refs/heads/main",
        )
        self.assertEqual(facts.federated_identity_credential_audiences, ["api://AzureADTokenExchange"])
        self.assertEqual(
            facts.federated_identity_credential_parent_id,
            "azurerm_user_assigned_identity.deploy.id",
        )
        self.assertEqual(facts.federated_identity_credential_uncertainties, [])

    def test_federated_identity_credential_preserves_multiple_audiences_and_parent_reference(self) -> None:
        credential = normalize_federated_identity_credential(
            _resource(
                {
                    "name": "github",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:tfstride/tfstride:*",
                    "audiences": ["api://AzureADTokenExchange", "api://AzureADTokenExchange/v2"],
                    "parent_id": "$" + "{azurerm_user_assigned_identity.deploy.id}",
                }
            )
        )
        facts = azure_facts(credential)

        self.assertEqual(
            facts.federated_identity_credential_audiences,
            ["api://AzureADTokenExchange", "api://AzureADTokenExchange/v2"],
        )
        self.assertEqual(
            facts.federated_identity_credential_parent_id,
            "$" + "{azurerm_user_assigned_identity.deploy.id}",
        )
        self.assertEqual(facts.federated_identity_credential_uncertainties, [])

    def test_federated_identity_credential_preserves_computed_values_as_uncertainties(self) -> None:
        credential = normalize_federated_identity_credential(
            _resource(
                {
                    "id": None,
                    "name": "github",
                    "issuer": None,
                    "subject": None,
                    "audiences": [],
                    "parent_id": None,
                },
                unknown_values={
                    "id": True,
                    "issuer": True,
                    "subject": True,
                    "audiences": True,
                    "parent_id": True,
                },
            )
        )
        facts = azure_facts(credential)

        self.assertEqual(credential.identifier, "azurerm_federated_identity_credential.github")
        self.assertIsNone(facts.federated_identity_credential_issuer)
        self.assertIsNone(facts.federated_identity_credential_subject)
        self.assertEqual(facts.federated_identity_credential_audiences, [])
        self.assertIsNone(facts.federated_identity_credential_parent_id)
        self.assertEqual(
            facts.federated_identity_credential_uncertainties,
            [
                "issuer is unknown after planning",
                "subject is unknown after planning",
                "audiences is unknown after planning",
                "parent_id is unknown after planning",
            ],
        )

    def test_azure_normalizer_registers_federated_identity_credentials_as_supported(self) -> None:
        resource = _resource(
            {
                "name": "github",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:tfstride/tfstride:*",
                "audiences": ["api://AzureADTokenExchange"],
                "parent_id": "azurerm_user_assigned_identity.deploy.id",
            }
        )

        inventory = AzureNormalizer().normalize([resource])

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual([item.address for item in inventory.resources], [resource.address])
        self.assertEqual(
            azure_facts(inventory.resources[0]).federated_identity_credential_parent_id,
            "azurerm_user_assigned_identity.deploy.id",
        )


if __name__ == "__main__":
    unittest.main()
