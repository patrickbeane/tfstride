from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_IDENTITY_ARM_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deploy"
)
_IDENTITY_ADDRESS = "azurerm_user_assigned_identity.deploy"
_CREDENTIAL_ADDRESS = "azurerm_federated_identity_credential.github"


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _identity(
    *,
    name: str = "deploy",
    identity_id: str | None = _IDENTITY_ARM_ID,
    principal_id: str = "managed-principal-id",
) -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "id": identity_id,
            "name": name,
            "principal_id": principal_id,
            "client_id": f"{name}-client-id",
            "tenant_id": "tenant-id",
        },
        name=name,
    )


def _credential(
    *,
    parent_id: object = f"{_IDENTITY_ADDRESS}.id",
    issuer: object = "https://token.actions.githubusercontent.com",
    subject: object = "repo:tfstride/tfstride:ref:refs/heads/main",
    audiences: object = ("api://AzureADTokenExchange",),
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL,
        {
            "name": "github",
            "issuer": issuer,
            "subject": subject,
            "audiences": audiences,
            "parent_id": parent_id,
        },
        name="github",
        unknown_values=unknown_values,
    )


def _role_assignment() -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        {
            "scope": "/subscriptions/sub-0001",
            "role_definition_name": "Owner",
            "role_definition_id": ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/owner"),
            "principal_id": "managed-principal-id",
            "principal_type": "ServicePrincipal",
        },
        name="owner",
    )


class AzureFederatedIdentityTrustPathTests(unittest.TestCase):
    def test_exact_terraform_parent_reference_connects_identity_and_existing_rbac_facts(self) -> None:
        inventory = AzureNormalizer().normalize([_identity(), _credential(), _role_assignment()])
        identity = inventory.get_by_address(_IDENTITY_ADDRESS)
        credential = inventory.get_by_address(_CREDENTIAL_ADDRESS)
        assert identity is not None
        assert credential is not None

        identity_facts = azure_facts(identity)
        credential_facts = azure_facts(credential)
        self.assertEqual(credential_facts.resolved_managed_identity_address, identity.address)
        self.assertEqual(
            identity_facts.federated_managed_identity_trust_paths,
            [
                {
                    "credential_address": _CREDENTIAL_ADDRESS,
                    "credential_id": _CREDENTIAL_ADDRESS,
                    "identity_address": _IDENTITY_ADDRESS,
                    "identity_id": _IDENTITY_ARM_ID,
                    "identity_principal_id": "managed-principal-id",
                    "identity_client_id": "deploy-client-id",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:tfstride/tfstride:ref:refs/heads/main",
                    "audiences": ["api://AzureADTokenExchange"],
                    "parent_identity_id": f"{_IDENTITY_ADDRESS}.id",
                    "grant_basis": "federated_identity_credential",
                }
            ],
        )
        self.assertEqual(identity_facts.federated_managed_identity_trust_path_uncertainties, [])
        self.assertEqual(
            [assignment["source"] for assignment in identity_facts.managed_identity_role_assignments],
            ["azurerm_role_assignment.owner"],
        )
        self.assertEqual(
            [grant.role_name for grant in identity_facts.privileged_access_grants],
            ["Owner"],
        )

    def test_exact_arm_id_connects_to_user_assigned_identity(self) -> None:
        inventory = AzureNormalizer().normalize([_identity(), _credential(parent_id=_IDENTITY_ARM_ID)])
        identity = inventory.get_by_address(_IDENTITY_ADDRESS)
        credential = inventory.get_by_address(_CREDENTIAL_ADDRESS)
        assert identity is not None
        assert credential is not None

        self.assertEqual(azure_facts(credential).resolved_managed_identity_address, _IDENTITY_ADDRESS)
        self.assertEqual(
            azure_facts(identity).federated_managed_identity_trust_paths[0]["parent_identity_id"],
            _IDENTITY_ARM_ID,
        )

    def test_identity_name_alone_does_not_create_a_trust_path(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _identity(),
                _identity(name="deploy-copy", identity_id=None, principal_id="copy-principal-id"),
                _credential(parent_id="deploy"),
            ]
        )
        identity = inventory.get_by_address(_IDENTITY_ADDRESS)
        credential = inventory.get_by_address(_CREDENTIAL_ADDRESS)
        assert identity is not None
        assert credential is not None

        self.assertEqual(azure_facts(identity).federated_managed_identity_trust_paths, [])
        self.assertIsNone(azure_facts(credential).resolved_managed_identity_address)
        self.assertEqual(
            azure_facts(credential).federated_managed_identity_trust_path_uncertainties,
            [
                f"{_CREDENTIAL_ADDRESS}: parent identity reference deploy does not resolve to a modeled "
                "user-assigned identity by exact Terraform reference or ARM ID"
            ],
        )

    def test_computed_trust_fields_are_retained_as_path_uncertainties(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _identity(),
                _credential(
                    issuer=None,
                    subject=None,
                    audiences=(),
                    unknown_values={
                        "issuer": True,
                        "subject": True,
                        "audiences": True,
                    },
                ),
            ]
        )
        identity = inventory.get_by_address(_IDENTITY_ADDRESS)
        assert identity is not None
        facts = azure_facts(identity)

        self.assertEqual(len(facts.federated_managed_identity_trust_paths), 1)
        path = facts.federated_managed_identity_trust_paths[0]
        self.assertIsNone(path["issuer"])
        self.assertIsNone(path["subject"])
        self.assertEqual(path["audiences"], [])
        self.assertEqual(
            facts.federated_managed_identity_trust_path_uncertainties,
            [
                f"{_CREDENTIAL_ADDRESS}: issuer is unknown after planning",
                f"{_CREDENTIAL_ADDRESS}: subject is unknown after planning",
                f"{_CREDENTIAL_ADDRESS}: audiences is unknown after planning",
            ],
        )

    def test_unresolved_parent_reference_does_not_attach_to_an_identity(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _identity(),
                _credential(
                    parent_id=None,
                    unknown_values={"parent_id": True},
                ),
            ]
        )
        identity = inventory.get_by_address(_IDENTITY_ADDRESS)
        credential = inventory.get_by_address(_CREDENTIAL_ADDRESS)
        assert identity is not None
        assert credential is not None

        self.assertEqual(azure_facts(identity).federated_managed_identity_trust_paths, [])
        self.assertEqual(
            azure_facts(credential).federated_managed_identity_trust_path_uncertainties,
            [
                f"{_CREDENTIAL_ADDRESS}: parent_id is unknown after planning",
                f"{_CREDENTIAL_ADDRESS}: parent user-assigned identity ID is missing or unresolved",
            ],
        )


if __name__ == "__main__":
    unittest.main()
