from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_federated_identity_trust_paths import (
    _credential,
    _identity,
    _resource,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-federated-identity-privileged-access"


def _role_assignment(
    *,
    role_name: object = "Owner",
    role_id: object = ("/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/owner"),
    scope: object = "/subscriptions/sub-0001",
    principal_id: object = "managed-principal-id",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        {
            "scope": scope,
            "role_definition_name": role_name,
            "role_definition_id": role_id,
            "principal_id": principal_id,
            "principal_type": "ServicePrincipal",
        },
        name="assignment",
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureFederatedIdentityRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_external_federation_to_owner_assignment_is_detected(self) -> None:
        findings = _evaluate([_identity(), _credential(), _role_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_user_assigned_identity.deploy",
                "azurerm_federated_identity_credential.github",
                "azurerm_role_assignment.assignment",
            ],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["federated_trust"],
            [
                "credential=azurerm_federated_identity_credential.github; "
                "issuer=https://token.actions.githubusercontent.com; "
                "subject=repo:tfstride/tfstride:ref:refs/heads/main; "
                "audiences=[api://AzureADTokenExchange]"
            ],
        )
        self.assertEqual(
            evidence["managed_identity"],
            [
                "address=azurerm_user_assigned_identity.deploy",
                "principal_id=managed-principal-id",
                "client_id=deploy-client-id",
            ],
        )
        self.assertEqual(
            evidence["rbac_assignments"],
            [
                "assignment=azurerm_role_assignment.assignment; role=Owner; "
                "scope=/subscriptions/sub-0001; scope_kind=subscription"
            ],
        )
        self.assertEqual(
            evidence["privilege_categories"],
            ["full-admin", "iam-admin", "policy-admin"],
        )
        self.assertEqual(evidence["permission_patterns"], ["Owner", _role_assignment().values["role_definition_id"]])

    def test_resource_scoped_sensitive_data_role_is_detected(self) -> None:
        findings = _evaluate(
            [
                _identity(),
                _credential(),
                _role_assignment(
                    role_name="Storage Blob Data Owner",
                    role_id="storage-data-owner",
                    scope="/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["privilege_categories"], ["data-admin"])
        self.assertIn("role=Storage Blob Data Owner", evidence["rbac_assignments"][0])

    def test_reader_assignment_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _identity(),
                _credential(),
                _role_assignment(role_name="Reader", role_id="reader"),
            ]
        )

        self.assertEqual(findings, [])

    def test_computed_federation_claims_do_not_create_a_privilege_path(self) -> None:
        findings = _evaluate(
            [
                _identity(),
                _credential(
                    issuer=None,
                    unknown_values={"issuer": True},
                ),
                _role_assignment(),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_parent_or_mismatched_principal_stays_quiet(self) -> None:
        unresolved_parent = _evaluate(
            [
                _identity(),
                _credential(parent_id="deploy"),
                _role_assignment(),
            ]
        )
        mismatched_principal = _evaluate(
            [
                _identity(),
                _credential(),
                _role_assignment(principal_id="different-principal-id"),
            ]
        )

        self.assertEqual(unresolved_parent, [])
        self.assertEqual(mismatched_principal, [])


if __name__ == "__main__":
    unittest.main()
