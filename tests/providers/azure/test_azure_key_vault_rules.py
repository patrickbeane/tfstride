from __future__ import annotations

import unittest

from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.observations import observe_azure_posture
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_MISSING = object()


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _vault(
    *,
    name: str = "application",
    public_network: bool = True,
    default_action: str | None = None,
    purge_protection: bool = True,
    access_policy: list[dict[str, object]] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/providers/Microsoft.KeyVault/vaults/{name}",
        "name": name,
        "tenant_id": "tenant-id",
        "public_network_access_enabled": public_network,
        "purge_protection_enabled": purge_protection,
        "enable_rbac_authorization": access_policy is None,
    }
    if default_action is not None:
        values["network_acls"] = [{"default_action": default_action, "ip_rules": ["198.51.100.10"]}]
    if access_policy is not None:
        values["access_policy"] = access_policy
    return _resource(AzureResourceType.KEY_VAULT, name, values)


def _secret(
    *,
    expiration_date: object = _MISSING,
    not_before_date: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"name": "api-key", "key_vault_id": "azurerm_key_vault.application.id"}
    if expiration_date is not _MISSING:
        values["expiration_date"] = expiration_date
    if not_before_date is not _MISSING:
        values["not_before_date"] = not_before_date
    return _resource(
        AzureResourceType.KEY_VAULT_SECRET,
        "api_key",
        values,
        unknown_values=unknown_values,
    )


def _certificate(
    *,
    expiration_date: object = _MISSING,
    not_before_date: object = _MISSING,
    validity_months: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {"name": "tls", "key_vault_id": "azurerm_key_vault.application.id"}
    if expiration_date is not _MISSING:
        values["expiration_date"] = expiration_date
    if not_before_date is not _MISSING:
        values["not_before_date"] = not_before_date
    if validity_months is not _MISSING:
        values["certificate_policy"] = [{"validity_in_months": validity_months}]
    return _resource(
        AzureResourceType.KEY_VAULT_CERTIFICATE,
        "tls",
        values,
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, boundaries, findings


class AzureKeyVaultRuleTests(unittest.TestCase):
    def test_public_key_vault_emits_network_finding_and_boundary(self) -> None:
        _, boundaries, findings = _evaluate(
            [_vault()],
            "azure-key-vault-public-network-access",
        )

        self.assertEqual(
            [boundary.identifier for boundary in boundaries],
            ["internet-to-service:internet->azurerm_key_vault.application"],
        )
        self.assertEqual([finding.rule_id for finding in findings], ["azure-key-vault-public-network-access"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.trust_boundary_id, boundaries[0].identifier)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "network exposure is evaluated separately from identity authorization",
            evidence["network_exposure"],
        )

    def test_private_key_vault_has_no_public_network_finding(self) -> None:
        inventory, boundaries, findings = _evaluate(
            [_vault(public_network=False)],
            "azure-key-vault-public-network-access",
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(findings, [])
        observations = observe_azure_posture(inventory)
        self.assertIn("azure-key-vault-network-restricted", [item.observation_id for item in observations])

    def test_default_deny_network_acls_are_observed_as_restricted(self) -> None:
        inventory, boundaries, findings = _evaluate(
            [_vault(default_action="Deny")],
            "azure-key-vault-public-network-access",
        )

        self.assertEqual(boundaries, [])
        self.assertEqual(findings, [])
        observations = observe_azure_posture(inventory)
        restricted = next(item for item in observations if item.observation_id == "azure-key-vault-network-restricted")
        evidence = {item.key: item.values for item in restricted.evidence}
        self.assertIn("allowed IP rule is 198.51.100.10", evidence["network_posture"])

    def test_privileged_role_assignment_is_detected_independently_of_network(self) -> None:
        role_assignment = _resource(
            AzureResourceType.ROLE_ASSIGNMENT,
            "admin",
            {
                "scope": "azurerm_key_vault.application.id",
                "role_definition_name": "Key Vault Administrator",
                "principal_id": "principal-id",
                "principal_type": "ServicePrincipal",
            },
        )
        _, _, findings = _evaluate(
            [_vault(public_network=False), role_assignment],
            "azure-key-vault-privileged-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-key-vault-privileged-access"])
        self.assertEqual(findings[0].severity.value, "high")
        self.assertEqual(
            findings[0].affected_resources,
            ["azurerm_key_vault.application", "azurerm_role_assignment.admin"],
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["authorization_scope"],
            ["identity authorization is evaluated separately from network exposure"],
        )

    def test_permissive_access_policy_is_detected(self) -> None:
        access_policy = _resource(
            AzureResourceType.KEY_VAULT_ACCESS_POLICY,
            "operators",
            {
                "key_vault_id": "azurerm_key_vault.application.id",
                "tenant_id": "tenant-id",
                "object_id": "operator-id",
                "secret_permissions": ["Get", "Set", "Delete", "Purge"],
            },
        )
        _, _, findings = _evaluate(
            [_vault(public_network=False, access_policy=[]), access_policy],
            "azure-key-vault-privileged-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-key-vault-privileged-access"])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("secret_permissions=[delete, get, purge, set]", evidence["privileged_access_policies"][0])

    def test_read_only_access_policy_is_not_flagged(self) -> None:
        inventory, _, findings = _evaluate(
            [
                _vault(
                    public_network=False,
                    access_policy=[
                        {
                            "tenant_id": "tenant-id",
                            "object_id": "reader-id",
                            "secret_permissions": ["Get", "List"],
                        }
                    ],
                )
            ],
            "azure-key-vault-privileged-access",
        )

        self.assertEqual(findings, [])
        facts = azure_facts(inventory.resources[0])
        self.assertEqual(facts.key_vault_access_policies[0]["secret_permissions"], ["get", "list"])
        observations = observe_azure_posture(inventory)
        self.assertIn(
            "azure-key-vault-authorization-model-observed",
            [item.observation_id for item in observations],
        )

    def test_purge_protection_disabled_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_vault(public_network=False, purge_protection=False)],
            "azure-key-vault-purge-protection-disabled",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-key-vault-purge-protection-disabled"])
        self.assertEqual(findings[0].severity.value, "medium")

    def test_secret_and_certificate_missing_lifecycle_are_detected(self) -> None:
        _, _, findings = _evaluate(
            [_secret(), _certificate()],
            "azure-key-vault-secret-certificate-lifecycle-incomplete",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-key-vault-secret-certificate-lifecycle-incomplete",
                "azure-key-vault-secret-certificate-lifecycle-incomplete",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["medium", "medium"])
        first_evidence = {item.key: item.values for item in findings[0].evidence}
        second_evidence = {item.key: item.values for item in findings[1].evidence}
        self.assertEqual(first_evidence["lifecycle_issues"], ["secret has no expiration_date"])
        self.assertEqual(second_evidence["lifecycle_issues"], ["certificate has no expiration_date"])
        self.assertIn("expiration_date=unset", first_evidence["lifecycle_posture"])
        self.assertIn("certificate_policy.validity_in_months=unset", second_evidence["lifecycle_posture"])

    def test_secret_and_certificate_bounded_lifecycle_are_quiet(self) -> None:
        _, _, findings = _evaluate(
            [
                _secret(
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2026-12-31T00:00:00Z",
                ),
                _certificate(validity_months=12),
            ],
            "azure-key-vault-secret-certificate-lifecycle-incomplete",
        )

        self.assertEqual(findings, [])

    def test_secret_very_long_lifetime_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [
                _secret(
                    not_before_date="2026-01-01T00:00:00Z",
                    expiration_date="2029-01-01T00:00:00Z",
                )
            ],
            "azure-key-vault-secret-certificate-lifecycle-incomplete",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-key-vault-secret-certificate-lifecycle-incomplete"]
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(evidence["lifecycle_issues"], ["configured lifetime is 1096 days; maximum is 730 days"])
        self.assertIn("configured_lifetime_days=1096", evidence["lifecycle_posture"])

    def test_certificate_very_long_validity_is_detected(self) -> None:
        _, _, findings = _evaluate(
            [_certificate(validity_months=36)],
            "azure-key-vault-secret-certificate-lifecycle-incomplete",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-key-vault-secret-certificate-lifecycle-incomplete"]
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(
            evidence["lifecycle_issues"],
            ["certificate_policy.validity_in_months is 36; maximum is 24"],
        )

    def test_unknown_lifecycle_values_are_not_overclaimed(self) -> None:
        _, _, findings = _evaluate(
            [
                _secret(unknown_values={"expiration_date": True}),
                _certificate(unknown_values={"certificate_policy": [{"validity_in_months": True}]}),
            ],
            "azure-key-vault-secret-certificate-lifecycle-incomplete",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
