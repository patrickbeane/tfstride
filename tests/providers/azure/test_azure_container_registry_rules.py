from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_REGISTRY_ID = "/subscriptions/example/resourceGroups/apps/providers/Microsoft.ContainerRegistry/registries/images"
_CMK_KEY_ID = "azurerm_key_vault_key.registry.id"

_CONTAINER_REGISTRY_RULE_IDS = (
    "azure-container-registry-public-network-access-not-disabled",
    "azure-container-registry-admin-account-enabled",
    "azure-container-registry-anonymous-pull-enabled",
    "azure-container-registry-customer-managed-key-missing",
    "azure-container-registry-missing-private-endpoint",
)


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


def _registry(
    *,
    sku: str = "Premium",
    public_network_access_enabled: object | None = False,
    default_action: str | None = "Deny",
    admin_enabled: object | None = False,
    anonymous_pull_enabled: object | None = False,
    cmk_key_id: str | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _REGISTRY_ID,
        "name": "images",
        "location": "eastus",
        "sku": sku,
    }
    if public_network_access_enabled is not None:
        values["public_network_access_enabled"] = public_network_access_enabled
    if default_action is not None:
        values["network_rule_set"] = [{"default_action": default_action, "ip_rule": []}]
    if admin_enabled is not None:
        values["admin_enabled"] = admin_enabled
    if anonymous_pull_enabled is not None:
        values["anonymous_pull_enabled"] = anonymous_pull_enabled
    if cmk_key_id is not None:
        values["encryption"] = [
            {
                "key_vault_key_id": cmk_key_id,
                "identity_client_id": "registry-identity-client-id",
            }
        ]
    return _resource(
        AzureResourceType.CONTAINER_REGISTRY,
        "images",
        values,
        unknown_values=unknown_values,
    )


def _private_endpoint(*, with_dns: bool = True) -> TerraformResource:
    values: dict[str, object] = {
        "name": "images-private-endpoint",
        "private_service_connection": [
            {
                "name": "images-connection",
                "private_connection_resource_id": _REGISTRY_ID,
                "subresource_names": ["registry"],
                "is_manual_connection": False,
            }
        ],
    }
    if with_dns:
        values["private_dns_zone_group"] = [
            {
                "name": "registry-dns",
                "private_dns_zone_ids": ["azurerm_private_dns_zone.registry.id"],
            }
        ]
    return _resource(AzureResourceType.PRIVATE_ENDPOINT, "images", values)


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureContainerRegistryRuleTests(unittest.TestCase):
    def test_unsafe_premium_registry_emits_network_auth_cmk_and_private_endpoint_findings(self) -> None:
        findings = _evaluate(
            [
                _registry(
                    public_network_access_enabled=True,
                    default_action="Allow",
                    admin_enabled=True,
                    anonymous_pull_enabled=True,
                )
            ],
            *_CONTAINER_REGISTRY_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_CONTAINER_REGISTRY_RULE_IDS))
        evidence_by_rule = {finding.rule_id: _evidence_by_key(finding) for finding in findings}
        self.assertEqual(
            evidence_by_rule["azure-container-registry-public-network-access-not-disabled"]["network_posture"],
            [
                "public_network_fallback_state=enabled",
                "public_network_access_enabled is true",
                "effective default_action is Allow",
                "network rule source is azurerm_container_registry.images",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-container-registry-admin-account-enabled"]["authorization_posture"],
            ["admin_enabled is true"],
        )
        self.assertEqual(
            evidence_by_rule["azure-container-registry-anonymous-pull-enabled"]["authorization_posture"],
            ["anonymous_pull_enabled is true"],
        )
        cmk_evidence = evidence_by_rule["azure-container-registry-customer-managed-key-missing"]["encryption_ownership"]
        self.assertIn("customer_managed_key_state=not_configured", cmk_evidence)
        self.assertNotIn("unencrypted", " ".join(cmk_evidence).lower())

    def test_standard_registry_skips_premium_only_cmk_and_private_endpoint_findings(self) -> None:
        findings = _evaluate(
            [
                _registry(
                    sku="Standard",
                    public_network_access_enabled=True,
                    default_action="Allow",
                    admin_enabled=True,
                    anonymous_pull_enabled=True,
                )
            ],
            *_CONTAINER_REGISTRY_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-container-registry-public-network-access-not-disabled",
                "azure-container-registry-admin-account-enabled",
                "azure-container-registry-anonymous-pull-enabled",
            ],
        )

    def test_unknown_premium_posture_reports_uncertainty_without_explicit_auth_claims(self) -> None:
        findings = _evaluate(
            [
                _registry(
                    public_network_access_enabled=None,
                    default_action=None,
                    admin_enabled=None,
                    anonymous_pull_enabled=None,
                    unknown_values={
                        "public_network_access_enabled": True,
                        "admin_enabled": True,
                        "anonymous_pull_enabled": True,
                        "encryption": True,
                    },
                )
            ],
            *_CONTAINER_REGISTRY_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-container-registry-public-network-access-not-disabled",
                "azure-container-registry-customer-managed-key-missing",
                "azure-container-registry-missing-private-endpoint",
            ],
        )
        evidence_by_rule = {finding.rule_id: _evidence_by_key(finding) for finding in findings}
        self.assertIn(
            "public_network_access_enabled is unknown after planning",
            evidence_by_rule["azure-container-registry-public-network-access-not-disabled"]["posture_uncertainty"],
        )
        self.assertIn(
            "encryption is unknown after planning",
            evidence_by_rule["azure-container-registry-customer-managed-key-missing"]["posture_uncertainty"],
        )
        all_evidence = [value for finding in findings for item in finding.evidence for value in item.values]
        self.assertNotIn("admin_enabled is true", all_evidence)
        self.assertNotIn("anonymous_pull_enabled is true", all_evidence)

    def test_default_deny_reduces_network_and_missing_endpoint_severity(self) -> None:
        findings = _evaluate(
            [_registry(public_network_access_enabled=True, default_action="Deny", cmk_key_id=_CMK_KEY_ID)],
            "azure-container-registry-public-network-access-not-disabled",
            "azure-container-registry-missing-private-endpoint",
        )

        self.assertEqual([finding.severity.value for finding in findings], ["low", "low"])
        self.assertIn("effective default_action is Deny", _evidence_by_key(findings[0])["network_posture"])

    def test_hardened_premium_registry_with_cmk_private_endpoint_and_dns_stays_quiet(self) -> None:
        findings = _evaluate(
            [_registry(cmk_key_id=_CMK_KEY_ID), _private_endpoint()],
            *_CONTAINER_REGISTRY_RULE_IDS,
            "azure-private-endpoint-public-fallback",
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual(findings, [])

    def test_private_endpoint_suppresses_missing_coverage_and_extends_generic_posture_rules(self) -> None:
        findings = _evaluate(
            [
                _registry(
                    public_network_access_enabled=True,
                    default_action="Allow",
                    cmk_key_id=_CMK_KEY_ID,
                ),
                _private_endpoint(with_dns=False),
            ],
            "azure-container-registry-missing-private-endpoint",
            "azure-private-endpoint-public-fallback",
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-private-endpoint-public-fallback",
                "azure-private-endpoint-dns-posture-incomplete",
            ],
        )
        fallback_evidence = _evidence_by_key(findings[0])
        self.assertEqual(fallback_evidence["private_endpoints"], ["azurerm_private_endpoint.images"])
        self.assertEqual(fallback_evidence["private_endpoint_subresources"], ["registry"])
        dns_evidence = _evidence_by_key(findings[1])
        self.assertEqual(
            dns_evidence["private_endpoint_dns_posture"],
            ["azurerm_private_endpoint.images: no private_dns_zone_group blocks are represented"],
        )


if __name__ == "__main__":
    unittest.main()
