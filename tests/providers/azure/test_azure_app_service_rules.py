from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_APP_RULE_IDS = (
    "azure-app-service-public-network-access-not-disabled",
    "azure-app-service-minimum-tls-below-1-2",
    "azure-app-service-minimum-tls-unknown",
    "azure-app-service-managed-identity-missing",
    "azure-app-service-vnet-integration-missing",
)
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


def _app(
    *,
    resource_type: str = AzureResourceType.LINUX_WEB_APP,
    name: str = "app",
    public_network: object = False,
    tls_version: object = "1.2",
    identity: object = _MISSING,
    vnet_subnet: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/resourceGroups/app/providers/Microsoft.Web/sites/{name}",
        "name": name,
        "location": "eastus",
        "service_plan_id": "azurerm_service_plan.apps.id",
    }
    if public_network is not _MISSING:
        values["public_network_access_enabled"] = public_network
    if tls_version is not _MISSING:
        values["site_config"] = [{"minimum_tls_version": tls_version}]
    if identity is not _MISSING:
        values["identity"] = identity
    if vnet_subnet is not _MISSING:
        values["virtual_network_subnet_id"] = vnet_subnet
    return _resource(resource_type, name, values, unknown_values=unknown_values)


def _system_identity() -> list[dict[str, object]]:
    return [
        {
            "type": "SystemAssigned",
            "principal_id": "principal-id",
            "tenant_id": "tenant-id",
            "identity_ids": [],
        }
    ]


def _user_identity() -> list[dict[str, object]]:
    return [{"type": "UserAssigned", "identity_ids": ["azurerm_user_assigned_identity.runtime.id"]}]


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return findings


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAppServicePublicNetworkRuleTests(unittest.TestCase):
    def test_public_network_access_enabled_emits_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=True, identity=_system_identity())],
            "azure-app-service-public-network-access-not-disabled",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-app-service-public-network-access-not-disabled"]
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["azurerm_linux_web_app.app"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["network_posture"],
            ["public_network_fallback_state=enabled", "public_network_access_enabled is true"],
        )

    def test_public_network_access_unknown_emits_uncertain_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=None,
                    identity=_system_identity(),
                    unknown_values={"public_network_access_enabled": True},
                )
            ],
            "azure-app-service-public-network-access-not-disabled",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-app-service-public-network-access-not-disabled"]
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["network_posture"],
            ["public_network_fallback_state=unknown", "public_network_access_enabled is unknown"],
        )
        self.assertEqual(
            evidence["posture_uncertainty"],
            ["public_network_access_enabled is unknown after planning"],
        )

    def test_public_network_access_disabled_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(public_network=False)],
            "azure-app-service-public-network-access-not-disabled",
        )

        self.assertEqual(findings, [])


class AzureAppServiceTlsRuleTests(unittest.TestCase):
    def test_minimum_tls_below_1_2_emits_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=True, tls_version="1.0", identity=_system_identity())],
            "azure-app-service-minimum-tls-below-1-2",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-minimum-tls-below-1-2"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["transport_posture"], ["minimum_tls_version is 1.0"])

    def test_minimum_tls_1_2_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(tls_version="1.2")],
            "azure-app-service-minimum-tls-below-1-2",
            "azure-app-service-minimum-tls-unknown",
        )

        self.assertEqual(findings, [])

    def test_missing_minimum_tls_emits_uncertain_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=False, tls_version=_MISSING, identity=_system_identity())],
            "azure-app-service-minimum-tls-unknown",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-minimum-tls-unknown"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["transport_posture"],
            ["minimum_tls_version is not represented in planned values"],
        )

    def test_unknown_minimum_tls_emits_uncertain_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    tls_version=None,
                    identity=_system_identity(),
                    unknown_values={"site_config": [{"minimum_tls_version": True}]},
                )
            ],
            "azure-app-service-minimum-tls-unknown",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-minimum-tls-unknown"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["transport_posture"], ["minimum_tls_version is unknown"])
        self.assertEqual(
            evidence["posture_uncertainty"],
            ["site_config.minimum_tls_version is unknown after planning"],
        )


class AzureAppServiceVnetIntegrationRuleTests(unittest.TestCase):
    def test_missing_vnet_integration_emits_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=False, identity=_system_identity(), vnet_subnet=_MISSING)],
            "azure-app-service-vnet-integration-missing",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-vnet-integration-missing"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertIn(
            "does not have VNet integration configured",
            finding.rationale,
        )
        self.assertIn(
            "may rely on public endpoints or service-level firewall exceptions",
            finding.rationale,
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["vnet_integration"], ["virtual_network_subnet_id is not configured"])
        self.assertEqual(
            evidence["network_posture"],
            ["public_network_fallback_state=disabled", "public_network_access_enabled is false"],
        )

    def test_missing_vnet_integration_with_public_access_enabled_raises_severity(self) -> None:
        findings = _evaluate(
            [_app(public_network=True, identity=_system_identity(), vnet_subnet=_MISSING)],
            "azure-app-service-vnet-integration-missing",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-vnet-integration-missing"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["network_posture"],
            ["public_network_fallback_state=enabled", "public_network_access_enabled is true"],
        )

    def test_configured_vnet_integration_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(vnet_subnet="azurerm_subnet.integration.id")],
            "azure-app-service-vnet-integration-missing",
        )

        self.assertEqual(findings, [])

    def test_unknown_vnet_integration_does_not_overclaim_missing_integration(self) -> None:
        findings = _evaluate(
            [
                _app(
                    vnet_subnet=None,
                    unknown_values={"virtual_network_subnet_id": True},
                )
            ],
            "azure-app-service-vnet-integration-missing",
        )

        self.assertEqual(findings, [])


class AzureAppServiceManagedIdentityRuleTests(unittest.TestCase):
    def test_missing_managed_identity_emits_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=True, identity=_MISSING)],
            "azure-app-service-managed-identity-missing",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-managed-identity-missing"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["identity_posture"], ["identity block is absent"])

    def test_identity_type_none_emits_missing_identity_finding(self) -> None:
        findings = _evaluate(
            [_app(identity=[{"type": "None"}])],
            "azure-app-service-managed-identity-missing",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-app-service-managed-identity-missing"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["identity_posture"], ["identity_type is None"])

    def test_system_assigned_identity_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(identity=_system_identity())],
            "azure-app-service-managed-identity-missing",
        )

        self.assertEqual(findings, [])

    def test_user_assigned_identity_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(resource_type=AzureResourceType.WINDOWS_FUNCTION_APP, identity=_user_identity())],
            "azure-app-service-managed-identity-missing",
        )

        self.assertEqual(findings, [])

    def test_unknown_identity_block_does_not_overclaim_missing_identity(self) -> None:
        findings = _evaluate(
            [_app(identity=None, unknown_values={"identity": True})],
            "azure-app-service-managed-identity-missing",
        )

        self.assertEqual(findings, [])

    def test_hardened_app_service_has_no_app_service_findings(self) -> None:
        rule_ids = tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group if "app-service" in rule_id)
        findings = _evaluate(
            [
                _app(
                    resource_type=AzureResourceType.LINUX_FUNCTION_APP,
                    public_network=False,
                    tls_version="1.2",
                    identity=_system_identity(),
                    vnet_subnet="azurerm_subnet.integration.id",
                )
            ],
            *rule_ids,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
