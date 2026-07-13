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
    "azure-app-service-platform-authentication-disabled",
    "azure-app-service-anonymous-platform-access-allowed",
    "azure-app-service-minimum-tls-below-1-2",
    "azure-app-service-minimum-tls-unknown",
    "azure-app-service-managed-identity-missing",
    "azure-app-service-vnet-integration-missing",
    "azure-app-service-access-restrictions-not-default-deny",
    "azure-app-service-broad-access-restriction-allow",
    "azure-app-service-scm-access-unrestricted",
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
    auth_settings: object = _MISSING,
    auth_settings_v2: object = _MISSING,
    site_config_overrides: dict[str, object] | None = None,
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
    site_config: dict[str, object] = {}
    if tls_version is not _MISSING:
        site_config["minimum_tls_version"] = tls_version
    if site_config_overrides:
        site_config.update(site_config_overrides)
    if site_config:
        values["site_config"] = [site_config]
    if identity is not _MISSING:
        values["identity"] = identity
    if vnet_subnet is not _MISSING:
        values["virtual_network_subnet_id"] = vnet_subnet
    if auth_settings is not _MISSING:
        values["auth_settings"] = auth_settings
    if auth_settings_v2 is not _MISSING:
        values["auth_settings_v2"] = auth_settings_v2
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


class AzureAppServiceAuthenticationRuleTests(unittest.TestCase):
    def test_public_app_with_legacy_platform_authentication_disabled_emits_one_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    auth_settings=[
                        {
                            "enabled": False,
                            "unauthenticated_client_action": "AllowAnonymous",
                            "default_provider": "AzureActiveDirectory",
                            "token_store_enabled": False,
                        }
                    ],
                )
            ],
            "azure-app-service-platform-authentication-disabled",
            "azure-app-service-anonymous-platform-access-allowed",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-platform-authentication-disabled"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn("application may still enforce its own authentication outside Terraform", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["platform_authentication"],
            [
                "configuration_source=auth_settings",
                "platform_authentication_state=disabled",
                "unauthenticated_action=AllowAnonymous",
                "default_provider=AzureActiveDirectory",
                "application-level authentication is not represented in Terraform",
            ],
        )

    def test_public_app_with_v2_anonymous_platform_access_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    resource_type=AzureResourceType.LINUX_FUNCTION_APP,
                    public_network=True,
                    auth_settings_v2=[
                        {
                            "auth_enabled": True,
                            "require_authentication": True,
                            "unauthenticated_action": "AllowAnonymous",
                            "default_provider": "azureactivedirectory",
                            "login": [{"token_store_enabled": True}],
                        }
                    ],
                )
            ],
            "azure-app-service-anonymous-platform-access-allowed",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-anonymous-platform-access-allowed"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn("application may still enforce its own authentication outside Terraform", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["platform_authentication"],
            [
                "configuration_source=auth_settings_v2",
                "platform_authentication_state=enabled",
                "require_authentication_state=enabled",
                "unauthenticated_action=AllowAnonymous",
                "default_provider=azureactivedirectory",
                "application-level authentication is not represented in Terraform",
            ],
        )

    def test_private_or_unconfigured_platform_authentication_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _app(
                    name="private",
                    public_network=False,
                    auth_settings_v2=[
                        {
                            "auth_enabled": False,
                            "require_authentication": False,
                            "unauthenticated_action": "AllowAnonymous",
                            "login": [{"token_store_enabled": False}],
                        }
                    ],
                ),
                _app(name="unconfigured", public_network=True),
                _app(
                    name="protected",
                    public_network=True,
                    auth_settings_v2=[
                        {
                            "auth_enabled": True,
                            "require_authentication": True,
                            "unauthenticated_action": "Return401",
                            "login": [{"token_store_enabled": True}],
                        }
                    ],
                ),
            ],
            "azure-app-service-platform-authentication-disabled",
            "azure-app-service-anonymous-platform-access-allowed",
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


class AzureAppServiceAccessRestrictionRuleTests(unittest.TestCase):
    def test_public_app_without_access_restrictions_emits_default_deny_finding(self) -> None:
        findings = _evaluate(
            [_app(public_network=True, identity=_system_identity())],
            "azure-app-service-access-restrictions-not-default-deny",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-access-restrictions-not-default-deny"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["access_restrictions"],
            ["ip_restriction_default_action is not represented", "ip_restriction_count=0"],
        )

    def test_public_app_with_default_allow_emits_default_deny_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={
                        "ip_restriction_default_action": "Allow",
                        "ip_restriction": [
                            {
                                "name": "office",
                                "priority": 100,
                                "action": "Allow",
                                "ip_address": "203.0.113.0/24",
                            }
                        ],
                    },
                )
            ],
            "azure-app-service-access-restrictions-not-default-deny",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-access-restrictions-not-default-deny"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertIn("ip_restriction_default_action is Allow", evidence["access_restrictions"])
        self.assertIn("ip_restriction_count=1", evidence["access_restrictions"])

    def test_default_deny_with_narrow_allow_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={
                        "ip_restriction_default_action": "Deny",
                        "ip_restriction": [
                            {
                                "name": "office",
                                "priority": 100,
                                "action": "Allow",
                                "ip_address": "203.0.113.0/24",
                            }
                        ],
                        "scm_use_main_ip_restriction": True,
                    },
                )
            ],
            "azure-app-service-access-restrictions-not-default-deny",
            "azure-app-service-broad-access-restriction-allow",
            "azure-app-service-scm-access-unrestricted",
        )

        self.assertEqual(findings, [])

    def test_private_app_without_access_restrictions_stays_quiet(self) -> None:
        findings = _evaluate(
            [_app(public_network=False, identity=_system_identity())],
            "azure-app-service-access-restrictions-not-default-deny",
            "azure-app-service-broad-access-restriction-allow",
            "azure-app-service-scm-access-unrestricted",
        )

        self.assertEqual(findings, [])

    def test_broad_main_site_allow_rule_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={
                        "ip_restriction_default_action": "Deny",
                        "ip_restriction": [
                            {
                                "name": "internet",
                                "priority": 100,
                                "action": "Allow",
                                "ip_address": "0.0.0.0/0",
                            }
                        ],
                    },
                )
            ],
            "azure-app-service-broad-access-restriction-allow",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-broad-access-restriction-allow"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["broad_allow_rules"],
            ["rule name=internet action=Allow priority=100 ip_address=0.0.0.0/0 broad_sources=[ip_address=0.0.0.0/0]"],
        )

    def test_broad_service_tag_allow_rule_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={
                        "ip_restriction_default_action": "Deny",
                        "ip_restriction": [
                            {
                                "name": "internet-tag",
                                "priority": 100,
                                "action": "Allow",
                                "service_tag": "Internet",
                            }
                        ],
                    },
                )
            ],
            "azure-app-service-broad-access-restriction-allow",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-broad-access-restriction-allow"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["broad_allow_rules"],
            [
                "rule name=internet-tag action=Allow priority=100 service_tag=Internet broad_sources=[service_tag=Internet]"
            ],
        )

    def test_scm_unrestricted_when_main_restrictions_are_not_inherited_and_scm_rules_absent(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={"scm_use_main_ip_restriction": False},
                )
            ],
            "azure-app-service-scm-access-unrestricted",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-scm-access-unrestricted"],
        )
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["scm_access_posture"],
            ["scm_use_main_ip_restriction is false", "scm access restrictions are not configured"],
        )

    def test_scm_broad_allow_rule_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _app(
                    public_network=True,
                    identity=_system_identity(),
                    site_config_overrides={
                        "scm_ip_restriction_default_action": "Deny",
                        "scm_ip_restriction": [
                            {
                                "name": "any-scm",
                                "priority": 100,
                                "action": "Allow",
                                "ip_address": "0.0.0.0/0",
                            }
                        ],
                    },
                )
            ],
            "azure-app-service-scm-access-unrestricted",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["azure-app-service-scm-access-unrestricted"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["scm_access_posture"],
            ["SCM access restriction includes a broad allow rule"],
        )
        self.assertIn(
            "rule name=any-scm action=Allow priority=100 ip_address=0.0.0.0/0 broad_sources=[ip_address=0.0.0.0/0]",
            evidence["scm_access_restrictions"],
        )


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
