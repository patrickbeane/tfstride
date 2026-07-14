from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_NAMESPACE_ID = "/subscriptions/example/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/events"
_CMK_KEY_ID = "azurerm_key_vault_key.service_bus.id"

_SERVICE_BUS_RULE_IDS = (
    "azure-service-bus-public-network-access-not-disabled",
    "azure-service-bus-minimum-tls-below-1-2",
    "azure-service-bus-minimum-tls-unknown",
    "azure-service-bus-local-auth-enabled",
    "azure-service-bus-customer-managed-key-missing",
    "azure-service-bus-missing-private-endpoint",
)


class _Missing:
    pass


_MISSING = _Missing()


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


def _namespace(
    *,
    sku: str = "Premium",
    public_network: object = False,
    default_action: str | None = "Deny",
    minimum_tls_version: object = "1.2",
    local_auth_enabled: object = False,
    cmk_key_id: str | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _NAMESPACE_ID,
        "name": "events",
        "sku": sku,
    }
    if public_network is not _MISSING:
        values["public_network_access_enabled"] = public_network
    if default_action is not None:
        values["network_rule_set"] = [{"default_action": default_action}]
    if minimum_tls_version is not _MISSING:
        values["minimum_tls_version"] = minimum_tls_version
    if local_auth_enabled is not _MISSING:
        values["local_auth_enabled"] = local_auth_enabled
    if cmk_key_id is not None:
        values["customer_managed_key"] = [{"key_vault_key_id": cmk_key_id}]
    return _resource(
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        "events",
        values,
        unknown_values=unknown_values,
    )


def _private_endpoint(
    *,
    public_dns: bool = True,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": "events-private-endpoint",
        "private_service_connection": [
            {
                "name": "events-connection",
                "private_connection_resource_id": _NAMESPACE_ID,
                "subresource_names": ["namespace"],
                "is_manual_connection": False,
            }
        ],
    }
    if public_dns:
        values["private_dns_zone_group"] = [
            {
                "name": "servicebus-dns",
                "private_dns_zone_ids": ["azurerm_private_dns_zone.servicebus.id"],
            }
        ]
    return _resource(AzureResourceType.PRIVATE_ENDPOINT, "events", values)


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


class AzureServiceBusRuleTests(unittest.TestCase):
    def test_unsafe_premium_namespace_emits_public_tls_local_auth_cmk_and_private_endpoint_findings(self) -> None:
        findings = _evaluate(
            [
                _namespace(
                    public_network=True,
                    default_action="Allow",
                    minimum_tls_version="1.0",
                    local_auth_enabled=True,
                )
            ],
            *_SERVICE_BUS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-service-bus-public-network-access-not-disabled",
                "azure-service-bus-minimum-tls-below-1-2",
                "azure-service-bus-local-auth-enabled",
                "azure-service-bus-customer-managed-key-missing",
                "azure-service-bus-missing-private-endpoint",
            ],
        )
        evidence_by_rule = {finding.rule_id: _evidence_by_key(finding) for finding in findings}
        self.assertEqual(
            evidence_by_rule["azure-service-bus-public-network-access-not-disabled"]["network_posture"],
            [
                "public_network_fallback_state=enabled",
                "public_network_access_enabled is true",
                "effective default_action is Allow",
                "network rule source is azurerm_servicebus_namespace.events",
            ],
        )
        self.assertEqual(
            evidence_by_rule["azure-service-bus-minimum-tls-below-1-2"]["transport_posture"],
            ["minimum_tls_version is 1.0"],
        )
        self.assertEqual(
            evidence_by_rule["azure-service-bus-local-auth-enabled"]["authorization_posture"],
            ["local_auth_enabled is true"],
        )
        cmk_evidence = evidence_by_rule["azure-service-bus-customer-managed-key-missing"]["encryption_ownership"]
        self.assertIn("customer_managed_key_state=not_configured", cmk_evidence)
        self.assertIn(
            "Azure Service Bus encryption at rest remains in place; this finding concerns customer key control",
            cmk_evidence,
        )
        self.assertNotIn("unencrypted", " ".join(cmk_evidence).lower())

    def test_unknown_tls_emits_uncertainty_without_disabled_claim(self) -> None:
        findings = _evaluate(
            [_namespace(minimum_tls_version=_MISSING)],
            "azure-service-bus-minimum-tls-below-1-2",
            "azure-service-bus-minimum-tls-unknown",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-service-bus-minimum-tls-unknown"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["transport_posture"], ["minimum_tls_version is not represented in planned values"])
        self.assertNotIn(
            "minimum_tls_version is disabled", [value for item in findings[0].evidence for value in item.values]
        )

    def test_default_deny_network_rules_reduce_severity_but_do_not_prove_private_only_access(self) -> None:
        findings = _evaluate(
            [
                _namespace(
                    public_network=True,
                    default_action="Deny",
                    cmk_key_id=_CMK_KEY_ID,
                )
            ],
            "azure-service-bus-public-network-access-not-disabled",
            "azure-service-bus-missing-private-endpoint",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-service-bus-public-network-access-not-disabled",
                "azure-service-bus-missing-private-endpoint",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["low", "low"])
        self.assertIn(
            "effective default_action is Deny",
            _evidence_by_key(findings[0])["network_posture"],
        )

    def test_non_premium_namespace_does_not_receive_cmk_or_private_endpoint_findings(self) -> None:
        findings = _evaluate(
            [
                _namespace(
                    sku="Basic",
                    public_network=False,
                    minimum_tls_version="1.2",
                    local_auth_enabled=False,
                )
            ],
            "azure-service-bus-customer-managed-key-missing",
            "azure-service-bus-missing-private-endpoint",
        )

        self.assertEqual(findings, [])

    def test_hardened_premium_namespace_with_cmk_and_private_endpoint_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _namespace(
                    public_network=False,
                    default_action="Deny",
                    minimum_tls_version="1.2",
                    local_auth_enabled=False,
                    cmk_key_id=_CMK_KEY_ID,
                ),
                _private_endpoint(),
            ],
            *_SERVICE_BUS_RULE_IDS,
            "azure-private-endpoint-public-fallback",
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual(findings, [])

    def test_private_endpoint_suppresses_missing_coverage_and_generic_posture_rules_include_service_bus(self) -> None:
        findings = _evaluate(
            [
                _namespace(
                    public_network=True,
                    default_action="Allow",
                    minimum_tls_version="1.2",
                    local_auth_enabled=False,
                    cmk_key_id=_CMK_KEY_ID,
                ),
                _private_endpoint(public_dns=False),
            ],
            "azure-service-bus-missing-private-endpoint",
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
        self.assertEqual(fallback_evidence["private_endpoints"], ["azurerm_private_endpoint.events"])
        self.assertEqual(fallback_evidence["private_endpoint_subresources"], ["namespace"])
        self.assertIn(
            "network rule source is azurerm_servicebus_namespace.events",
            fallback_evidence["network_acl_posture"],
        )
        dns_evidence = _evidence_by_key(findings[1])
        self.assertEqual(
            dns_evidence["private_endpoint_dns_posture"],
            ["azurerm_private_endpoint.events: no private_dns_zone_group blocks are represented"],
        )


if __name__ == "__main__":
    unittest.main()
