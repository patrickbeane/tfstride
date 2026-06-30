from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_KEY_VAULT_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.KeyVault/vaults/application"
_MSSQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/sqlserver"


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


def _storage_account(
    *,
    public_network: object = True,
    default_action: str | None = "Allow",
    unknown_public_network: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _STORAGE_ID,
        "name": "logs",
        "allow_nested_items_to_be_public": False,
        "shared_access_key_enabled": False,
        "min_tls_version": "TLS1_2",
    }
    unknown_values: dict[str, object] = {}
    if public_network is not _MISSING:
        values["public_network_access_enabled"] = public_network
    if default_action is not None:
        values["network_rules"] = [{"default_action": default_action}]
    if unknown_public_network:
        unknown_values["public_network_access_enabled"] = True
    return _resource(
        AzureResourceType.STORAGE_ACCOUNT,
        "logs",
        values,
        unknown_values=unknown_values,
    )


def _key_vault(
    *,
    public_network: object = True,
    default_action: str | None = "Allow",
    unknown_public_network: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _KEY_VAULT_ID,
        "name": "application",
        "tenant_id": "tenant-id",
        "purge_protection_enabled": True,
    }
    unknown_values: dict[str, object] = {}
    if public_network is not _MISSING:
        values["public_network_access_enabled"] = public_network
    if default_action is not None:
        values["network_acls"] = [{"default_action": default_action, "ip_rules": ["198.51.100.10"]}]
    if unknown_public_network:
        unknown_values["public_network_access_enabled"] = True
    return _resource(
        AzureResourceType.KEY_VAULT,
        "application",
        values,
        unknown_values=unknown_values,
    )


def _mssql_server(
    *,
    public_network: object = True,
    unknown_public_network: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": _MSSQL_ID,
        "name": "sqlserver",
        "location": "eastus",
        "minimum_tls_version": "1.2",
    }
    unknown_values: dict[str, object] = {}
    if public_network is not _MISSING:
        values["public_network_access_enabled"] = public_network
    if unknown_public_network:
        unknown_values["public_network_access_enabled"] = True
    return _resource(
        AzureResourceType.MSSQL_SERVER,
        "sqlserver",
        values,
        unknown_values=unknown_values,
    )


def _private_endpoint(
    name: str,
    target_id: str,
    *,
    subresources: tuple[str, ...] = ("blob",),
    dns_zone_ids: tuple[str, ...] = (),
    dns_group_name: str = "private-dns",
    subnet_id: str | None = None,
    unknown_dns_group: bool = False,
    empty_dns_group: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "name": f"{name}-pe",
        "private_service_connection": [
            {
                "name": f"{name}-connection",
                "private_connection_resource_id": target_id,
                "subresource_names": list(subresources),
                "is_manual_connection": False,
            }
        ],
    }
    if subnet_id is not None:
        values["subnet_id"] = subnet_id
    if dns_zone_ids or empty_dns_group:
        values["private_dns_zone_group"] = [{"name": dns_group_name, "private_dns_zone_ids": list(dns_zone_ids)}]
    unknown_values = {"private_dns_zone_group": True} if unknown_dns_group else None
    return _resource(
        AzureResourceType.PRIVATE_ENDPOINT,
        name,
        values,
        unknown_values=unknown_values,
    )


def _virtual_network(name: str) -> TerraformResource:
    return _resource(
        AzureResourceType.VIRTUAL_NETWORK,
        name,
        {
            "id": f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/virtualNetworks/{name}",
            "name": name,
            "address_space": ["10.0.0.0/16"],
        },
    )


def _subnet(name: str, virtual_network_name: str) -> TerraformResource:
    return _resource(
        AzureResourceType.SUBNET,
        name,
        {
            "id": f"/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Network/virtualNetworks/{virtual_network_name}/subnets/{name}",
            "name": name,
            "virtual_network_name": f"azurerm_virtual_network.{virtual_network_name}.name",
            "address_prefixes": ["10.0.1.0/24"],
        },
    )


def _private_dns_zone(name: str, zone_name: str) -> TerraformResource:
    return _resource(
        AzureResourceType.PRIVATE_DNS_ZONE,
        name,
        {
            "id": f"/subscriptions/sub-0001/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/{zone_name}",
            "name": zone_name,
        },
    )


def _private_dns_zone_virtual_network_link(
    name: str,
    *,
    zone_reference: str,
    virtual_network_reference: str,
) -> TerraformResource:
    return _resource(
        AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
        name,
        {
            "id": f"/subscriptions/sub-0001/resourceGroups/dns/providers/Microsoft.Network/privateDnsZones/links/{name}",
            "name": name,
            "private_dns_zone_name": zone_reference,
            "virtual_network_id": virtual_network_reference,
            "registration_enabled": False,
        },
    )


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


class _Missing:
    pass


_MISSING = _Missing()


class AzurePrivateEndpointPostureRuleTests(unittest.TestCase):
    def test_storage_without_private_endpoint_public_enabled_is_detected(self) -> None:
        findings = _evaluate(
            [_storage_account(public_network=True, default_action="Allow")],
            "azure-storage-account-missing-private-endpoint",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-storage-account-missing-private-endpoint"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["target_resource"],
            ["address=azurerm_storage_account.logs", "type=azurerm_storage_account"],
        )
        self.assertEqual(
            evidence["public_network_fallback"],
            ["public_network_fallback_state=enabled", "public_network_access_enabled is true"],
        )
        self.assertEqual(
            evidence["private_endpoint_coverage"],
            ["no resolved private endpoint targets this resource"],
        )
        self.assertIn("effective default_action is Allow", evidence["network_acl_posture"])

    def test_storage_without_private_endpoint_public_unknown_is_detected(self) -> None:
        findings = _evaluate(
            [_storage_account(public_network=_MISSING, default_action="Deny")],
            "azure-storage-account-missing-private-endpoint",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-storage-account-missing-private-endpoint"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["public_network_fallback"],
            ["public_network_fallback_state=unknown", "public_network_access_enabled is unknown"],
        )
        self.assertIn("effective default_action is Deny", evidence["network_acl_posture"])
        self.assertEqual(
            evidence["fallback_uncertainty"],
            ["public_network_access_enabled is not represented in planned values"],
        )

    def test_key_vault_without_private_endpoint_public_enabled_and_unknown_are_detected(self) -> None:
        public_findings = _evaluate(
            [_key_vault(public_network=True, default_action="Allow")],
            "azure-key-vault-missing-private-endpoint",
        )
        unknown_findings = _evaluate(
            [_key_vault(public_network=_MISSING, default_action=None)],
            "azure-key-vault-missing-private-endpoint",
        )

        self.assertEqual(
            [finding.rule_id for finding in public_findings],
            ["azure-key-vault-missing-private-endpoint"],
        )
        self.assertEqual(public_findings[0].severity.value, "medium")
        self.assertIn(
            "public_network_fallback_state=enabled",
            _evidence_by_key(public_findings[0])["public_network_fallback"],
        )
        self.assertEqual(
            [finding.rule_id for finding in unknown_findings],
            ["azure-key-vault-missing-private-endpoint"],
        )
        self.assertEqual(unknown_findings[0].severity.value, "medium")
        self.assertEqual(
            _evidence_by_key(unknown_findings[0])["fallback_uncertainty"],
            ["public_network_access_enabled is not represented in planned values"],
        )

    def test_sql_server_without_private_endpoint_public_enabled_and_unknown_are_detected(self) -> None:
        public_findings = _evaluate(
            [_mssql_server(public_network=True)],
            "azure-sql-missing-private-endpoint",
        )
        unknown_findings = _evaluate(
            [_mssql_server(public_network=_MISSING, unknown_public_network=True)],
            "azure-sql-missing-private-endpoint",
        )

        self.assertEqual([finding.rule_id for finding in public_findings], ["azure-sql-missing-private-endpoint"])
        self.assertEqual(public_findings[0].severity.value, "medium")
        self.assertEqual([finding.rule_id for finding in unknown_findings], ["azure-sql-missing-private-endpoint"])
        self.assertEqual(
            _evidence_by_key(unknown_findings[0])["fallback_uncertainty"],
            ["public_network_access_enabled is unknown after planning"],
        )

    def test_private_endpoint_with_public_fallback_enabled_emits_distinct_finding(self) -> None:
        findings = _evaluate(
            [
                _storage_account(public_network=True, default_action="Allow"),
                _private_endpoint("logs_blob", _STORAGE_ID, subresources=("blob",)),
            ],
            "azure-storage-account-missing-private-endpoint",
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-public-fallback"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            ["azurerm_storage_account.logs", "azurerm_private_endpoint.logs_blob"],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["private_endpoints"], ["azurerm_private_endpoint.logs_blob"])
        self.assertEqual(evidence["private_endpoint_subresources"], ["blob"])

    def test_private_endpoint_with_public_fallback_unknown_emits_uncertain_finding(self) -> None:
        findings = _evaluate(
            [
                _key_vault(public_network=_MISSING, unknown_public_network=True),
                _private_endpoint("vault", _KEY_VAULT_ID, subresources=("vault",)),
            ],
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-public-fallback"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        evidence = _evidence_by_key(finding)
        self.assertEqual(evidence["private_endpoints"], ["azurerm_private_endpoint.vault"])
        self.assertEqual(
            evidence["fallback_uncertainty"],
            ["public_network_access_enabled is unknown after planning"],
        )

    def test_private_endpoint_missing_dns_zone_group_is_detected(self) -> None:
        findings = _evaluate(
            [
                _storage_account(public_network=False, default_action="Deny"),
                _private_endpoint("logs_blob", _STORAGE_ID, subresources=("blob",)),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-dns-posture-incomplete"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(
            finding.affected_resources,
            ["azurerm_storage_account.logs", "azurerm_private_endpoint.logs_blob"],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["private_endpoint_dns_posture"],
            ["azurerm_private_endpoint.logs_blob: no private_dns_zone_group blocks are represented"],
        )

    def test_private_endpoint_unknown_dns_zone_group_is_detected(self) -> None:
        findings = _evaluate(
            [
                _key_vault(public_network=False, default_action="Deny"),
                _private_endpoint(
                    "vault",
                    _KEY_VAULT_ID,
                    subresources=("vault",),
                    unknown_dns_group=True,
                ),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-dns-posture-incomplete"])
        self.assertEqual(
            _evidence_by_key(findings[0])["private_endpoint_dns_posture"],
            ["azurerm_private_endpoint.vault: private_dns_zone_group is unknown after planning"],
        )

    def test_private_endpoint_dns_zone_group_without_zone_ids_is_detected(self) -> None:
        findings = _evaluate(
            [
                _storage_account(public_network=False, default_action="Deny"),
                _private_endpoint(
                    "logs_blob",
                    _STORAGE_ID,
                    subresources=("blob",),
                    empty_dns_group=True,
                ),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-dns-posture-incomplete"])
        self.assertEqual(
            _evidence_by_key(findings[0])["private_endpoint_dns_posture"],
            ["azurerm_private_endpoint.logs_blob: private_dns_zone_group does not include private_dns_zone_ids"],
        )

    def test_private_endpoint_dns_zone_link_to_different_vnet_is_detected(self) -> None:
        findings = _evaluate(
            [
                _mssql_server(public_network=False),
                _virtual_network("main"),
                _virtual_network("shared"),
                _subnet("data", "main"),
                _private_dns_zone("sql", "privatelink.database.windows.net"),
                _private_dns_zone_virtual_network_link(
                    "sql_shared",
                    zone_reference="azurerm_private_dns_zone.sql.name",
                    virtual_network_reference="azurerm_virtual_network.shared.id",
                ),
                _private_endpoint(
                    "sql",
                    _MSSQL_ID,
                    subresources=("sqlServer",),
                    dns_zone_ids=("azurerm_private_dns_zone.sql.id",),
                    subnet_id="azurerm_subnet.data.id",
                ),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-dns-posture-incomplete"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["private_endpoint_dns_posture"],
            [
                "azurerm_private_endpoint.sql: private DNS zone links are modeled for the endpoint zones "
                "but none target the endpoint VNet"
            ],
        )
        self.assertEqual(
            evidence["private_dns_zone_groups"],
            [
                "azurerm_private_endpoint.sql: group_names=private-dns",
                "azurerm_private_endpoint.sql: zone_ids=azurerm_private_dns_zone.sql.id",
            ],
        )
        self.assertEqual(
            evidence["private_dns_zone_links"],
            [
                "azurerm_private_dns_zone_virtual_network_link.sql_shared: "
                "zone=azurerm_private_dns_zone.sql.name; virtual_network=azurerm_virtual_network.shared.id"
            ],
        )
        self.assertIn("azurerm_private_endpoint.sql: subnet=azurerm_subnet.data.id", evidence["endpoint_network"])
        self.assertIn(
            "azurerm_private_endpoint.sql: endpoint_vnet=azurerm_virtual_network.main", evidence["endpoint_network"]
        )

    def test_private_endpoint_dns_zone_group_and_matching_vnet_link_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _storage_account(public_network=False, default_action="Deny"),
                _virtual_network("main"),
                _subnet("data", "main"),
                _private_dns_zone("blob", "privatelink.blob.core.windows.net"),
                _private_dns_zone_virtual_network_link(
                    "blob_main",
                    zone_reference="azurerm_private_dns_zone.blob.name",
                    virtual_network_reference="azurerm_virtual_network.main.id",
                ),
                _private_endpoint(
                    "logs_blob",
                    _STORAGE_ID,
                    subresources=("blob",),
                    dns_zone_ids=("azurerm_private_dns_zone.blob.id",),
                    subnet_id="azurerm_subnet.data.id",
                ),
            ],
            "azure-private-endpoint-dns-posture-incomplete",
        )

        self.assertEqual(findings, [])

    def test_private_endpoint_with_public_network_disabled_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _storage_account(public_network=False, default_action="Allow"),
                _private_endpoint("logs_blob", _STORAGE_ID, subresources=("blob",)),
            ],
            "azure-storage-account-missing-private-endpoint",
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
