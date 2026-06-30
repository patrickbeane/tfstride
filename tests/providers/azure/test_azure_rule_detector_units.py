from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_registry import default_rule_registry
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.azure.aks_rules import AzureAksRuleDetectors
from tfstride.providers.azure.app_service_rules import AzureAppServiceRuleDetectors
from tfstride.providers.azure.key_vault_rules import AzureKeyVaultRuleDetectors
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.mssql_rules import AzureMssqlRuleDetectors
from tfstride.providers.azure.postgresql_rules import AzurePostgresqlRuleDetectors
from tfstride.providers.azure.private_endpoint_rules import AzurePrivateEndpointPostureRuleDetectors
from tfstride.providers.azure.public_network import PUBLIC_NETWORK_FALLBACK_ENABLED
from tfstride.providers.azure.resource_types import AzureResourceType

_RULE_REGISTRY = default_rule_registry()
_FINDING_FACTORY = FindingFactory(_RULE_REGISTRY)
_STORAGE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs"
_MSSQL_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Sql/servers/sqlserver"
_POSTGRESQL_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.DBforPostgreSQL/flexibleServers/postgres"
)


def _context(resources: list[NormalizedResource], *, provider: str = "azure") -> RuleEvaluationContext:
    return RuleEvaluationContext(
        inventory=ResourceInventory(provider=provider, resources=resources),
        boundary_index={},
        rule_registry=_RULE_REGISTRY,
    )


def _resource(
    resource_type: str,
    name: str,
    *,
    category: ResourceCategory,
    metadata: dict | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.{name}",
        provider="azure",
        resource_type=resource_type,
        name=name,
        category=category,
        metadata=metadata or {},
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAppServiceRuleDetectorUnitTests(unittest.TestCase):
    def test_public_network_detector_emits_finding_from_normalized_facts(self) -> None:
        app = _resource(
            AzureResourceType.LINUX_WEB_APP,
            "app",
            category=ResourceCategory.COMPUTE,
            metadata={
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: PUBLIC_NETWORK_FALLBACK_ENABLED,
            },
        )

        findings = AzureAppServiceRuleDetectors(_FINDING_FACTORY).detect_public_network_access_not_disabled(
            _context([app]),
            "azure-app-service-public-network-access-not-disabled",
        )

        self.assertEqual(
            [finding.rule_id for finding in findings], ["azure-app-service-public-network-access-not-disabled"]
        )
        self.assertEqual(findings[0].affected_resources, ["azurerm_linux_web_app.app"])
        self.assertEqual(
            _evidence_by_key(findings[0])["network_posture"],
            ["public_network_fallback_state=enabled", "public_network_access_enabled is true"],
        )


class AzureKeyVaultRuleDetectorUnitTests(unittest.TestCase):
    def test_public_network_detector_emits_finding_from_normalized_facts(self) -> None:
        vault = _resource(
            AzureResourceType.KEY_VAULT,
            "vault",
            category=ResourceCategory.DATA,
            metadata={
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
            },
        )

        findings = AzureKeyVaultRuleDetectors(_FINDING_FACTORY).detect_public_network_access(
            _context([vault]),
            "azure-key-vault-public-network-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-key-vault-public-network-access"])
        self.assertEqual(findings[0].affected_resources, ["azurerm_key_vault.vault"])
        self.assertIn(
            "effective network_acls.default_action is Allow", _evidence_by_key(findings[0])["network_exposure"]
        )


class AzureMssqlRuleDetectorUnitTests(unittest.TestCase):
    def test_broad_firewall_detector_links_rule_to_server_from_normalized_facts(self) -> None:
        server = _resource(
            AzureResourceType.MSSQL_SERVER,
            "sqlserver",
            category=ResourceCategory.DATA,
            metadata={AzureResourceMetadata.MSSQL_SERVER_ID: _MSSQL_ID},
        )
        firewall_rule = _resource(
            AzureResourceType.MSSQL_FIREWALL_RULE,
            "wide",
            category=ResourceCategory.NETWORK,
            metadata={
                AzureResourceMetadata.MSSQL_SERVER_ID: _MSSQL_ID,
                AzureResourceMetadata.MSSQL_FIREWALL_START_IP: "0.0.0.0",
                AzureResourceMetadata.MSSQL_FIREWALL_END_IP: "255.255.255.255",
            },
        )

        findings = AzureMssqlRuleDetectors(_FINDING_FACTORY).detect_broad_firewall_access(
            _context([server, firewall_rule]),
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-sql-firewall-broad-public-access"])
        self.assertEqual(
            findings[0].affected_resources,
            ["azurerm_mssql_server.sqlserver", "azurerm_mssql_firewall_rule.wide"],
        )
        self.assertIn("server_id is " + _MSSQL_ID, _evidence_by_key(findings[0])["firewall_rule"])


class AzurePostgresqlRuleDetectorUnitTests(unittest.TestCase):
    def test_weak_tls_detector_reads_server_configuration_facts(self) -> None:
        server = _resource(
            AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
            "postgres",
            category=ResourceCategory.DATA,
            metadata={AzureResourceMetadata.POSTGRESQL_SERVER_ID: _POSTGRESQL_ID},
        )
        config = _resource(
            AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
            "ssl",
            category=ResourceCategory.DATA,
            metadata={
                AzureResourceMetadata.POSTGRESQL_CONFIG_SERVER_ID: _POSTGRESQL_ID,
                AzureResourceMetadata.POSTGRESQL_CONFIG_NAME: "ssl_min_protocol_version",
                AzureResourceMetadata.POSTGRESQL_CONFIG_VALUE: "TLSv1.0",
            },
        )

        findings = AzurePostgresqlRuleDetectors(_FINDING_FACTORY).detect_weak_tls_or_ssl(
            _context([server, config]),
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-postgresql-weak-tls-or-ssl"])
        self.assertEqual(findings[0].affected_resources, ["azurerm_postgresql_flexible_server.postgres"])
        self.assertEqual(
            _evidence_by_key(findings[0])["transport_posture"],
            ["ssl_min_protocol_version is TLSv1.0"],
        )


class AzurePrivateEndpointRuleDetectorUnitTests(unittest.TestCase):
    def test_public_fallback_detector_uses_private_endpoint_index_from_normalized_facts(self) -> None:
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "logs",
            category=ResourceCategory.DATA,
            metadata={
                AzureResourceMetadata.STORAGE_ACCOUNT_ID: _STORAGE_ID,
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: PUBLIC_NETWORK_FALLBACK_ENABLED,
            },
        )
        private_endpoint = _resource(
            AzureResourceType.PRIVATE_ENDPOINT,
            "logs",
            category=ResourceCategory.NETWORK,
            metadata={
                AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS: [
                    {
                        "name": "logs-blob",
                        "private_connection_resource_id": _STORAGE_ID,
                        "subresource_names": ["blob"],
                        "is_manual_connection": False,
                    }
                ],
            },
        )

        findings = AzurePrivateEndpointPostureRuleDetectors(_FINDING_FACTORY).detect_private_endpoint_public_fallback(
            _context([storage, private_endpoint]),
            "azure-private-endpoint-public-fallback",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-private-endpoint-public-fallback"])
        self.assertEqual(
            findings[0].affected_resources,
            ["azurerm_storage_account.logs", "azurerm_private_endpoint.logs"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["private_endpoints"], ["azurerm_private_endpoint.logs"])
        self.assertEqual(evidence["private_endpoint_subresources"], ["blob"])


class AzureRuleDetectorProviderScopeUnitTests(unittest.TestCase):
    def test_new_detector_classes_ignore_non_azure_inventory(self) -> None:
        app = _resource(
            AzureResourceType.LINUX_WEB_APP,
            "app",
            category=ResourceCategory.COMPUTE,
            metadata={
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: PUBLIC_NETWORK_FALLBACK_ENABLED,
            },
        )
        vault = _resource(
            AzureResourceType.KEY_VAULT,
            "vault",
            category=ResourceCategory.DATA,
            metadata={
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Allow",
            },
        )
        sql = _resource(
            AzureResourceType.MSSQL_SERVER,
            "sqlserver",
            category=ResourceCategory.DATA,
            metadata={AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True},
        )
        postgres = _resource(
            AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
            "postgres",
            category=ResourceCategory.DATA,
            metadata={AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True},
        )
        storage = _resource(
            AzureResourceType.STORAGE_ACCOUNT,
            "logs",
            category=ResourceCategory.DATA,
            metadata={
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: PUBLIC_NETWORK_FALLBACK_ENABLED,
            },
        )
        cluster = _resource(
            AzureResourceType.KUBERNETES_CLUSTER,
            "cluster",
            category=ResourceCategory.COMPUTE,
            metadata={
                AzureResourceMetadata.AKS_PRIVATE_CLUSTER_STATE: "disabled",
                AzureResourceMetadata.AKS_AUTHORIZED_IP_RANGES_STATE: "not_configured",
            },
        )
        non_azure_context = _context([app, vault, sql, postgres, storage, cluster], provider="aws")

        cases = (
            (
                AzureAppServiceRuleDetectors(_FINDING_FACTORY).detect_public_network_access_not_disabled,
                "azure-app-service-public-network-access-not-disabled",
            ),
            (
                AzureKeyVaultRuleDetectors(_FINDING_FACTORY).detect_public_network_access,
                "azure-key-vault-public-network-access",
            ),
            (
                AzureMssqlRuleDetectors(_FINDING_FACTORY).detect_public_network_access_enabled,
                "azure-sql-public-network-access-enabled",
            ),
            (
                AzurePostgresqlRuleDetectors(_FINDING_FACTORY).detect_public_network_access_enabled,
                "azure-postgresql-public-network-access-enabled",
            ),
            (
                AzurePrivateEndpointPostureRuleDetectors(
                    _FINDING_FACTORY
                ).detect_storage_account_missing_private_endpoint,
                "azure-storage-account-missing-private-endpoint",
            ),
            (
                AzurePrivateEndpointPostureRuleDetectors(
                    _FINDING_FACTORY
                ).detect_private_endpoint_dns_posture_incomplete,
                "azure-private-endpoint-dns-posture-incomplete",
            ),
            (
                AzureAksRuleDetectors(_FINDING_FACTORY).detect_public_api_server_unrestricted,
                "azure-aks-api-server-public-unrestricted",
            ),
        )

        for detector, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                self.assertEqual(detector(non_azure_context, rule_id), [])


if __name__ == "__main__":
    unittest.main()
