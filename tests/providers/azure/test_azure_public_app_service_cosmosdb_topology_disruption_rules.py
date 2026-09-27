from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_cosmosdb_topology_destruction_paths import (
    _azure_account,
)
from tests.providers.test_public_workload_structured_data_topology_destruction_boundaries import (
    _AZURE_DELETE_ACCOUNT,
    _AZURE_DELETE_CONTAINER,
    _AZURE_DELETE_DATABASE,
    _azure_control_assignment,
    _azure_control_role,
    _azure_management_lock,
    _azure_workload,
    azure_container,
    azure_database,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts

_RULE_ID = "azure-public-app-service-cosmosdb-topology-disruption"
_ITEM_RULE_ID = "azure-public-app-service-cosmosdb-item-disruption"
_MUTATION_RULE_ID = "azure-public-app-service-cosmosdb-mutation-access"
_ACCOUNT_ADDRESS = "azurerm_cosmosdb_account.orders"
_DATABASE_ADDRESS = "azurerm_cosmosdb_sql_database.app"
_CONTAINER_ADDRESS = "azurerm_cosmosdb_sql_container.events"
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_ROLE_ADDRESS = "azurerm_role_definition.cosmos_topology"
_ACCOUNT_ID = "/subscriptions/sub-0001/resourceGroups/data/providers/Microsoft.DocumentDB/databaseAccounts/orders"


def _public_workload() -> TerraformResource:
    workload = _azure_workload()
    workload.values["public_network_access_enabled"] = True
    return workload


def _resources(
    *,
    public: bool = True,
    account: TerraformResource | None = None,
    role: TerraformResource | None = None,
    assignment: TerraformResource | None = None,
    actions: list[str] | None = None,
) -> list[TerraformResource]:
    return [
        account or _azure_account(),
        azure_database(),
        azure_container(),
        _public_workload() if public else _azure_workload(public=False),
        role
        or _azure_control_role(
            actions=actions
            or [
                _AZURE_DELETE_ACCOUNT,
                _AZURE_DELETE_DATABASE,
                _AZURE_DELETE_CONTAINER,
            ]
        ),
        assignment or _azure_control_assignment(),
    ]


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )
    return inventory, findings


def _reevaluate(inventory, *rule_ids: str):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or (_RULE_ID,))),
    )


def _evidence(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceCosmosDbTopologyDisruptionRuleTests(unittest.TestCase):
    def test_topology_deletion_is_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            _resources(actions=[_AZURE_DELETE_CONTAINER]),
            _RULE_ID,
            _ITEM_RULE_ID,
            _MUTATION_RULE_ID,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)

    def test_account_scope_fans_out_to_exact_modeled_targets(self) -> None:
        _, findings = _evaluate(
            _resources(
                actions=[
                    _AZURE_DELETE_ACCOUNT,
                    _AZURE_DELETE_DATABASE,
                    _AZURE_DELETE_CONTAINER,
                ]
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        evidence = _evidence(finding)
        paths = evidence["cosmosdb_topology_destruction_paths"]
        self.assertEqual(len(paths), 3)
        self.assertIn(f"operation={_AZURE_DELETE_ACCOUNT}", paths[0])
        self.assertIn("target_scope=exact_cosmosdb_account", paths[0])
        self.assertTrue(any("target_scope=exact_cosmosdb_sql_database" in value for value in paths))
        self.assertTrue(any("target_scope=exact_cosmosdb_sql_container" in value for value in paths))
        self.assertIn("successful_deletion_observed=false", evidence["cosmosdb_backup_recovery_evidence"][0])
        self.assertIn("out_of_plan_restore_resources_evaluated=false", evidence["cosmosdb_backup_recovery_evidence"][0])
        self.assertIn("permits external ingress within the evidenced scope", finding.rationale)
        self.assertIn("successful deletion", finding.rationale)
        self.assertNotIn("restoration_observed=true", finding.rationale)

    def test_private_workload_keeps_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(_resources(public=False))
        self.assertEqual(findings, [])
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertTrue(azure_facts(workload).app_service_cosmosdb_topology_destruction_paths)

    def test_mixed_native_item_and_control_plane_delete_are_separate(self) -> None:
        control_resources = _resources(actions=[_AZURE_DELETE_CONTAINER])
        native_assignment = _resource(
            "azurerm_cosmosdb_sql_role_assignment",
            "item_delete",
            {
                "resource_group_name": "data",
                "account_name": "orders",
                "scope": _ACCOUNT_ID,
                "principal_id": "app-system-principal-id",
                "role_definition_id": (
                    "/subscriptions/sub-0001/resourceGroups/data/providers/"
                    "Microsoft.DocumentDB/databaseAccounts/orders/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
                ),
            },
        )
        _, findings = _evaluate(
            [*control_resources, native_assignment],
            _RULE_ID,
            _ITEM_RULE_ID,
            _MUTATION_RULE_ID,
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn(_RULE_ID, rule_ids)
        self.assertIn(_ITEM_RULE_ID, rule_ids)
        self.assertIn(_MUTATION_RULE_ID, rule_ids)

    def test_removed_current_role_action_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_resources(actions=[_AZURE_DELETE_CONTAINER]))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        role = inventory.get_by_address(_ROLE_ADDRESS)
        assert role is not None
        azure_facts(role).set(AzureResourceMetadata.ROLE_DEFINITION_ACTIONS, [])

        self.assertEqual(_reevaluate(inventory), [])

    def test_stale_cached_target_is_rejected(self) -> None:
        inventory, findings = _evaluate(_resources(actions=[_AZURE_DELETE_CONTAINER]))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = azure_facts(workload).app_service_cosmosdb_topology_destruction_paths
        paths[0]["cosmosdb_resource_address"] = "azurerm_cosmosdb_sql_container.stale"
        azure_facts(workload).set_app_service_cosmosdb_topology_destruction_paths(paths)

        self.assertEqual(_reevaluate(inventory), [])

    def test_current_lock_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_resources(actions=[_AZURE_DELETE_CONTAINER]))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

        lock_inventory = AzureNormalizer().normalize(
            [
                _azure_management_lock(
                    scope=f"{_ACCOUNT_ID}/sqlDatabases/app/containers/events",
                )
            ]
        )
        current_inventory = ResourceInventory(
            provider=inventory.provider,
            resources=[*inventory.resources, *lock_inventory.resources],
        )

        self.assertEqual(_reevaluate(current_inventory), [])

    def test_recovery_posture_drift_refreshes_current_evidence(self) -> None:
        account = _azure_account(unknown_backup=True)
        inventory, findings = _evaluate(_resources(account=account, actions=[_AZURE_DELETE_ACCOUNT]))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertIn(
            "backup_posture_state=unknown",
            _evidence(findings[0])["cosmosdb_backup_recovery_evidence"][0],
        )

        account_resource = inventory.get_by_address(_ACCOUNT_ADDRESS)
        assert account_resource is not None
        azure_facts(account_resource).set(
            AzureResourceMetadata.COSMOSDB_BACKUP_TYPE,
            "Continuous",
        )
        azure_facts(account_resource).set(
            AzureResourceMetadata.COSMOSDB_BACKUP_CONFIGURATION_STATE,
            "configured",
        )
        azure_facts(account_resource).set(
            AzureResourceMetadata.COSMOSDB_POSTURE_UNCERTAINTIES,
            [],
        )

        current_findings = _reevaluate(inventory)
        self.assertEqual([finding.rule_id for finding in current_findings], [_RULE_ID])
        recovery = _evidence(current_findings[0])["cosmosdb_backup_recovery_evidence"][0]
        self.assertIn("backup_posture_state=continuous", recovery)
        self.assertIn("backup_interval_minutes=not_applicable", recovery)
        self.assertNotIn("backup posture is unknown", recovery)

    def test_unknown_backup_fields_are_rendered_as_unknown(self) -> None:
        account = _azure_account(unknown_backup=True)
        _, findings = _evaluate(_resources(account=account, actions=[_AZURE_DELETE_ACCOUNT]))
        recovery = _evidence(findings[0])["cosmosdb_backup_recovery_evidence"][0]
        self.assertIn("backup_posture_state=unknown", recovery)
        self.assertIn("backup_tier=unknown", recovery)
        self.assertIn("backup_interval_minutes=unknown", recovery)

    def test_unrelated_rules_do_not_receive_control_plane_delete_evidence(self) -> None:
        _, findings = _evaluate(
            _resources(actions=[_AZURE_DELETE_ACCOUNT]),
            _RULE_ID,
            _ITEM_RULE_ID,
            _MUTATION_RULE_ID,
        )
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_registration_uses_public_cosmos_topology_rule(self) -> None:
        _, findings = _evaluate(_resources(actions=[_AZURE_DELETE_ACCOUNT]))
        self.assertEqual(findings[0].rule_id, _RULE_ID)


def _resource(resource_type: str, name: str, values: dict[str, object]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values={},
    )


if __name__ == "__main__":
    unittest.main()
