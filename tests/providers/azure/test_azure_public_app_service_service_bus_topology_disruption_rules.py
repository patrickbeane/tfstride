from __future__ import annotations

import unittest
from typing import cast

from tests.helpers.inventory import inventory_with_resources
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID,
    _TOPIC_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_topology_destruction_paths import (
    _DELETE_NAMESPACE,
    _DELETE_QUEUE,
    _DELETE_SUBSCRIPTION,
    _DELETE_TOPIC,
    _contributor_assignment,
    _control_assignment,
    _control_role,
    _entity,
    _management_lock,
    _namespace,
    _subscription,
    _workload,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.azure.app_service_service_bus_topology_disruption_rules import (
    _authorization_grant_is_current,
)
from tfstride.providers.azure.arm_control_plane_evidence import (
    AzureArmControlPlaneGrant,
)
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-service-bus-topology-disruption"
_MESSAGE_RULE_ID = "azure-public-app-service-service-bus-message-disruption"
_RECEIVE_RULE_ID = "azure-public-app-service-service-bus-receive-access"
_MUTATION_RULE_ID = "azure-public-app-service-service-bus-mutation-access"
_WORKLOAD_ADDRESS = "azurerm_linux_web_app.orders"
_QUEUE_ADDRESS = "azurerm_servicebus_queue.orders"
_TOPIC_ADDRESS = "azurerm_servicebus_topic.orders"
_SUBSCRIPTION_ADDRESS = "azurerm_servicebus_subscription.orders"
_NAMESPACE_ADDRESS = "azurerm_servicebus_namespace.orders"
_ASSIGNMENT_ADDRESS = "azurerm_role_assignment.messaging_topology"


def _public(resource: TerraformResource, *, enabled: bool = True) -> TerraformResource:
    resource.values["public_network_access_enabled"] = enabled
    return resource


def _evaluate(
    resources: list[TerraformResource],
    rule_ids: frozenset[str] | None = None,
):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(
            enabled_rule_ids=rule_ids or frozenset({_RULE_ID}),
        ),
    )
    return inventory, findings


def _evidence(finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _topology_resources(
    actions: list[str],
    *,
    public: bool = True,
    include_children: bool = True,
) -> list[TerraformResource]:
    resources: list[TerraformResource] = [
        _namespace(),
        _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
    ]
    if include_children:
        resources.extend(
            [
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
            ]
        )
    resources.extend(
        [
            _public(_workload(public=public), enabled=public),
            _control_role(actions=actions),
            _control_assignment(),
        ]
    )
    return resources


def _raw_authorization_grant(path) -> AzureArmControlPlaneGrant:
    grant = dict(path["authorization_grant"])
    role_evidence = grant.pop("role_evidence")
    assert isinstance(role_evidence, dict)
    grant.update(role_evidence)
    return cast(AzureArmControlPlaneGrant, grant)


class AzurePublicAppServiceServiceBusTopologyDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered_as_denial_of_service(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

        _, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], include_children=False),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, StrideCategory.DENIAL_OF_SERVICE)

    def test_built_in_contributor_authority_is_revalidated(self) -> None:
        _, findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_workload()),
                _contributor_assignment(),
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, _RULE_ID)

    def test_current_grant_must_match_exact_projector_contract(self) -> None:
        inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], include_children=False),
        )
        self.assertEqual(len(findings), 1)
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        path = azure_facts(workload).app_service_service_bus_topology_destruction_paths[0]
        grant = _raw_authorization_grant(path)
        self.assertTrue(
            _authorization_grant_is_current(path, grant, _DELETE_QUEUE),
        )

        incompatible_grants = {
            "role resolution": {"role_resolution_state": "unknown"},
            "assignable scope": {
                "assignable_scope_compatibility_state": "unknown",
            },
            "role condition": {
                "role_definition_condition_state": "configured",
            },
            "delegation constraint": {
                "delegation_constraint_kind": "allowed_role_definition_ids",
                "allowed_role_definition_ids": ["role-id"],
            },
            "requested operation": {"requested_actions": [_DELETE_TOPIC]},
            "matched operation": {"matched_actions": [_DELETE_TOPIC]},
            "excluded operation": {"excluded_actions": [_DELETE_QUEUE]},
        }
        for case, changes in incompatible_grants.items():
            with self.subTest(case=case):
                candidate = cast(
                    AzureArmControlPlaneGrant,
                    {**grant, **changes},
                )
                self.assertFalse(
                    _authorization_grant_is_current(
                        path,
                        candidate,
                        _DELETE_QUEUE,
                    )
                )

    def test_topology_deletion_is_not_message_disclosure_or_mutation(self) -> None:
        _, findings = _evaluate(
            _topology_resources(
                [
                    _DELETE_NAMESPACE,
                    _DELETE_QUEUE,
                    _DELETE_TOPIC,
                    _DELETE_SUBSCRIPTION,
                ]
            ),
            frozenset(
                {
                    _RULE_ID,
                    _MESSAGE_RULE_ID,
                    _RECEIVE_RULE_ID,
                    _MUTATION_RULE_ID,
                }
            ),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_exact_targets_and_operations_are_reported_once(self) -> None:
        _inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE, _DELETE_TOPIC]),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn(_QUEUE_ADDRESS, finding.affected_resources)
        self.assertIn(_TOPIC_ADDRESS, finding.affected_resources)
        self.assertIn(_NAMESPACE_ADDRESS, finding.affected_resources)
        self.assertNotIn(_SUBSCRIPTION_ADDRESS, finding.affected_resources)
        self.assertIn("queue(s) or topic(s)", finding.rationale)
        self.assertIn("does not establish successful deletion", finding.rationale)
        self.assertIn("descendant-resource impact", finding.rationale)

        evidence = _evidence(finding)
        topology_paths = evidence["service_bus_topology_destruction_paths"]
        self.assertEqual(len(topology_paths), 2)
        self.assertTrue(any(f"operation={_DELETE_QUEUE}" in value for value in topology_paths))
        self.assertTrue(any(f"operation={_DELETE_TOPIC}" in value for value in topology_paths))
        self.assertTrue(
            all(
                "authorization_state=granted" in value and "operation_evaluation=deterministic_allowed" in value
                for value in topology_paths
            )
        )
        self.assertEqual(len(evidence["topology_deletion_outcome_evidence"]), 2)
        self.assertTrue(
            all(
                "successful_deletion_observed=False" in value and "out_of_plan_topology_evaluated=False" in value
                for value in evidence["topology_deletion_outcome_evidence"]
            )
        )

    def test_namespace_and_subscription_paths_preserve_native_ancestry(self) -> None:
        _inventory, findings = _evaluate(
            _topology_resources([_DELETE_NAMESPACE, _DELETE_SUBSCRIPTION]),
        )

        self.assertEqual(len(findings), 1)
        evidence = _evidence(findings[0])
        paths = evidence["service_bus_topology_destruction_paths"]
        self.assertEqual(len(paths), 2)
        namespace_path = next(value for value in paths if f"operation={_DELETE_NAMESPACE}" in value)
        subscription_path = next(value for value in paths if f"operation={_DELETE_SUBSCRIPTION}" in value)
        self.assertIn(f"target_address={_NAMESPACE_ADDRESS}", namespace_path)
        self.assertIn("target_granularity=service_bus_namespace_topology", namespace_path)
        self.assertIn(f"topic={_TOPIC_ADDRESS}", subscription_path)
        self.assertIn(f"subscription={_SUBSCRIPTION_ADDRESS}", subscription_path)
        self.assertIn("target_granularity=subscription_topology", subscription_path)

    def test_private_workload_keeps_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], public=False, include_children=False),
        )

        self.assertEqual(findings, [])
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertEqual(
            len(azure_facts(workload).app_service_service_bus_topology_destruction_paths),
            1,
        )

    def test_stale_target_evidence_is_rejected(self) -> None:
        inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], include_children=False),
        )
        self.assertEqual(len(findings), 1)
        workload = inventory.get_by_address(_WORKLOAD_ADDRESS)
        assert workload is not None
        paths = [dict(path) for path in azure_facts(workload).app_service_service_bus_topology_destruction_paths]
        paths[0]["service_bus_resource_id"] = f"{_QUEUE_ID}-stale"
        azure_facts(workload).set_app_service_service_bus_topology_destruction_paths(paths)

        _inventory, stale_findings = _evaluate_inventory(inventory)
        self.assertEqual(stale_findings, [])

    def test_stale_assignment_evidence_is_rejected(self) -> None:
        inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], include_children=False),
        )
        self.assertEqual(len(findings), 1)
        assignment = inventory.get_by_address(_ASSIGNMENT_ADDRESS)
        assert assignment is not None
        azure_facts(assignment).set(
            AzureResourceMetadata.ROLE_DEFINITION_ID,
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/stale",
        )

        _inventory, stale_findings = _evaluate_inventory(inventory)
        self.assertEqual(stale_findings, [])

    def test_current_management_lock_rejects_cached_topology_path(self) -> None:
        inventory, findings = _evaluate(
            _topology_resources([_DELETE_QUEUE], include_children=False),
        )
        self.assertEqual(len(findings), 1)
        lock_inventory = AzureNormalizer().normalize(
            [
                _management_lock(
                    scope="azurerm_servicebus_queue.orders.id",
                )
            ]
        )
        lock = lock_inventory.get_by_address("azurerm_management_lock.topology_lock")
        assert lock is not None
        inventory = inventory_with_resources(inventory, (*inventory.resources, lock))

        _inventory, stale_findings = _evaluate_inventory(inventory)
        self.assertEqual(stale_findings, [])


def _evaluate_inventory(inventory):
    return inventory, StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


if __name__ == "__main__":
    unittest.main()
