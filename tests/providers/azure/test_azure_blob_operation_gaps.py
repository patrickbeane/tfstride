from __future__ import annotations

import json
import unittest
from dataclasses import replace

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _CUSTOM_ROLE_ID,
    _STORAGE_ACCOUNT_ID,
    _custom_role,
    _custom_role_assignment,
    _role_assignment,
    _storage_account,
    _storage_container,
    _symbolic_resolution,
    _web_app,
)
from tfstride.models import AnalysisResult, TerraformReferenceResolutionState, TerraformReferenceTarget
from tfstride.providers.azure.blob_operation_gaps import (
    BLOB_ACCESS,
    BLOB_DELETION,
    BLOB_GAP_FAMILIES,
    BLOB_MUTATION,
    BLOB_TOPOLOGY,
    collect_blob_operation_gaps,
)
from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.catalog import default_provider_operation_gap_factories_by_provider
from tfstride.reporting.json_report import render_json
from tfstride.reporting.markdown import render_markdown

_WRITE = "microsoft.storage/storageaccounts/blobservices/containers/blobs/write"
_DELETE_CONTAINER = "Microsoft.Storage/storageAccounts/blobServices/containers/delete"
_ACCOUNT = "azurerm_storage_account.orders"
_CONTAINER = "azurerm_storage_container.orders"
_ROLE = "azurerm_role_definition.blob_writer"


def _normalize(resources):
    return AzureNormalizer().normalize(resources)


def _signature(results):
    return {(gap.family, gap.operation, gap.target_address, gap.reason_code) for gap in results.records}


class AzureBlobOperationGapTests(unittest.TestCase):
    def test_provider_registration_and_evaluated_grant_are_quiet(self):
        inventory = _normalize([_storage_account(), _storage_container(), _web_app(), _role_assignment()])
        results = collect_blob_operation_gaps(inventory)
        self.assertEqual(set(results.reporting_families), set(BLOB_GAP_FAMILIES))
        self.assertEqual(results.records, ())
        self.assertEqual(default_provider_operation_gap_factories_by_provider()["azure"][0](inventory), results)
        self.assertTrue(any("deny assignments" in limitation for limitation in AZURE_LIMITATIONS))

    def test_read_only_blob_role_does_not_create_a_topology_gap(self):
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_name="Storage Blob Data Reader",
            role_definition_id=(
                "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
            ),
            condition="SECRET-READER-CONDITION",
        )
        results = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), assignment])
        )
        self.assertEqual({gap.family for gap in results.records}, {BLOB_ACCESS})

    def test_condition_keeps_exact_operation_and_scope_without_leaking_expression(self):
        sentinel = "SECRET-AZURE-CONDITION"
        role = _custom_role(data_actions=[_WRITE])
        assignment = _role_assignment(
            role_definition_id="azurerm_role_definition.blob_writer.role_definition_resource_id",
            role_name=None,
            scope=_STORAGE_ACCOUNT_ID,
            condition=sentinel,
        )
        inventory = _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
        results = collect_blob_operation_gaps(inventory)
        self.assertEqual(
            _signature(results),
            {(family, _WRITE, _ACCOUNT, "assignment_condition_unresolved") for family in (BLOB_ACCESS, BLOB_MUTATION)},
        )
        self.assertTrue(all(gap.scope == _STORAGE_ACCOUNT_ID for gap in results.records))
        self.assertTrue(all(gap.provenance[0].resource_address == assignment.address for gap in results.records))
        report = AnalysisResult("Azure gaps", "plan.json", "plan.json", inventory, [], [], operation_gaps=results)
        payload = json.loads(render_json(report))
        self.assertEqual(payload["analysis_coverage"]["references"]["unresolved_reference_count"], 0)
        self.assertEqual(payload["summary"]["active_findings"], 0)
        self.assertNotIn(sentinel, json.dumps(payload["operation_gaps"]))
        self.assertIn("condition", payload["operation_gaps"]["records"][0]["next_step"])
        self.assertIn("## Analysis Gaps", render_markdown(report))
        self.assertNotIn(sentinel, render_markdown(report))

    def test_unavailable_role_definition_is_case_specific_and_does_not_invent_operations(self):
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_name=None,
            role_definition_id="/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/missing",
        )
        results = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), assignment])
        )
        self.assertEqual({gap.reason_code for gap in results.records}, {"role_definition_unavailable"})
        self.assertTrue(all(gap.operation is None for gap in results.records if gap.family != BLOB_TOPOLOGY))
        self.assertEqual({gap.family for gap in results.records}, set(BLOB_GAP_FAMILIES))
        self.assertEqual(
            {gap.target_address for gap in results.records if gap.family in {BLOB_ACCESS, BLOB_MUTATION}},
            {_ACCOUNT},
        )
        self.assertEqual(
            {gap.target_address for gap in results.records if gap.family in {BLOB_DELETION, BLOB_TOPOLOGY}},
            {_CONTAINER},
        )
        unrelated = _storage_account()
        unrelated.address = "azurerm_storage_account.other"
        unrelated.name = "other"
        unrelated.values["id"] = _STORAGE_ACCOUNT_ID.replace("sub-0001", "sub-00010")
        with_unrelated = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), unrelated, _web_app(), assignment])
        )
        self.assertEqual(_signature(with_unrelated), _signature(results))

    def test_ambiguous_custom_role_reference_keeps_scope_but_no_operation(self):
        first = _custom_role(data_actions=[_WRITE])
        second = _custom_role(data_actions=[_WRITE])
        second.address = "azurerm_role_definition.duplicate"
        second.name = "duplicate"
        assignment = _role_assignment(scope=_STORAGE_ACCOUNT_ID, role_name=None, role_definition_id=_CUSTOM_ROLE_ID)
        results = collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), first, second, assignment]))
        self.assertEqual({gap.reason_code for gap in results.records}, {"role_definition_ambiguous"})
        self.assertTrue(all(gap.operation is None and gap.target_address == _ACCOUNT for gap in results.records))

    def test_unknown_assignable_scope_is_a_gap_but_known_incompatibility_is_not(self):
        role = _custom_role(data_actions=[_WRITE], unknown_values={"assignable_scopes": True})
        assignment = _custom_role_assignment(scope=_STORAGE_ACCOUNT_ID)
        uncertain = collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), role, assignment]))
        self.assertEqual(
            _signature(uncertain),
            {(family, _WRITE, _ACCOUNT, "assignable_scope_unresolved") for family in (BLOB_ACCESS, BLOB_MUTATION)},
        )
        self.assertTrue(all(gap.provenance[0].resource_address == _ROLE for gap in uncertain.records))
        role.unknown_values = {}
        role.values["assignable_scopes"] = ["/subscriptions/other"]
        self.assertEqual(
            collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), role, assignment])).records,
            (),
        )

    def test_container_delete_assignability_uses_its_arm_role_evidence(self):
        role = _custom_role(data_actions=[], unknown_values={"assignable_scopes": True})
        role.values["permissions"][0]["actions"] = [_DELETE_CONTAINER]
        assignment = _custom_role_assignment(scope=_STORAGE_ACCOUNT_ID)
        uncertain = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
        )
        self.assertEqual(
            _signature(uncertain),
            {(BLOB_TOPOLOGY, _DELETE_CONTAINER, _CONTAINER, "assignable_scope_unresolved")},
        )
        self.assertEqual(uncertain.records[0].provenance[0].resource_address, _ROLE)
        role.unknown_values = {}
        role.values["assignable_scopes"] = ["/subscriptions/other"]
        self.assertEqual(
            collect_blob_operation_gaps(
                _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
            ).records,
            (),
        )

    def test_unresolved_data_actions_and_control_plane_actions_stay_in_their_families(self):
        role = _custom_role(data_actions=[_WRITE], unknown_values={"permissions": [{"data_actions": True}]})
        assignment = _custom_role_assignment(scope=_STORAGE_ACCOUNT_ID)
        data = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
        )
        self.assertEqual({gap.reason_code for gap in data.records}, {"role_data_actions_unresolved"})
        self.assertEqual({gap.family for gap in data.records}, {BLOB_ACCESS, BLOB_MUTATION, BLOB_DELETION})
        self.assertNotIn(BLOB_TOPOLOGY, {gap.family for gap in data.records})
        role = _custom_role(data_actions=[], unknown_values={"permissions": [{"actions": True}]})
        topology = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
        )
        self.assertEqual(
            _signature(topology), {(BLOB_TOPOLOGY, _DELETE_CONTAINER, _CONTAINER, "role_actions_unresolved")}
        )

    def test_ambiguous_scope_reports_only_its_modeled_candidates(self):
        other = _storage_account()
        other.address = "azurerm_storage_account.other"
        other.name = "other"
        other.values["id"] = _STORAGE_ACCOUNT_ID.replace("ordersdata", "otherdata")
        assignment = _role_assignment(scope=None, unknown_values={"scope": True})
        resolution = _symbolic_resolution(("scope",), "azurerm_storage_account.orders.id")
        assignment.reference_resolutions = (
            replace(
                resolution,
                state=TerraformReferenceResolutionState.AMBIGUOUS,
                targets=(
                    *resolution.targets,
                    TerraformReferenceTarget(other.address, other.address + ".id"),
                ),
            ),
        )
        results = collect_blob_operation_gaps(_normalize([_storage_account(), other, _web_app(), assignment]))
        self.assertEqual({gap.reason_code for gap in results.records}, {"assignment_scope_ambiguous"})
        self.assertEqual({gap.target_address for gap in results.records}, {_ACCOUNT, other.address})
        self.assertTrue(all(gap.operation is not None for gap in results.records))

    def test_symbolic_principal_ambiguity_stays_with_the_referenced_workload(self):
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID, principal_id=None, unknown_values={"principal_id": True}
        )
        other = _web_app()
        other.address = "azurerm_linux_web_app.other"
        other.name = "other"
        other.values["identity"][0]["principal_id"] = "other-app-principal"
        resolution = _symbolic_resolution(("principal_id",), "azurerm_linux_web_app.orders.principal_id")
        assignment.reference_resolutions = (
            replace(
                resolution,
                state=TerraformReferenceResolutionState.AMBIGUOUS,
                targets=(
                    *resolution.targets,
                    TerraformReferenceTarget(other.address, other.address + ".principal_id"),
                ),
            ),
        )
        results = collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), other, assignment]))
        self.assertEqual({gap.reason_code for gap in results.records}, {"assignment_principal_unresolved"})
        self.assertEqual({gap.target_address for gap in results.records}, {_ACCOUNT})
        self.assertEqual(
            {gap.resource_address for gap in results.records}, {"azurerm_linux_web_app.orders", other.address}
        )
        assignment.reference_resolutions = ()
        self.assertEqual(
            collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), other, assignment])).records, ()
        )

    def test_container_delete_condition_is_specific_to_topology(self):
        role = _custom_role(data_actions=[])
        role.values["permissions"][0]["actions"] = [_DELETE_CONTAINER]
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_definition_id="azurerm_role_definition.blob_writer.role_definition_resource_id",
            role_name=None,
            condition="SECRET-CONTAINER-CONDITION",
        )
        results = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), role, assignment])
        )
        self.assertEqual(
            _signature(results),
            {(BLOB_TOPOLOGY, _DELETE_CONTAINER, _CONTAINER, "assignment_condition_unresolved")},
        )

    def test_builtin_blob_contributor_condition_also_affects_container_delete(self):
        assignment = _role_assignment(scope=_STORAGE_ACCOUNT_ID, condition="SECRET-BLOB-CONDITION")
        results = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), assignment])
        )
        self.assertIn(
            (BLOB_TOPOLOGY, _DELETE_CONTAINER, _CONTAINER, "assignment_condition_unresolved"), _signature(results)
        )

    def test_arm_only_builtin_role_does_not_create_blob_data_gaps(self):
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_name="Storage Account Contributor",
            role_definition_id=(
                "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/"
                "17d1049b-9a84-46fb-8f53-869881c3d3ab"
            ),
            condition="SECRET-ARM-CONDITION",
        )
        results = collect_blob_operation_gaps(
            _normalize([_storage_account(), _storage_container(), _web_app(), assignment])
        )
        self.assertEqual(
            _signature(results),
            {(BLOB_TOPOLOGY, _DELETE_CONTAINER, _CONTAINER, "assignment_condition_unresolved")},
        )

    def test_unknown_role_identity_is_not_dismissed_by_a_builtin_display_name(self):
        assignment = _role_assignment(
            scope=_STORAGE_ACCOUNT_ID,
            role_name="Storage Account Contributor",
            unknown_values={"role_definition_id": True},
        )
        results = collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), assignment]))
        self.assertEqual({gap.reason_code for gap in results.records}, {"role_definition_unavailable"})
        self.assertTrue(all(gap.operation is None for gap in results.records))

    def test_evaluated_role_exclusions_are_not_analysis_gaps(self):
        role = _custom_role(data_actions=[_WRITE], not_data_actions=[_WRITE])
        role.values["permissions"][0]["actions"] = [_DELETE_CONTAINER]
        role.values["permissions"][0]["not_actions"] = [_DELETE_CONTAINER]
        results = collect_blob_operation_gaps(
            _normalize(
                [
                    _storage_account(),
                    _storage_container(),
                    _web_app(),
                    role,
                    _custom_role_assignment(scope=_STORAGE_ACCOUNT_ID),
                ]
            )
        )
        self.assertEqual(results.records, ())

    def test_unknown_scope_cannot_turn_a_known_non_blob_role_into_a_blob_gap(self):
        role = _custom_role(data_actions=[])
        assignment = _custom_role_assignment(scope=None)
        assignment.reference_resolutions = (
            replace(
                _symbolic_resolution(("scope",), "azurerm_storage_account.orders.id"),
                state=TerraformReferenceResolutionState.AMBIGUOUS,
            ),
        )
        results = collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), role, assignment]))
        self.assertEqual(results.records, ())

    def test_unknown_scope_without_target_or_unrelated_principal_is_quiet(self):
        assignment = _role_assignment(scope=None, unknown_values={"scope": True})
        self.assertEqual(
            collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), assignment])).records, ()
        )
        unrelated = _role_assignment(principal_id="another-principal", scope=_STORAGE_ACCOUNT_ID)
        unrelated.unknown_values = {"condition": True}
        self.assertEqual(
            collect_blob_operation_gaps(_normalize([_storage_account(), _web_app(), unrelated])).records, ()
        )

    def test_current_re_evaluation_removes_or_introduces_condition_gap(self):
        assignment = _role_assignment(scope=_STORAGE_ACCOUNT_ID)
        inventory = _normalize([_storage_account(), _web_app(), assignment])
        self.assertEqual(collect_blob_operation_gaps(inventory).records, ())
        current = inventory.get_by_address(assignment.address)
        assert current is not None
        from tfstride.providers.azure.metadata import AzureResourceMetadata
        from tfstride.providers.azure.resource_facts import azure_facts

        azure_facts(current).set(AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, "SECRET-CURRENT-CONDITION")
        self.assertEqual(
            {gap.reason_code for gap in collect_blob_operation_gaps(inventory).records},
            {"assignment_condition_unresolved"},
        )
        azure_facts(current).set(AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, None)
        self.assertEqual(collect_blob_operation_gaps(inventory).records, ())
