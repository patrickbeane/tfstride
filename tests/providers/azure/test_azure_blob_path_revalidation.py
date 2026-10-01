from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.providers.azure.test_azure_app_service_storage_access_paths import _custom_role
from tests.providers.test_protected_data_key_authority_convergence import _azure_resources
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.app_service_blob_deletion_paths import (
    ModelAppServiceBlobDeletionPathsStage,
)
from tfstride.providers.azure.resource_decoration.app_service_key_vault_protected_data_convergence import (
    ModelAppServiceKeyVaultProtectedDataConvergenceStage,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder

_DECRYPT = "azure-public-app-service-key-vault-decrypt-access"
_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"
_SUBSCRIPTION = "/subscriptions/sub-0001"
_GROUP = _SUBSCRIPTION + "/resourceGroups/app"


def _resources(*, custom_actions=None, scope=_SUBSCRIPTION):
    resources = _azure_resources()
    assignment = next(r for r in resources if r.address == "azurerm_role_assignment.orders_blob")
    assignment.values["scope"] = scope
    assignment.unknown_values.pop("scope", None)
    assignment.reference_resolutions = ()
    if custom_actions is not None:
        role = _custom_role(data_actions=custom_actions)
        resources.append(role)
        assignment.values["role_definition_id"] = role.values["id"]
        assignment.values["role_definition_name"] = None
    return resources


def _finding(inventory):
    findings = StrideRuleEngine().evaluate(
        inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DECRYPT}))
    )
    assert len(findings) == 1  # Independently established key authority must survive.
    return findings[0]


def _has_data_dependency(finding):
    evidence = {item.key: item.values for item in finding.evidence}
    return "unique_dependency_count=1" in evidence["downstream_dependencies"][0]


@pytest.mark.parametrize(
    "field,value",
    [
        (AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE, "/subscriptions/unrelated"),
        (AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, "container restriction"),
        (AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION_VERSION, "2.0"),
        (AzureResourceMetadata.ROLE_DEFINITION_ID, "unmodeled-role"),
        (AzureResourceMetadata.PRINCIPAL_ID, "another-principal"),
    ],
)
def test_read_convergence_revalidates_current_assignment(field, value):
    inventory = AzureNormalizer().normalize(_resources())
    assert _has_data_dependency(_finding(inventory))
    assignment = inventory.get_by_address("azurerm_role_assignment.orders_blob")
    assignment.set_metadata_field(field, value)
    assert not _has_data_dependency(_finding(inventory))
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert azure_facts(app).app_service_storage_protected_data_convergences


@pytest.mark.parametrize("action", ["tags/read", "filter/action", "write", "add/action", "delete"])
def test_only_payload_read_can_support_plaintext_data_convergence(action):
    inventory = AzureNormalizer().normalize(_resources(custom_actions=[_BLOBS + action]))
    assert not _has_data_dependency(_finding(inventory))


@pytest.mark.parametrize("scope", [_SUBSCRIPTION, _GROUP])
@pytest.mark.parametrize("custom", [False, True])
def test_ancestor_payload_read_remains_usable(scope, custom):
    inventory = AzureNormalizer().normalize(
        _resources(scope=scope, custom_actions=[_BLOBS + "read"] if custom else None)
    )
    assert _has_data_dependency(_finding(inventory))


@pytest.mark.parametrize(
    "field,value",
    [
        (AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS, [_BLOBS + "read"]),
        (AzureResourceMetadata.ROLE_DEFINITION_ASSIGNABLE_SCOPES, [_GROUP]),
        (
            AzureResourceMetadata.ROLE_DEFINITION_UNCERTAINTIES,
            ["permissions[0].not_data_actions is unknown after planning"],
        ),
    ],
)
def test_read_convergence_rechecks_custom_role_constraints(field, value):
    inventory = AzureNormalizer().normalize(_resources(custom_actions=[_BLOBS + "read"]))
    assert _has_data_dependency(_finding(inventory))
    role = inventory.get_by_address("azurerm_role_definition.blob_writer")
    role.set_metadata_field(field, value)
    finding = _finding(inventory)
    assert not _has_data_dependency(finding)
    if field == AzureResourceMetadata.ROLE_DEFINITION_UNCERTAINTIES:
        evidence = {item.key: item.values for item in finding.evidence}
        assert any("data actions are unresolved" in value for value in evidence["downstream_dependency_uncertainties"])


def test_deleting_read_caches_does_not_erase_current_authority():
    inventory = AzureNormalizer().normalize(_resources())
    expected = _finding(inventory)
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    facts = azure_facts(app)
    facts.set_app_service_storage_access_paths([])
    facts.set_app_service_storage_protected_data_convergences([])
    assert _finding(inventory) == expected


def test_restore_read_authority_recreates_convergence_without_redecoration():
    inventory = AzureNormalizer().normalize(_resources(custom_actions=[_BLOBS + "tags/read"]))
    assert not _has_data_dependency(_finding(inventory))
    role = inventory.get_by_address("azurerm_role_definition.blob_writer")
    role.set_metadata_field(AzureResourceMetadata.ROLE_DEFINITION_DATA_ACTIONS, [_BLOBS + "read"])
    assert _has_data_dependency(_finding(inventory))
    role.set_metadata_field(AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS, [_BLOBS + "read"])
    assert not _has_data_dependency(_finding(inventory))


@pytest.mark.parametrize("blocked", [False, True])
def test_convergence_stage_uses_current_authority_without_cached_access_paths(blocked):
    inventory = AzureNormalizer().normalize(_resources())
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    facts = azure_facts(app)
    facts.set_app_service_storage_access_paths([])
    if blocked:
        inventory.get_by_address("azurerm_role_assignment.orders_blob").set_metadata_field(
            AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, "unresolved restriction"
        )
    resources = list(inventory.resources)
    ModelAppServiceKeyVaultProtectedDataConvergenceStage().apply(
        resources, AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
    )
    assert bool(facts.app_service_storage_protected_data_convergences) is not blocked


@pytest.mark.parametrize("blocked", [False, True])
def test_deletion_stage_uses_current_authority_without_cached_access_paths(blocked):
    from tests.providers.azure.test_azure_public_app_service_blob_rules import (
        _public,
        _role_assignment,
        _storage_account,
        _storage_container,
        _web_app,
    )

    inventory = AzureNormalizer().normalize(
        [_storage_account(), _storage_container(), _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION)]
    )
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    facts = azure_facts(app)
    assert facts.app_service_blob_deletion_paths
    facts.set_app_service_storage_access_paths([])
    app.set_metadata_field(AzureResourceMetadata.MANAGED_IDENTITY_ROLE_ASSIGNMENTS, [])
    if blocked:
        inventory.get_by_address("azurerm_role_assignment.orders_blob").set_metadata_field(
            AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION_VERSION, "2.0"
        )
    resources = list(inventory.resources)
    ModelAppServiceBlobDeletionPathsStage().apply(
        resources, AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
    )
    assert bool(facts.app_service_blob_deletion_paths) is not blocked
    if blocked:
        assert any("condition is unresolved" in value for value in facts.app_service_blob_deletion_path_uncertainties)


def test_write_and_tag_read_does_not_claim_payload_read_in_mutation_finding():
    inventory = AzureNormalizer().normalize(_resources(custom_actions=[_BLOBS + "write", _BLOBS + "tags/read"]))
    rule = "azure-public-app-service-storage-mutation-access"
    findings = StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset({rule})))
    assert len(findings) == 1
    assert "does not establish read access or information disclosure" in findings[0].rationale


def test_resource_order_preserves_current_convergence():
    resources = _resources(custom_actions=[_BLOBS + "read"])
    expected = _finding(AzureNormalizer().normalize(resources))
    for offset in range(len(resources)):
        ordered = resources[offset:] + resources[:offset]
        assert _finding(AzureNormalizer().normalize(list(reversed(ordered)))) == expected


@pytest.mark.parametrize("unknown", [False, True])
def test_plan_ingestion_rechecks_inherited_read_constraints(tmp_path: Path, unknown):
    resources = _resources(custom_actions=[_BLOBS + "read"])
    payload = {
        "terraform_version": "1.9.0",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": r.address,
                        "type": r.resource_type,
                        "name": r.name,
                        "mode": "managed",
                        "provider_name": "registry.terraform.io/hashicorp/azurerm",
                        "values": r.values,
                    }
                    for r in resources
                ]
            }
        },
        "resource_changes": [
            {
                "address": "azurerm_role_definition.blob_writer",
                "change": {
                    "actions": ["create"],
                    "after_unknown": {"permissions": [{"not_data_actions": True}]} if unknown else {},
                },
            }
        ],
    }
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(payload))
    result = TfStride(provider="azure", rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DECRYPT}))).analyze_plan(
        plan
    )
    assert len(result.findings) == 1
    assert _has_data_dependency(result.findings[0]) is not unknown
