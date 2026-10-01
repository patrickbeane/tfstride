from __future__ import annotations

import json
from itertools import permutations
from pathlib import Path

import pytest

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _function_app,
    _role_assignment,
    _user_assigned_identity,
    _web_app,
)
from tests.providers.azure.test_azure_public_app_service_blob_rules import (
    _DELETE,
    _DELETE_VERSION,
    _RULE_ID,
    _evaluate,
    _evidence,
    _public,
    _storage_account,
    _storage_container,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts import azure_facts

_SUBSCRIPTION = "/subscriptions/sub-0001"
_GROUP = f"{_SUBSCRIPTION}/resourceGroups/app"


def _reevaluate(inventory):
    return StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})))


def _custom_resources(scope=_SUBSCRIPTION, **kwargs):
    return [
        _storage_account(),
        _storage_container(),
        _public(_web_app()),
        _custom_role(**kwargs),
        _custom_role_assignment(scope=scope),
    ]


@pytest.mark.parametrize("scope", [_SUBSCRIPTION, _GROUP, _STORAGE_ACCOUNT_ID])
@pytest.mark.parametrize("custom", [False, True])
def test_inherited_blob_delete_authority_reaches_the_container(scope: str, custom: bool) -> None:
    resources = [_storage_account(), _storage_container(), _public(_web_app())]
    if custom:
        resources.extend([_custom_role(data_actions=[_DELETE]), _custom_role_assignment(scope=scope)])
    else:
        resources.append(_role_assignment(scope=scope))
    _, findings = _evaluate(resources)
    assert [finding.rule_id for finding in findings] == [_RULE_ID]
    evidence = _evidence(findings[0])
    assert any(f"assignment_scope={scope}" in value for value in evidence["authorization_scope"])
    assert any(f"operation={_DELETE}" in value for value in evidence["storage_blob_deletion_paths"])
    assert not any(f"operation={_DELETE_VERSION}" in value for value in evidence["storage_blob_deletion_paths"])
    assert "permanent_loss_established=true" not in " ".join(evidence["recovery_posture"])


@pytest.mark.parametrize("scope", ["/subscriptions/sub-00010", _GROUP + "-other", _STORAGE_ACCOUNT_ID + "other"])
def test_inherited_grants_do_not_cover_unrelated_descendants(scope: str) -> None:
    _, findings = _evaluate(_custom_resources(scope, data_actions=[_DELETE]))
    assert findings == []


@pytest.mark.parametrize(
    "action",
    [
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
        "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    ],
)
def test_other_operations_do_not_become_blob_deletion(action: str) -> None:
    _, findings = _evaluate(_custom_resources(data_actions=[action]))
    assert findings == []


def test_management_action_is_not_a_blob_data_action() -> None:
    resources = _custom_resources(data_actions=[])
    resources[-2].values["permissions"][0]["actions"] = ["*"]
    _, findings = _evaluate(resources)
    assert findings == []


def test_not_data_actions_exclusions_are_local_to_their_grant() -> None:
    resources = _custom_resources(data_actions=[_DELETE], not_data_actions=[_DELETE])
    _, excluded = _evaluate(resources)
    assert excluded == []
    resources.append(_role_assignment(scope=_GROUP, name="independent"))
    _, findings = _evaluate(resources)
    assert len(findings) == 1
    assert "azurerm_role_assignment.independent" in findings[0].affected_resources
    assert "azurerm_role_assignment.orders_blob" not in findings[0].affected_resources


def test_custom_role_must_be_assignable_at_the_grant_scope() -> None:
    resources = _custom_resources(data_actions=[_DELETE])
    resources[-2].values["assignable_scopes"] = [_GROUP]
    inventory, findings = _evaluate(resources)
    assert findings == []
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert any("assignable-scope" in value for value in azure_facts(app).app_service_storage_access_path_uncertainties)


def test_cross_subscription_runtime_identity_can_receive_an_explicit_grant() -> None:
    identity = _user_assigned_identity()
    identity.values["id"] = str(identity.values["id"]).replace("sub-0001", "identity-subscription")
    _, findings = _evaluate(
        [
            _storage_account(),
            _storage_container(),
            identity,
            _public(_function_app()),
            _role_assignment(scope=_SUBSCRIPTION, principal_id=_USER_PRINCIPAL_ID),
        ]
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        (AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION, "container name restriction"),
        (AzureResourceMetadata.ROLE_ASSIGNMENT_CONDITION_VERSION, "2.0"),
        (AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE, "/subscriptions/unrelated"),
        (AzureResourceMetadata.ROLE_DEFINITION_ID, "unmodeled-role"),
        (AzureResourceMetadata.PRINCIPAL_ID, "unrelated-principal"),
    ],
)
def test_cached_deletion_path_cannot_override_changed_assignment(field, value) -> None:
    inventory, findings = _evaluate(_custom_resources(data_actions=[_DELETE]))
    assert len(findings) == 1
    inventory.get_by_address("azurerm_role_assignment.orders_blob").set_metadata_field(field, value)
    assert _reevaluate(inventory) == []
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert azure_facts(app).app_service_blob_deletion_paths  # Old evidence is intentionally still present.


@pytest.mark.parametrize(
    "field,value",
    [
        (AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS, [_DELETE]),
        (AzureResourceMetadata.ROLE_DEFINITION_ASSIGNABLE_SCOPES, [_GROUP]),
        (
            AzureResourceMetadata.ROLE_DEFINITION_UNCERTAINTIES,
            ["permissions[0].not_data_actions is unknown after planning"],
        ),
    ],
)
def test_current_custom_role_constraints_are_rechecked(field, value) -> None:
    inventory, findings = _evaluate(_custom_resources(data_actions=[_DELETE]))
    assert len(findings) == 1
    inventory.get_by_address("azurerm_role_definition.blob_writer").set_metadata_field(field, value)
    assert _reevaluate(inventory) == []


@pytest.mark.parametrize("unknown", [{"condition": True}, {"condition_version": True}])
def test_unresolved_assignment_constraint_does_not_establish_deletion(unknown) -> None:
    inventory, findings = _evaluate(
        [
            _storage_account(),
            _storage_container(),
            _public(_web_app()),
            _role_assignment(scope=_SUBSCRIPTION, unknown_values=unknown),
        ]
    )
    assert findings == []
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert azure_facts(app).app_service_storage_access_path_uncertainties


def test_conditional_alternative_does_not_broaden_an_independent_grant() -> None:
    _, findings = _evaluate(
        [
            _storage_account(),
            _storage_container(),
            _public(_web_app()),
            _role_assignment(scope=_SUBSCRIPTION, condition="container name restriction"),
            _role_assignment(scope=_GROUP, name="unconditional"),
        ]
    )
    assert len(findings) == 1
    assert "azurerm_role_assignment.orders_blob" not in findings[0].affected_resources
    assert "azurerm_role_assignment.unconditional" in findings[0].affected_resources


@pytest.mark.parametrize("hns,expected", [(False, True), (True, False)])
def test_inherited_version_delete_keeps_lifecycle_prerequisites(hns: bool, expected: bool) -> None:
    resources = _custom_resources(data_actions=[_DELETE_VERSION])
    resources[0] = _storage_account(hns_enabled=hns)
    _, findings = _evaluate(resources)
    assert bool(findings) is expected
    if findings:
        paths = _evidence(findings[0])["storage_blob_deletion_paths"]
        assert all(f"operation={_DELETE_VERSION}" in value for value in paths)


def test_resource_order_does_not_change_inherited_blob_authority() -> None:
    resources = [_storage_account(), _storage_container(), _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION)]
    _, expected = _evaluate(resources)
    for ordering in permutations(resources):
        _, findings = _evaluate(list(ordering))
        assert findings == expected


@pytest.mark.parametrize("condition_unknown", [False, True])
def test_plan_ingestion_preserves_ancestor_grant_and_unknown_constraint(
    tmp_path: Path, condition_unknown: bool
) -> None:
    resources = [_storage_account(), _storage_container(), _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION)]
    resources[1].values["storage_account_id"] = _STORAGE_ACCOUNT_ID
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
                "address": resources[-1].address,
                "change": {
                    "actions": ["create"],
                    "after_unknown": {"condition": True} if condition_unknown else {},
                },
            }
        ],
    }
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(payload))
    result = TfStride(provider="azure", rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID}))).analyze_plan(
        plan
    )
    assert bool(result.findings) is not condition_unknown
