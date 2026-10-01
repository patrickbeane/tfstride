from __future__ import annotations

from itertools import permutations

import pytest

from tests.providers.azure.test_azure_app_service_storage_access_paths import (
    _STORAGE_ACCOUNT_ID,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _function_app,
    _role_assignment,
    _storage_account,
    _storage_container,
    _symbolic_resolution,
    _user_assigned_identity,
    _web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import _evaluate, _public
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.providers.azure.blob_operation_authority import evaluate_blob_operation_authority
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.app_service_storage_access_paths import (
    current_app_service_storage_access_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder

_SUBSCRIPTION = "/subscriptions/sub-0001"
_GROUP = f"{_SUBSCRIPTION}/resourceGroups/app"
_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"
_MUTATION = "azure-public-app-service-storage-mutation-access"


def _current(inventory):
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert app is not None
    context = AzureDecorationContext(AzureResourceIndexBuilder().build(inventory.resources))
    return current_app_service_storage_access_paths(app, context)


def _findings(inventory):
    return StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=frozenset({_MUTATION})))


@pytest.mark.parametrize(
    "scope", ["/subscriptions/sub-0001", "/subscriptions/sub-0001/resourceGroups/app", _STORAGE_ACCOUNT_ID]
)
def test_ancestor_blob_grant_reaches_only_the_modeled_target(scope: str) -> None:
    resources = [_storage_account(), _public(_web_app()), _role_assignment(scope=scope)]
    inventory = AzureNormalizer().normalize(resources)
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert app is not None
    paths = azure_facts(app).app_service_storage_access_paths
    assert len(paths) == 1
    assert paths[0]["storage_resource_address"] == "azurerm_storage_account.orders"
    assert paths[0]["assignment_scope"] == scope
    assert len(_evaluate(resources)) == 1


@pytest.mark.parametrize("scope", [_SUBSCRIPTION, _GROUP, _STORAGE_ACCOUNT_ID])
def test_non_descendants_do_not_inherit(scope: str) -> None:
    unrelated = _storage_account()
    unrelated.address = "azurerm_storage_account.other"
    unrelated.name = "other"
    unrelated.values["id"] = _STORAGE_ACCOUNT_ID.replace("sub-0001", "sub-00010")
    inventory = AzureNormalizer().normalize([_storage_account(), unrelated, _web_app(), _role_assignment(scope=scope)])
    paths, _ = _current(inventory)
    assert {path["storage_resource_address"] for path in paths} == {"azurerm_storage_account.orders"}


@pytest.mark.parametrize("scope", [f"{_GROUP}-other", _STORAGE_ACCOUNT_ID + "other", "/subscriptions/other"])
def test_sibling_scope_is_not_containment(scope: str) -> None:
    inventory = AzureNormalizer().normalize([_storage_account(), _public(_web_app()), _role_assignment(scope=scope)])
    assert _current(inventory)[0] == []
    assert _findings(inventory) == []


def test_cross_subscription_identity_can_receive_target_subscription_grant() -> None:
    identity = _user_assigned_identity()
    identity.values["id"] = str(identity.values["id"]).replace("sub-0001", "identity-subscription")
    findings = _evaluate(
        [
            _storage_account(),
            identity,
            _public(_function_app()),
            _role_assignment(principal_id=_USER_PRINCIPAL_ID, scope=_SUBSCRIPTION),
        ]
    )
    assert len(findings) == 1
    assert "azurerm_user_assigned_identity.orders_runtime" in findings[0].affected_resources


@pytest.mark.parametrize("scope", [_SUBSCRIPTION, _GROUP, _STORAGE_ACCOUNT_ID])
def test_account_namespace_does_not_duplicate_container_paths(scope: str) -> None:
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _storage_container(), _web_app(), _role_assignment(scope=scope)]
    )
    paths, _ = _current(inventory)
    assert [path["storage_resource_address"] for path in paths] == ["azurerm_storage_account.orders"]


def test_custom_role_exclusions_do_not_deny_independent_grants() -> None:
    role = _custom_role(data_actions=[_BLOBS + "read", _BLOBS + "write"], not_data_actions=[_BLOBS + "write"])
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            role,
            _custom_role_assignment(scope=_SUBSCRIPTION),
            _role_assignment(scope=_GROUP, name="independent"),
        ]
    )
    paths, _ = _current(inventory)
    assert len(paths) == 2
    custom = next(path for path in paths if path["role_kind"] == "custom")
    assert (_BLOBS + "write").lower() in custom["excluded_data_actions"]
    assert (_BLOBS + "write").lower() not in custom["matched_data_actions"]
    assert custom["access_classes"] == ["read"]
    assert len(_findings(inventory)) == 1


def test_management_actions_cannot_supply_blob_data_actions() -> None:
    role = _custom_role(data_actions=[])
    role.values["permissions"][0]["actions"] = ["*"]
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), role, _custom_role_assignment(scope=_SUBSCRIPTION)]
    )
    assert _current(inventory)[0] == []
    assert _findings(inventory) == []


@pytest.mark.parametrize(
    "assignable,scope,expected",
    [
        (_SUBSCRIPTION, _GROUP, True),
        (_GROUP, _GROUP, True),
        (_GROUP, _STORAGE_ACCOUNT_ID, True),
        (_GROUP, _SUBSCRIPTION, False),
        ("/subscriptions/foreign", _GROUP, False),
    ],
)
def test_custom_role_assignability_applies_to_assignment_scope(assignable: str, scope: str, expected: bool) -> None:
    role = _custom_role(data_actions=[_BLOBS + "write"])
    role.values["assignable_scopes"] = [assignable]
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), role, _custom_role_assignment(scope=scope)]
    )
    paths, uncertainties = _current(inventory)
    assert bool(paths) is expected
    assert bool(_findings(inventory)) is expected
    if not expected:
        assert any("assignable-scope" in value for value in uncertainties)


def test_conditional_alternatives_keep_scope_and_condition_separate() -> None:
    assignment = _role_assignment(scope=_SUBSCRIPTION, condition="container-specific condition")
    assignment.values["condition_version"] = "2.0"
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), assignment, _role_assignment(scope=_GROUP, name="unconditional")]
    )
    paths, _ = _current(inventory)
    assert {(p["assignment_scope"], p["condition"], p["access_state"]) for p in paths} == {
        (_SUBSCRIPTION, "container-specific condition", "conditional"),
        (_GROUP, None, "granted"),
    }
    assert len(_findings(inventory)) == 1
    context = AzureDecorationContext(AzureResourceIndexBuilder().build(inventory.resources))
    result = evaluate_blob_operation_authority(
        inventory.get_by_address("azurerm_role_assignment.orders_blob"),
        inventory.get_by_address("azurerm_storage_account.orders"),
        context,
        principal_id=_SYSTEM_PRINCIPAL_ID,
    )
    assert result.condition_version == "2.0"
    assert result.state == "conditional"


@pytest.mark.parametrize("unknown", [{"condition": True}, {"condition_version": True}, {"role_definition_id": True}])
def test_unknown_assignment_constraints_stay_uncertain(unknown: dict[str, object]) -> None:
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION, unknown_values=unknown)]
    )
    paths, uncertainties = _current(inventory)
    assert paths == []
    assert uncertainties
    assert _findings(inventory) == []


@pytest.mark.parametrize(
    "unknown", [{"assignable_scopes": True}, {"permissions": True}, {"permissions": [{"not_data_actions": True}]}]
)
def test_unknown_custom_role_constraints_stay_uncertain(unknown: dict[str, object]) -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            _custom_role(data_actions=[_BLOBS + "write"], unknown_values=unknown),
            _custom_role_assignment(scope=_SUBSCRIPTION),
        ]
    )
    paths, uncertainties = _current(inventory)
    assert paths == []
    assert uncertainties
    assert _findings(inventory) == []


def test_unknown_role_id_does_not_fall_back_to_builtin_display_name() -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            _role_assignment(scope=_SUBSCRIPTION, role_definition_id="unmodeled-custom-role"),
        ]
    )
    assert _current(inventory)[0] == []
    assert _current(inventory)[1]
    assert _findings(inventory) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("role_assignment_scope", "/subscriptions/other"),
        ("role_assignment_scope", None),
        ("role_assignment_condition", "new constraint"),
        ("role_assignment_condition_version", "2.0"),
        ("principal_id", "another-principal"),
        ("role_definition_id", "unmodeled-role"),
    ],
)
def test_current_authority_does_not_trust_cached_assignment_or_path(field: str, value: object) -> None:
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), _role_assignment(scope=_STORAGE_ACCOUNT_ID)]
    )
    assert len(_findings(inventory)) == 1
    assignment = inventory.get_by_address("azurerm_role_assignment.orders_blob")
    assignment.set_metadata_field(getattr(AzureResourceMetadata, field.upper()), value)
    assert _findings(inventory) == []
    # The old decoration is intentionally retained: it must not be the proof.
    app = inventory.get_by_address("azurerm_linux_web_app.orders")
    assert azure_facts(app).app_service_storage_access_paths


def test_current_custom_data_actions_are_rechecked() -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            _custom_role(data_actions=[_BLOBS + "write"]),
            _custom_role_assignment(scope=_SUBSCRIPTION),
        ]
    )
    assert len(_findings(inventory)) == 1
    role = inventory.get_by_address("azurerm_role_definition.blob_writer")
    role.set_metadata_field(AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS, [_BLOBS + "write"])
    assert _findings(inventory) == []


def test_resource_permutations_preserve_authority_and_findings() -> None:
    baseline = None
    for resources in permutations([_storage_account(), _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION)]):
        inventory = AzureNormalizer().normalize(list(resources))
        result = (_current(inventory), _findings(inventory))
        if baseline is None:
            baseline = result
        assert result == baseline


def test_exact_first_plan_principal_and_custom_role_references_remain_usable() -> None:
    assignment = _role_assignment(
        scope=_SUBSCRIPTION,
        principal_id=None,
        role_name=None,
        role_definition_id=None,
        unknown_values={"principal_id": True, "role_definition_id": True},
    )
    assignment.reference_resolutions = (
        _symbolic_resolution(("principal_id",), "azurerm_linux_web_app.orders.principal_id"),
        _symbolic_resolution(
            ("role_definition_id",), "azurerm_role_definition.blob_writer.role_definition_resource_id"
        ),
    )
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), _custom_role(data_actions=[_BLOBS + "write"]), assignment]
    )
    paths, uncertainties = _current(inventory)
    assert len(paths) == 1
    assert uncertainties == []
    assert len(_findings(inventory)) == 1


@pytest.mark.parametrize("stale_id", [False, True])
def test_unknown_account_id_allows_exact_symbolic_identity_but_not_inferred_ancestry(stale_id: bool) -> None:
    account = _storage_account()
    if not stale_id:
        account.values.pop("id")
    account.unknown_values["id"] = True
    inventory = AzureNormalizer().normalize([account, _public(_web_app()), _role_assignment()])
    assert len(_current(inventory)[0]) == 1
    ancestor_inventory = AzureNormalizer().normalize(
        [account, _public(_web_app()), _role_assignment(scope=_SUBSCRIPTION)]
    )
    paths, uncertainties = _current(ancestor_inventory)
    assert paths == []
    assert uncertainties


def test_unmodeled_management_group_ancestry_is_uncertain() -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            _role_assignment(scope="/providers/Microsoft.Management/managementGroups/root"),
        ]
    )
    paths, uncertainties = _current(inventory)
    assert paths == []
    assert uncertainties
    assert _findings(inventory) == []


def test_conditional_ancestor_grant_alone_does_not_prove_public_mutation() -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_web_app()),
            _role_assignment(scope=_SUBSCRIPTION, condition="container-specific condition"),
        ]
    )
    paths, _ = _current(inventory)
    assert len(paths) == 1
    assert paths[0]["access_state"] == "conditional"
    assert _findings(inventory) == []


def test_removing_current_user_identity_attachment_invalidates_cached_paths() -> None:
    inventory = AzureNormalizer().normalize(
        [
            _storage_account(),
            _public(_function_app()),
            _user_assigned_identity(),
            _role_assignment(scope=_SUBSCRIPTION, principal_id=_USER_PRINCIPAL_ID),
        ]
    )
    assert len(_findings(inventory)) == 1
    app = inventory.get_by_address("azurerm_linux_function_app.orders_worker")
    app.set_metadata_field(AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES, [])
    assert _findings(inventory) == []


def test_changed_scope_is_not_overridden_by_old_symbolic_reference() -> None:
    account = _storage_account()
    account.values.pop("id")
    account.unknown_values["id"] = True
    inventory = AzureNormalizer().normalize([account, _public(_web_app()), _role_assignment()])
    assert len(_findings(inventory)) == 1
    assignment = inventory.get_by_address("azurerm_role_assignment.orders_blob")
    assignment.set_metadata_field(AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE, "/subscriptions/other")
    assert _findings(inventory) == []


def test_changed_role_is_not_overridden_by_old_symbolic_reference() -> None:
    assignment = _role_assignment(
        scope=_SUBSCRIPTION, role_name=None, role_definition_id=None, unknown_values={"role_definition_id": True}
    )
    assignment.reference_resolutions = (
        _symbolic_resolution(
            ("role_definition_id",), "azurerm_role_definition.blob_writer.role_definition_resource_id"
        ),
    )
    inventory = AzureNormalizer().normalize(
        [_storage_account(), _public(_web_app()), _custom_role(data_actions=[_BLOBS + "write"]), assignment]
    )
    assert len(_findings(inventory)) == 1
    normalized_assignment = inventory.get_by_address("azurerm_role_assignment.orders_blob")
    normalized_assignment.set_metadata_field(AzureResourceMetadata.ROLE_DEFINITION_ID, "different-role")
    assert _findings(inventory) == []
