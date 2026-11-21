"""Characterize Azure Key Vault operation findings and their reevaluation.

Two things are pinned here. First, the exact decrypt and signing findings a fresh
normalization produces for each way an App Service identity can be granted Key Vault
key operations (RBAC at key, vault, resource-group and subscription scope, access
policies, custom roles, and system- and user-assigned identities), so a change to how
those paths are validated must preserve valid findings, evidence, and ordering.
Second, what happens when authorization resources change while the previously
decorated paths are retained: a fresh normalization drops the finding, and
reevaluation should too. Cases where reevaluation still reports the old finding are
marked as expected failures until the operation rules revalidate current authorization.

Regenerate the recorded findings only for a deliberate behavior change:

    python -m tests.providers.azure.test_azure_key_vault_operation_reevaluation --write
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tests.helpers.inventory import inventory_with_resources
from tests.providers.azure.test_azure_app_service_key_vault_operation_paths import (
    _CUSTOM_ROLE_ID,
    _RESOURCE_GROUP_SCOPE,
    _SERVICE_ENCRYPTION_USER_ID,
    _SUBSCRIPTION_SCOPE,
    _SYSTEM_PRINCIPAL_ID,
    _USER_PRINCIPAL_ID,
    _access_policy,
    _custom_role_assignment,
    _function_app,
    _key,
    _resource,
    _role_assignment,
    _user_assigned_identity,
    _vault,
    _web_app,
)
from tests.providers.azure.test_azure_public_app_service_storage_mutation_rules import _public
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType

SNAPSHOT_PATH = Path(__file__).resolve().parents[2] / "golden" / "azure_key_vault_operation_findings_snapshot.json"
_DECRYPT_RULE = "azure-public-app-service-key-vault-decrypt-access"
_SIGN_RULE = "azure-public-app-service-key-vault-signing-access"
_RULES = frozenset({_DECRYPT_RULE, _SIGN_RULE})
_KEY_SCOPE = "azurerm_key_vault_key.signing.resource_versionless_id"
_VAULT_SCOPE = "azurerm_key_vault.orders.id"
_CHANGED_PRINCIPAL = "00000000-0000-0000-0000-00000000dead"
_CONDITION = "@Resource[Microsoft.KeyVault/vaults/keys:name] StringEquals 'other'"


def _custom_role(data_actions: list[str]) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        "key_operator",
        {
            "id": _CUSTOM_ROLE_ID,
            "name": "Custom Key Operator",
            "scope": _SUBSCRIPTION_SCOPE,
            "assignable_scopes": [_SUBSCRIPTION_SCOPE],
            "permissions": [
                {"actions": [], "not_actions": [], "data_actions": data_actions, "not_data_actions": []},
            ],
        },
    )


_CUSTOM_KEY_ACTIONS = [
    "Microsoft.KeyVault/vaults/keys/decrypt/action",
    "Microsoft.KeyVault/vaults/keys/unwrap/action",
    "Microsoft.KeyVault/vaults/keys/sign/action",
]


def _second_key() -> TerraformResource:
    second = _key(key_opts=("decrypt", "sign"))
    second.address = "azurerm_key_vault_key.secondary"
    second.name = "secondary"
    second.values["name"] = "secondary"
    second.values["versionless_id"] = str(second.values["versionless_id"]).replace("signing", "secondary")
    second.values["resource_versionless_id"] = str(second.values["resource_versionless_id"]).replace(
        "signing", "secondary"
    )
    second.values.pop("id", None)
    second.values.pop("resource_id", None)
    second.values.pop("version", None)
    return second


def _base(rbac: bool, *authorization: TerraformResource, workload: TerraformResource | None = None):
    return [_vault(rbac_enabled=rbac), _key(), _public(workload or _web_app()), *authorization]


# Valid scenarios: (name, resources). Each is evaluated after a fresh normalization.
_VALID_SCENARIOS: dict[str, Callable[[], list[TerraformResource]]] = {
    "rbac vault scope": lambda: _base(True, _role_assignment()),
    "rbac exact key scope": lambda: _base(True, _role_assignment(scope=_KEY_SCOPE)),
    "rbac resource group scope": lambda: _base(True, _role_assignment(scope=_RESOURCE_GROUP_SCOPE)),
    "rbac subscription scope": lambda: _base(True, _role_assignment(scope=_SUBSCRIPTION_SCOPE)),
    "rbac subscription scope two keys": lambda: [
        *_base(True, _role_assignment(scope=_SUBSCRIPTION_SCOPE)),
        _second_key(),
    ],
    "rbac unwrap-only role": lambda: _base(
        True,
        _role_assignment(role_id=_SERVICE_ENCRYPTION_USER_ID, role_name="Key Vault Crypto Service Encryption User"),
    ),
    "rbac custom role": lambda: _base(
        True,
        _custom_role(_CUSTOM_KEY_ACTIONS),
        _custom_role_assignment(),
    ),
    "rbac user-assigned identity": lambda: [
        _vault(rbac_enabled=True),
        _key(),
        _user_assigned_identity(),
        _public(_function_app()),
        _role_assignment(principal_id=_USER_PRINCIPAL_ID),
    ],
    "access policy system identity": lambda: _base(False, _access_policy(principal_id=_SYSTEM_PRINCIPAL_ID)),
    "access policy user-assigned identity": lambda: [
        _vault(),
        _key(),
        _user_assigned_identity(),
        _public(_function_app()),
        _access_policy(principal_id=_USER_PRINCIPAL_ID),
    ],
    "access policy decrypt only": lambda: _base(
        False,
        _access_policy(principal_id=_SYSTEM_PRINCIPAL_ID, key_permissions=("Decrypt",)),
    ),
}


def _evaluate(inventory: ResourceInventory) -> list[Finding]:
    return StrideRuleEngine().evaluate(inventory, [], rule_policy=RulePolicy(enabled_rule_ids=_RULES))


def _digest(values: list[str]) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode("utf-8")).hexdigest()


def _finding_record(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "affected_resources": list(finding.affected_resources),
        "rationale": finding.rationale,
        "evidence": [
            {"key": item.key, "count": len(item.values), "sha256": _digest(list(item.values))}
            for item in finding.evidence
        ],
    }


def build_snapshot() -> dict[str, Any]:
    return {
        name: [_finding_record(finding) for finding in _evaluate(AzureNormalizer().normalize(build()))]
        for name, build in _VALID_SCENARIOS.items()
    }


def _retained_path_findings(
    base: list[TerraformResource],
    changed: list[TerraformResource],
    swapped_addresses: tuple[str, ...],
) -> tuple[int, int, int]:
    """Return findings for the base plan, the retained-path reevaluation, and a fresh changed plan."""

    original = AzureNormalizer().normalize(base)
    fresh = AzureNormalizer().normalize(changed)
    replacements = {address: fresh.get_by_address(address) for address in swapped_addresses}
    mixed = inventory_with_resources(
        original,
        (replacements.get(resource.address) or resource for resource in original.resources),
    )
    return len(_evaluate(original)), len(_evaluate(mixed)), len(_evaluate(fresh))


class AzureKeyVaultOperationFindingsSnapshotTests(unittest.TestCase):
    def test_valid_scenarios_produce_findings(self) -> None:
        snapshot = build_snapshot()
        for name, findings in snapshot.items():
            with self.subTest(scenario=name):
                self.assertTrue(findings, name)
        self.assertEqual({finding["rule_id"] for finding in snapshot["rbac vault scope"]}, _RULES)
        self.assertEqual(
            {finding["rule_id"] for finding in snapshot["access policy decrypt only"]},
            {_DECRYPT_RULE},
        )

    def test_findings_match_the_recorded_snapshot(self) -> None:
        recorded = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(build_snapshot(), recorded)


class AzureKeyVaultOperationReevaluationTests(unittest.TestCase):
    # The operation rules currently trust the authorization evidence stored on each path, so
    # every changed-authorization case below still reports the old findings on reevaluation.
    # The rejection tests are expected failures until the rules revalidate current authorization.

    def assert_reevaluation_matches_fresh_normalization(
        self,
        base: list[TerraformResource],
        changed: list[TerraformResource],
        *swapped_addresses: str,
    ) -> None:
        original, retained, fresh = _retained_path_findings(base, changed, swapped_addresses)
        self.assertGreater(original, 0)
        self.assertEqual(retained, fresh)

    def test_unchanged_authorization_keeps_findings_on_reevaluation(self) -> None:
        for name, build in _VALID_SCENARIOS.items():
            with self.subTest(scenario=name):
                original = AzureNormalizer().normalize(build())
                rebuilt = inventory_with_resources(original, original.resources)
                self.assertEqual(
                    [_finding_record(finding) for finding in _evaluate(rebuilt)],
                    [_finding_record(finding) for finding in _evaluate(original)],
                )

    @unittest.expectedFailure
    def test_changed_role_assignment_principal_is_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _role_assignment()),
            _base(True, _role_assignment(principal_id=_CHANGED_PRINCIPAL)),
            "azurerm_role_assignment.key_access",
        )

    @unittest.expectedFailure
    def test_added_role_assignment_condition_is_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _role_assignment()),
            _base(True, _role_assignment(condition=_CONDITION)),
            "azurerm_role_assignment.key_access",
        )

    @unittest.expectedFailure
    def test_removed_access_policy_permissions_are_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(False, _access_policy(principal_id=_SYSTEM_PRINCIPAL_ID)),
            _base(False, _access_policy(principal_id=_SYSTEM_PRINCIPAL_ID, key_permissions=("Get",))),
            "azurerm_key_vault_access_policy.runtime",
        )

    @unittest.expectedFailure
    def test_changed_custom_role_permissions_are_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _custom_role(_CUSTOM_KEY_ACTIONS), _custom_role_assignment()),
            _base(
                True,
                _custom_role(["Microsoft.KeyVault/vaults/keys/read"]),
                _custom_role_assignment(),
            ),
            "azurerm_role_definition.key_operator",
        )

    @unittest.expectedFailure
    def test_changed_assignment_scope_is_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _role_assignment()),
            _base(True, _role_assignment(scope="/subscriptions/other-subscription")),
            "azurerm_role_assignment.key_access",
        )

    @unittest.expectedFailure
    def test_changed_role_definition_to_a_non_crypto_role_is_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _role_assignment()),
            _base(
                True,
                _role_assignment(role_id="4633458b-17de-408a-b874-0445c86b69e6", role_name="Key Vault Secrets User"),
            ),
            "azurerm_role_assignment.key_access",
        )

    @unittest.expectedFailure
    def test_switching_the_vault_authorization_model_is_rejected(self) -> None:
        self.assert_reevaluation_matches_fresh_normalization(
            _base(True, _role_assignment()),
            _base(False, _role_assignment()),
            "azurerm_key_vault.orders",
        )


if __name__ == "__main__":
    if "--write" in sys.argv:
        SNAPSHOT_PATH.write_text(json.dumps(build_snapshot(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {SNAPSHOT_PATH}")
    else:
        unittest.main()
