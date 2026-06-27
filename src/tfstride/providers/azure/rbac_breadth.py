from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tfstride.providers.azure.resource_utils import compact_strings

OWNER_LIKE_OR_WILDCARD = "owner_like_or_wildcard"
AUTHORIZATION_MANAGEMENT = "authorization_management"
ROLE_ASSIGNMENT_CAPABLE = "role_assignment_capable"
COMPUTE_MANAGEMENT = "compute_management"
NETWORK_MANAGEMENT = "network_management"
STORAGE_DATA_PLANE = "storage_data_plane"
KEY_VAULT_DATA_PLANE = "key_vault_data_plane"
RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT = "resource_group_subscription_wide_management"
UNKNOWN_CUSTOM_WILDCARD = "unknown_custom_wildcard"

_STORAGE_DATA_PREFIXES = (
    "microsoft.storage/storageaccounts/blobservices",
    "microsoft.storage/storageaccounts/fileservices",
    "microsoft.storage/storageaccounts/queueservices",
    "microsoft.storage/storageaccounts/tableservices",
)
_KEY_VAULT_DATA_PREFIXES = (
    "microsoft.keyvault/vaults/secrets",
    "microsoft.keyvault/vaults/keys",
    "microsoft.keyvault/vaults/certificates",
)
_RESOURCE_SCOPE_PREFIXES = (
    "microsoft.resources/subscriptions",
    "microsoft.resources/subscriptions/resourcegroups",
)


@dataclass(frozen=True, slots=True)
class AzureRbacActionBreadth:
    signals: tuple[str, ...]
    mitigating_actions: tuple[str, ...]
    mitigating_data_actions: tuple[str, ...]

    @property
    def mitigations(self) -> tuple[str, ...]:
        return tuple(
            [
                *[f"not_action={action}" for action in self.mitigating_actions],
                *[f"not_data_action={action}" for action in self.mitigating_data_actions],
            ]
        )


def classify_role_definition_breadth(
    *,
    actions: Iterable[str] = (),
    not_actions: Iterable[str] = (),
    data_actions: Iterable[str] = (),
    not_data_actions: Iterable[str] = (),
) -> AzureRbacActionBreadth:
    signals: list[str] = []
    normalized_actions = compact_strings(actions)
    normalized_data_actions = compact_strings(data_actions)
    for action in normalized_actions:
        _extend_unique(signals, _classify_management_action(action))
    for action in normalized_data_actions:
        _extend_unique(signals, _classify_data_action(action))

    return AzureRbacActionBreadth(
        signals=tuple(signals),
        mitigating_actions=tuple(compact_strings(not_actions)),
        mitigating_data_actions=tuple(compact_strings(not_data_actions)),
    )


def _classify_management_action(action: str) -> tuple[str, ...]:
    normalized = _normalize_action(action)
    signals: list[str] = []
    if normalized == "*":
        signals.append(OWNER_LIKE_OR_WILDCARD)
        return tuple(signals)
    if normalized.startswith("microsoft.authorization/"):
        signals.append(AUTHORIZATION_MANAGEMENT)
        if _is_authorization_role_assignment_capable(normalized):
            signals.append(ROLE_ASSIGNMENT_CAPABLE)
    if normalized.startswith("microsoft.compute/"):
        signals.append(COMPUTE_MANAGEMENT)
    if normalized.startswith("microsoft.network/"):
        signals.append(NETWORK_MANAGEMENT)
    if _starts_with_any(normalized, _RESOURCE_SCOPE_PREFIXES):
        signals.append(RESOURCE_GROUP_SUBSCRIPTION_WIDE_MANAGEMENT)
    if _starts_with_any(normalized, _STORAGE_DATA_PREFIXES):
        signals.append(STORAGE_DATA_PLANE)
    if _starts_with_any(normalized, _KEY_VAULT_DATA_PREFIXES):
        signals.append(KEY_VAULT_DATA_PLANE)
    if "*" in normalized and not signals:
        signals.append(UNKNOWN_CUSTOM_WILDCARD)
    return tuple(signals)


def _classify_data_action(action: str) -> tuple[str, ...]:
    normalized = _normalize_action(action)
    signals: list[str] = []
    if normalized == "*":
        signals.append(OWNER_LIKE_OR_WILDCARD)
        return tuple(signals)
    if _starts_with_any(normalized, _STORAGE_DATA_PREFIXES):
        signals.append(STORAGE_DATA_PLANE)
    if _starts_with_any(normalized, _KEY_VAULT_DATA_PREFIXES):
        signals.append(KEY_VAULT_DATA_PLANE)
    if "*" in normalized and not signals:
        signals.append(UNKNOWN_CUSTOM_WILDCARD)
    return tuple(signals)


def _is_authorization_role_assignment_capable(action: str) -> bool:
    return action == "microsoft.authorization/*" or action.startswith("microsoft.authorization/roleassignments/")


def _normalize_action(action: str) -> str:
    return action.strip().lower()


def _starts_with_any(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def _extend_unique(target: list[str], values: Iterable[str]) -> None:
    seen = set(target)
    for value in values:
        if not value or value in seen:
            continue
        target.append(value)
        seen.add(value)
