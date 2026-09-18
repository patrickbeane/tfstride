from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureResourceIndexBuilder,
    AzureResourceReferenceView,
)
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, compact_strings
from tfstride.providers.coercion import dedupe_strings

_AZURE_DIAGNOSTIC_SETTING = AzureResourceType.MONITOR_DIAGNOSTIC_SETTING
_TARGET_ID_FACT_NAMES = (
    "storage_account_id",
    "key_vault_id",
    "app_service_id",
    "aks_cluster_id",
    "mssql_server_id",
    "mssql_database_id",
    "postgresql_server_id",
    "load_balancer_id",
    "application_gateway_id",
    "private_endpoint_id",
    "private_dns_zone_id",
    "private_dns_zone_virtual_network_link_id",
)


@dataclass(frozen=True, slots=True)
class AzureDiagnosticSettingTarget:
    diagnostic_setting_address: str
    target_resource_id: str
    enabled_log_categories: tuple[str, ...]
    enabled_log_category_groups: tuple[str, ...]
    metric_categories: tuple[str, ...]
    destinations: tuple[str, ...]
    uncertainties: tuple[str, ...] = ()
    log_records: tuple[Mapping[str, Any], ...] = ()
    metric_records: tuple[Mapping[str, Any], ...] = ()
    log_analytics_workspace_id: str | None = None
    storage_account_id: str | None = None
    eventhub_authorization_rule_id: str | None = None
    eventhub_name: str | None = None
    marketplace_partner_resource_id: str | None = None
    target_resource_address: str | None = None


@dataclass(frozen=True, slots=True)
class AzureUnresolvedDiagnosticSettingTarget:
    diagnostic_setting_address: str
    target_resource_id: str | None
    destinations: tuple[str, ...]
    enabled_log_categories: tuple[str, ...]
    enabled_log_category_groups: tuple[str, ...]
    metric_categories: tuple[str, ...]
    uncertainties: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AzureDiagnosticSettingCoverage:
    settings: tuple[AzureDiagnosticSettingTarget, ...]

    @property
    def has_diagnostic_settings(self) -> bool:
        return bool(self.settings)

    @property
    def diagnostic_setting_addresses(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(setting.diagnostic_setting_address for setting in self.settings))

    @property
    def enabled_log_categories(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(category for setting in self.settings for category in setting.enabled_log_categories)
        )

    @property
    def enabled_log_category_groups(self) -> tuple[str, ...]:
        return tuple(
            dedupe_strings(group for setting in self.settings for group in setting.enabled_log_category_groups)
        )

    @property
    def metric_categories(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(category for setting in self.settings for category in setting.metric_categories))

    @property
    def destinations(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(destination for setting in self.settings for destination in setting.destinations))

    @property
    def uncertainties(self) -> tuple[str, ...]:
        return tuple(dedupe_strings(uncertainty for setting in self.settings for uncertainty in setting.uncertainties))


@dataclass(frozen=True, slots=True)
class AzureDiagnosticSettingIndex:
    settings_by_target_key: Mapping[str, tuple[AzureDiagnosticSettingTarget, ...]]
    unresolved_targets: tuple[AzureUnresolvedDiagnosticSettingTarget, ...]

    def coverage_for(self, resource: NormalizedResource) -> AzureDiagnosticSettingCoverage:
        settings: list[AzureDiagnosticSettingTarget] = []
        seen: set[tuple[str, str]] = set()
        for target_key in _target_resource_keys(resource):
            for setting in self.settings_by_target_key.get(target_key, ()):
                if setting.target_resource_address != resource.address:
                    continue
                dedupe_key = (setting.diagnostic_setting_address, setting.target_resource_id)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                settings.append(setting)
        return AzureDiagnosticSettingCoverage(tuple(settings))


def build_azure_diagnostic_setting_index(
    source: ResourceInventory | Iterable[NormalizedResource],
) -> AzureDiagnosticSettingIndex:
    resources = tuple(source.resources if isinstance(source, ResourceInventory) else source)
    resource_references = AzureResourceIndexBuilder().build(list(resources)).resources_by_reference
    target_resource_types = frozenset(
        resource.resource_type for resource in resources if resource.resource_type != _AZURE_DIAGNOSTIC_SETTING
    )
    pending_settings_by_key: dict[str, list[AzureDiagnosticSettingTarget]] = {}
    unresolved_targets: list[AzureUnresolvedDiagnosticSettingTarget] = []

    for resource in resources:
        if resource.resource_type != _AZURE_DIAGNOSTIC_SETTING:
            continue
        setting = _diagnostic_setting_target(resource)
        if setting is None:
            unresolved_targets.append(_unresolved_diagnostic_setting_target(resource, target_resource_id=None))
            continue
        target = _resolve_diagnostic_target(
            resource,
            setting.target_resource_id,
            resource_references,
            target_resource_types,
        )
        if target is not None:
            target_key = _primary_target_resource_key(target)
            resolved_setting = replace(
                setting,
                target_resource_address=target.address,
            )
            pending_settings_by_key.setdefault(target_key, []).append(resolved_setting)
            continue
        unresolved_targets.append(_unresolved_diagnostic_setting_target(resource, setting.target_resource_id))

    return AzureDiagnosticSettingIndex(
        settings_by_target_key=MappingProxyType(
            {key: tuple(value) for key, value in sorted(pending_settings_by_key.items())}
        ),
        unresolved_targets=tuple(unresolved_targets),
    )


def _resolve_diagnostic_target(
    diagnostic_setting: NormalizedResource,
    reference: str,
    resource_references: AzureResourceReferenceView,
    target_resource_types: frozenset[str],
) -> NormalizedResource | None:
    reference_key = azure_reference_key(reference)
    resolution = resource_references.resolve(
        reference,
        source=diagnostic_setting,
        resource_types=target_resource_types,
    )
    candidates = tuple(
        candidate for candidate in resolution.candidates if reference_key in _target_resource_keys(candidate)
    )
    return candidates[0] if len(candidates) == 1 else None


def _primary_target_resource_key(resource: NormalizedResource) -> str:
    for value in _resource_id_values(resource, include_terraform_reference=False):
        return azure_reference_key(value)
    return azure_reference_key(f"{resource.address}.id")


def _target_resource_keys(resource: NormalizedResource) -> tuple[str, ...]:
    values = [f"{resource.address}.id", *_resource_id_values(resource)]
    return tuple(azure_reference_key(value) for value in compact_strings(values))


def _resource_id_values(resource: NormalizedResource, *, include_terraform_reference: bool = True) -> tuple[str, ...]:
    facts = azure_facts(resource)
    values: list[str | None] = []
    if include_terraform_reference:
        values.append(f"{resource.address}.id")
    if _looks_like_azure_resource_id(resource.identifier):
        values.append(resource.identifier)
    for name in _TARGET_ID_FACT_NAMES:
        value = getattr(facts, name, None)
        if _looks_like_target_id(value):
            values.append(value)
    return tuple(compact_strings(values))


def _diagnostic_setting_target(resource: NormalizedResource) -> AzureDiagnosticSettingTarget | None:
    facts = azure_facts(resource)
    target_resource_id = facts.diagnostic_target_resource_id
    if not target_resource_id:
        return None
    return AzureDiagnosticSettingTarget(
        diagnostic_setting_address=resource.address,
        target_resource_id=target_resource_id,
        enabled_log_categories=tuple(facts.diagnostic_enabled_log_categories),
        enabled_log_category_groups=tuple(facts.diagnostic_enabled_log_category_groups),
        metric_categories=tuple(facts.diagnostic_metric_categories),
        destinations=_diagnostic_destinations(facts),
        uncertainties=tuple(facts.azure_security_posture_uncertainties),
        log_records=tuple(_immutable_record(record) for record in facts.diagnostic_log_records),
        metric_records=tuple(_immutable_record(record) for record in facts.diagnostic_metric_records),
        log_analytics_workspace_id=facts.diagnostic_log_analytics_workspace_id,
        storage_account_id=facts.diagnostic_storage_account_id,
        eventhub_authorization_rule_id=facts.diagnostic_eventhub_authorization_rule_id,
        eventhub_name=facts.diagnostic_eventhub_name,
        marketplace_partner_resource_id=facts.diagnostic_marketplace_partner_resource_id,
    )


def _unresolved_diagnostic_setting_target(
    resource: NormalizedResource,
    target_resource_id: str | None,
) -> AzureUnresolvedDiagnosticSettingTarget:
    facts = azure_facts(resource)
    return AzureUnresolvedDiagnosticSettingTarget(
        diagnostic_setting_address=resource.address,
        target_resource_id=target_resource_id,
        destinations=_diagnostic_destinations(facts),
        enabled_log_categories=tuple(facts.diagnostic_enabled_log_categories),
        enabled_log_category_groups=tuple(facts.diagnostic_enabled_log_category_groups),
        metric_categories=tuple(facts.diagnostic_metric_categories),
        uncertainties=tuple(facts.azure_security_posture_uncertainties),
    )


def _diagnostic_destinations(facts: Any) -> tuple[str, ...]:
    destinations = []
    if facts.diagnostic_log_analytics_workspace_id:
        destinations.append(f"log_analytics_workspace_id={facts.diagnostic_log_analytics_workspace_id}")
    if facts.diagnostic_storage_account_id:
        destinations.append(f"storage_account_id={facts.diagnostic_storage_account_id}")
    if facts.diagnostic_eventhub_authorization_rule_id:
        destinations.append(f"eventhub_authorization_rule_id={facts.diagnostic_eventhub_authorization_rule_id}")
    if facts.diagnostic_eventhub_name:
        destinations.append(f"eventhub_name={facts.diagnostic_eventhub_name}")
    if facts.diagnostic_marketplace_partner_resource_id:
        destinations.append(f"marketplace_partner_resource_id={facts.diagnostic_marketplace_partner_resource_id}")
    return tuple(destinations)


def _immutable_record(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(record))


def _looks_like_target_id(value: object) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return _looks_like_azure_resource_id(text) or _looks_like_terraform_id_reference(text)


def _looks_like_azure_resource_id(value: object) -> bool:
    if value is None:
        return False
    return str(value).strip().startswith("/")


def _looks_like_terraform_id_reference(value: object) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    return text.lower().endswith(".id")
