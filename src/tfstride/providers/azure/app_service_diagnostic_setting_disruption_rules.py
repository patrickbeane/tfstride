from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.app_service_ingress_helpers import app_service_ingress
from tfstride.providers.azure.audit_telemetry_disruption_evidence import (
    AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath,
)
from tfstride.providers.azure.resource_decoration.app_service_diagnostic_setting_audit_telemetry_disruption_paths import (
    current_app_service_diagnostic_setting_audit_telemetry_disruption_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_DELETE_DIAGNOSTIC_SETTING = "Microsoft.Insights/DiagnosticSettings/Delete"
_DIAGNOSTIC_SETTING_MARKER = "/providers/Microsoft.Insights/diagnosticSettings/"
_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "identity_address",
    "identity_kind",
    "principal_id",
    "credential_context",
    "diagnostic_setting_address",
    "diagnostic_setting_resource_type",
    "diagnostic_setting_name",
    "diagnostic_setting_arm_id",
    "monitored_resource_address",
    "monitored_resource_type",
    "monitored_resource_id",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
    "role_assignment_address",
)


class AzureAppServiceDiagnosticSettingDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_diagnostic_setting_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        resources = list(context.inventory.resources)
        decoration_context = AzureDecorationContext(AzureResourceIndexBuilder().build(resources))
        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths: list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath] = []
            seen_keys: set[tuple[str, ...]] = set()
            for cached_path in app_facts.app_service_diagnostic_setting_audit_telemetry_disruption_paths:
                current_path = _current_diagnostic_setting_path(
                    cached_path,
                    app,
                    context,
                    decoration_context,
                )
                if current_path is None:
                    continue
                key = _relationship_key(current_path)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                paths.append(current_path)
            if not paths:
                continue

            diagnostic_addresses = _path_string_values(paths, "diagnostic_setting_address")
            identity_addresses = _path_string_values(paths, "identity_address")
            assignment_addresses = _path_string_values(paths, "role_assignment_address")
            authorization_sources = _path_string_values(paths, "authorization_source_addresses")
            target_addresses = _target_model_evidence_addresses(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(diagnostic_addresses) > 1 else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *diagnostic_addresses,
                            *target_addresses,
                            *assignment_addresses,
                            *authorization_sources,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(app, paths),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item(
                            "diagnostic_setting_audit_telemetry_disruption_paths",
                            _path_evidence(paths),
                        ),
                        evidence_item("diagnostic_setting_destination_evidence", _destination_evidence(paths)),
                        evidence_item(
                            "diagnostic_setting_audit_telemetry_relevance_evidence", _relevance_evidence(paths)
                        ),
                        evidence_item("diagnostic_setting_management_lock_evidence", _lock_evidence(paths)),
                        evidence_item("diagnostic_setting_outcome_evidence", _outcome_evidence(paths)),
                        evidence_item("assessment_scope", _assessment_scope()),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_diagnostic_setting_path(
    cached_path: Mapping[str, object],
    app: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AzureDecorationContext,
) -> AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath | None:
    if not _cached_path_is_coherent(cached_path, app):
        return None

    diagnostic_address = _known_string(cached_path.get("diagnostic_setting_address"))
    if diagnostic_address is None:
        return None
    diagnostic_setting = context.inventory.get_by_address(diagnostic_address)
    if (
        diagnostic_setting is None
        or diagnostic_setting.provider != "azure"
        or diagnostic_setting.resource_type != AzureResourceType.MONITOR_DIAGNOSTIC_SETTING
    ):
        return None

    current_paths = current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
        app,
        diagnostic_setting,
        list(context.inventory.resources),
        decoration_context,
    )
    return next(
        (current_path for current_path in current_paths if _relationship_matches(cached_path, current_path)),
        None,
    )


def _cached_path_is_coherent(
    path: Mapping[str, object],
    app: NormalizedResource,
) -> bool:
    diagnostic_address = _known_string(path.get("diagnostic_setting_address"))
    diagnostic_arm_id = _known_string(path.get("diagnostic_setting_arm_id"))
    identity_address = _known_string(path.get("identity_address"))
    assignment_address = _known_string(path.get("role_assignment_address"))
    target_addresses = path.get("target_model_evidence_addresses")
    return bool(
        path.get("workload_address") == app.address
        and path.get("workload_type") == app.resource_type
        and path.get("identity_kind") in {"system_assigned", "user_assigned"}
        and identity_address
        and _known_string(path.get("principal_id"))
        and path.get("credential_context") == "workload_runtime"
        and diagnostic_address
        and path.get("diagnostic_setting_resource_type") == AzureResourceType.MONITOR_DIAGNOSTIC_SETTING
        and _known_string(path.get("diagnostic_setting_name"))
        and _is_canonical_diagnostic_setting_arm_id(diagnostic_arm_id)
        and path.get("operation") == _DELETE_DIAGNOSTIC_SETTING
        and path.get("operation_class") == "diagnostic_setting_deletion"
        and path.get("internal_operation") == "delete_diagnostic_setting"
        and path.get("management_effect") == "audit_telemetry_disruption"
        and path.get("target_granularity") == "diagnostic_setting"
        and path.get("target_scope") == "exact_monitor_diagnostic_setting"
        and isinstance(target_addresses, list)
        and diagnostic_address in target_addresses
        and assignment_address
        and path.get("authorization_state") == "granted"
        and path.get("modeled_allow_evidence_complete") is True
        and path.get("condition") is None
        and path.get("condition_state") == "not_configured"
        and path.get("lifecycle_compatibility_state") == "compatible"
        and _lock_evidence_is_compatible(path.get("management_lock_evidence"))
        and _destination_evidence_is_configured(path.get("destination_evidence"))
        and _relevance_evidence_is_established(path.get("audit_telemetry_relevance_evidence"))
        and _outcome_evidence_is_conservative(path.get("outcome_evidence"))
    )


def _relationship_matches(
    cached_path: Mapping[str, object],
    current_path: Mapping[str, object],
) -> bool:
    return all(cached_path.get(field) == current_path.get(field) for field in _RELATIONSHIP_FIELDS)


def _relationship_key(
    path: Mapping[str, object],
) -> tuple[str, ...]:
    return tuple(repr(path.get(field)) for field in _RELATIONSHIP_FIELDS)


def _is_canonical_diagnostic_setting_arm_id(value: object) -> bool:
    normalized = _known_string(value)
    return bool(
        normalized
        and "|" not in normalized
        and normalized.casefold().startswith("/subscriptions/")
        and _DIAGNOSTIC_SETTING_MARKER.casefold() in normalized.casefold()
    )


def _path_string_values(paths: Sequence[Mapping[str, object]], key: str) -> list[str]:
    values: set[str] = set()
    for path in paths:
        value = path.get(key)
        if isinstance(value, list):
            values.update(item for item in value if isinstance(item, str) and item)
        elif isinstance(value, str) and value:
            values.add(value)
    return sorted(values)


def _target_model_evidence_addresses(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        target_addresses = path.get("target_model_evidence_addresses")
        if isinstance(target_addresses, list):
            values.update(item for item in target_addresses if isinstance(item, str) and item)
    return sorted(values)


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"diagnostic_setting_address={path.get('diagnostic_setting_address')}",
                    f"diagnostic_setting_name={path.get('diagnostic_setting_name')}",
                    f"diagnostic_setting_id={_display(path.get('diagnostic_setting_id'))}",
                    f"diagnostic_setting_reference={_display(path.get('diagnostic_setting_reference'))}",
                    f"diagnostic_setting_arm_id={path.get('diagnostic_setting_arm_id')}",
                    f"monitored_resource_address={path.get('monitored_resource_address')}",
                    f"monitored_resource_id={path.get('monitored_resource_id')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"role_assignment_address={path.get('role_assignment_address')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                    f"role={_authorization_role(path.get('authorization_grant'))}",
                    f"role_kind={_role_kind(path.get('authorization_grant'))}",
                    f"role_actions={','.join(_string_values(_authorization_grant_value(path.get('authorization_grant'), 'role_actions'))) or 'none'}",
                    f"role_not_actions={','.join(_string_values(_authorization_grant_value(path.get('authorization_grant'), 'role_not_actions'))) or 'none'}",
                    "authorization_state=granted",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _destination_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("destination_evidence")
        if not isinstance(evidence, Mapping):
            continue
        values.add(
            "; ".join(
                (
                    f"diagnostic_setting_address={path.get('diagnostic_setting_address')}",
                    f"destination_basis={_display(evidence.get('destination_basis'))}",
                    f"log_analytics_workspace_id={_display(evidence.get('log_analytics_workspace_id'))}",
                    f"storage_account_id={_display(evidence.get('storage_account_id'))}",
                    f"eventhub_authorization_rule_id={_display(evidence.get('eventhub_authorization_rule_id'))}",
                    f"eventhub_name={_display(evidence.get('eventhub_name'))}",
                    f"marketplace_partner_resource_id={_display(evidence.get('marketplace_partner_resource_id'))}",
                    "destination_state=configured",
                )
            )
        )
    return sorted(values)


def _relevance_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("audit_telemetry_relevance_evidence")
        if not isinstance(evidence, Mapping):
            continue
        values.add(
            "; ".join(
                (
                    f"diagnostic_setting_address={path.get('diagnostic_setting_address')}",
                    f"relevance_basis={_display(evidence.get('relevance_basis'))}",
                    f"matched_audit_security_category={_display(evidence.get('matched_audit_security_category'))}",
                    f"matched_audit_security_category_group={_display(evidence.get('matched_audit_security_category_group'))}",
                    f"enabled_log_categories={','.join(_string_values(evidence.get('enabled_log_categories'))) or 'none'}",
                    f"enabled_log_category_groups={','.join(_string_values(evidence.get('enabled_log_category_groups'))) or 'none'}",
                    "audit_telemetry_relevance_state=established",
                )
            )
        )
    return sorted(values)


def _lock_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("management_lock_evidence")
        if not isinstance(evidence, Mapping):
            continue
        values.add(
            "; ".join(
                (
                    f"diagnostic_setting_address={path.get('diagnostic_setting_address')}",
                    f"modeled_management_lock_state={_display(evidence.get('modeled_management_lock_state'))}",
                    f"deletion_compatibility_state={_display(evidence.get('deletion_compatibility_state'))}",
                    "blocking_lock_present=false",
                )
            )
        )
    return sorted(values)


def _outcome_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        evidence = path.get("outcome_evidence")
        if not isinstance(evidence, Mapping):
            continue
        values.add(
            "; ".join(
                (
                    f"diagnostic_setting_address={path.get('diagnostic_setting_address')}",
                    f"successful_operation_observed={_display(evidence.get('successful_operation_observed'))}",
                    "historical_log_deletion_authorized_by_operation="
                    f"{_display(evidence.get('historical_log_deletion_authorized_by_operation'))}",
                    f"historical_log_deletion_observed={_display(evidence.get('historical_log_deletion_observed'))}",
                    "destination_resource_deletion_authorized_by_operation="
                    f"{_display(evidence.get('destination_resource_deletion_authorized_by_operation'))}",
                    f"destination_resource_deletion_observed={_display(evidence.get('destination_resource_deletion_observed'))}",
                    f"all_resource_diagnostic_settings_evaluated={_display(evidence.get('all_resource_diagnostic_settings_evaluated'))}",
                    f"out_of_plan_diagnostic_settings_evaluated={_display(evidence.get('out_of_plan_diagnostic_settings_evaluated'))}",
                    f"telemetry_recovery_state={_display(evidence.get('telemetry_recovery_state'))}",
                    f"restoration_observed={_display(evidence.get('restoration_observed'))}",
                    f"uncertainties={','.join(_string_values(evidence.get('uncertainties'))) or 'none'}",
                )
            )
        )
    return sorted(values)


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=Repudiation risk from deterministic "
            "Microsoft.Insights/DiagnosticSettings/Delete authority over exact "
            "currently audit/security-relevant diagnostic settings"
        ),
        (
            "effect=compromise of the public App Service could disrupt future "
            "export or recording of the modeled audit/security telemetry to the "
            "configured destination, weakening auditability/accountability"
        ),
        (
            "does_not_establish=successful API operation, diagnostic-setting deletion, "
            "historical or source telemetry deletion, deletion of logs already delivered "
            "to any destination, destination-resource deletion, disruption of every or "
            "out-of-plan diagnostic setting, recovery/restoration, or broader service availability impact"
        ),
    ]


def _rationale(
    app: NormalizedResource,
    paths: Sequence[Mapping[str, object]],
) -> str:
    diagnostic_count = len({path.get("diagnostic_setting_address") for path in paths})
    diagnostic_label = "diagnostic setting" if diagnostic_count == 1 else "diagnostic settings"
    destinations = _destination_labels(paths)
    destination_text = ", ".join(destinations) or "the modeled configured destination"
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its current App Service runtime identity "
        f"has deterministic {_DELETE_DIAGNOSTIC_SETTING} authority over {diagnostic_count} exact {diagnostic_label} "
        f"that currently export modeled audit/security telemetry to {destination_text}. A compromise of the public "
        "workload could request deletion of those exact diagnostic-setting targets, disrupting future export or "
        "recording of the modeled audit/security telemetry and weakening auditability/accountability. This "
        "plan-local evidence does not establish a successful API call or deletion, deletion of historical/source "
        "telemetry, deletion of logs already delivered to Log Analytics, deletion of logs already delivered to Storage, "
        "deletion of logs already delivered to Event Hubs, deletion of logs already delivered to marketplace/partner "
        "destinations, deletion of the destination resource, disruption of every parent-resource, subscription, or "
        "tenant diagnostic setting, disruption of out-of-plan settings, recovery/restoration, or broader service "
        "availability impact."
    )


def _destination_labels(paths: Sequence[Mapping[str, object]]) -> list[str]:
    labels: set[str] = set()
    for path in paths:
        evidence = path.get("destination_evidence")
        if not isinstance(evidence, Mapping):
            continue
        basis = _known_string(evidence.get("destination_basis"))
        if basis == "log_analytics_workspace":
            value = _known_string(evidence.get("log_analytics_workspace_id"))
        elif basis == "storage_account":
            value = _known_string(evidence.get("storage_account_id"))
        elif basis == "event_hub":
            value = _known_string(evidence.get("eventhub_authorization_rule_id"))
        elif basis == "marketplace_partner":
            value = _known_string(evidence.get("marketplace_partner_resource_id"))
        else:
            value = None
        if basis and value:
            labels.add(f"{basis} {value}")
    return sorted(labels)


def _authorization_grant_value(value: object, key: str) -> object:
    if not isinstance(value, Mapping):
        return None
    return cast(Mapping[str, object], value).get(key)


def _authorization_role(value: object) -> str:
    role = _authorization_grant_value(value, "role_definition_name")
    return _display(role)


def _role_kind(value: object) -> str:
    role_evidence = _authorization_grant_value(value, "role_evidence")
    if not isinstance(role_evidence, Mapping):
        return "unknown"
    return _display(cast(Mapping[str, object], role_evidence).get("role_kind"))


def _lock_evidence_is_compatible(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    evidence = cast(Mapping[str, object], value)
    return bool(
        evidence.get("modeled_management_lock_state") == "not_observed"
        and evidence.get("deletion_compatibility_state") == "compatible"
    )


def _destination_evidence_is_configured(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    return cast(Mapping[str, object], value).get("destination_state") == "configured"


def _relevance_evidence_is_established(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    return cast(Mapping[str, object], value).get("audit_telemetry_relevance_state") == "established"


def _outcome_evidence_is_conservative(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    evidence = cast(Mapping[str, object], value)
    return bool(
        evidence.get("successful_operation_observed") is False
        and evidence.get("historical_log_deletion_authorized_by_operation") is False
        and evidence.get("historical_log_deletion_observed") is False
        and evidence.get("destination_resource_deletion_authorized_by_operation") is False
        and evidence.get("destination_resource_deletion_observed") is False
        and evidence.get("all_resource_diagnostic_settings_evaluated") is False
        and evidence.get("out_of_plan_diagnostic_settings_evaluated") is False
        and evidence.get("restoration_observed") is False
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
