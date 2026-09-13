from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    azure_arm_scope_contains,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import AzureArmControlPlaneGrant
from tfstride.providers.azure.audit_telemetry_disruption_evidence import (
    AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath,
    AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence,
    AzureDiagnosticSettingAuditCategoryRelevanceEvidence,
    AzureDiagnosticSettingBuiltInRoleEvidence,
    AzureDiagnosticSettingConfiguredDestinationEvidence,
    AzureDiagnosticSettingCustomRoleEvidence,
    AzureDiagnosticSettingDeletionAuthorizationGrant,
    AzureDiagnosticSettingEstablishedAuditTelemetryRelevanceEvidence,
    AzureDiagnosticSettingEventHubDestinationEvidence,
    AzureDiagnosticSettingLogAnalyticsDestinationEvidence,
    AzureDiagnosticSettingManagementLockNotObserved,
    AzureDiagnosticSettingMarketplaceDestinationEvidence,
    AzureDiagnosticSettingRoleEvidence,
    AzureDiagnosticSettingStorageDestinationEvidence,
)
from tfstride.providers.azure.key_vault_evidence import AzureKeyVaultRuntimeIdentityKind
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.coercion import dedupe, dedupe_strings

_DELETE_DIAGNOSTIC_SETTING: Literal["Microsoft.Insights/DiagnosticSettings/Delete"] = (
    "Microsoft.Insights/DiagnosticSettings/Delete"
)
_DIAGNOSTIC_SETTING_MARKER = "/providers/Microsoft.Insights/diagnosticSettings/"
_PARENT_RESOURCE_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/[^/]+/[^/]+/[^/]+(?:/[^/]+/[^/]+)*$",
    re.IGNORECASE,
)
# Web App diagnostic categories deterministically include AppServiceAuditLogs.
# Do not generalize allLogs relevance to Function Apps or other Azure targets.
_ALL_LOGS_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.LINUX_WEB_APP,
        AzureResourceType.WINDOWS_WEB_APP,
    }
)
_AUDIT_SECURITY_CATEGORIES_BY_RESOURCE_TYPE = {
    AzureResourceType.LINUX_WEB_APP: frozenset({"appserviceauditlogs"}),
    AzureResourceType.WINDOWS_WEB_APP: frozenset({"appserviceauditlogs"}),
}
_DESTINATION_FIELDS = (
    "log_analytics_workspace_id",
    "storage_account_id",
    "eventhub_authorization_rule_id",
    "eventhub_name",
    "partner_solution_id",
)
_LockEvaluationState = Literal["not_observed", "blocking", "unknown"]


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


@dataclass(frozen=True, slots=True)
class _DiagnosticSettingTarget:
    resource: NormalizedResource
    name: str
    reference: str
    configured_id: str | None
    arm_id: str
    monitored_resource: NormalizedResource
    monitored_resource_id: str


@dataclass(frozen=True, slots=True)
class _LockEvaluation:
    state: _LockEvaluationState
    uncertainties: tuple[str, ...] = ()


class ModelAppServiceDiagnosticSettingAuditTelemetryDisruptionPathsStage:
    """Model exact App Service authority to delete audit diagnostic settings."""

    name = "model_app_service_diagnostic_setting_audit_telemetry_disruption_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        targets, target_uncertainties = _diagnostic_setting_targets(resources)
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        locks = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK)

        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_diagnostic_setting_paths(
                workload,
                targets,
                assignments,
                locks,
                context,
            )
            uncertainties.extend(f"{workload.address}: {value}" for value in target_uncertainties)
            facts = azure_facts(workload)
            facts.set_app_service_diagnostic_setting_audit_telemetry_disruption_paths(paths)
            facts.extend_app_service_diagnostic_setting_audit_telemetry_disruption_path_uncertainties(
                dedupe(uncertainties)
            )


def current_app_service_diagnostic_setting_audit_telemetry_disruption_paths(
    workload: NormalizedResource,
    diagnostic_setting: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath]:
    """Recompute every current deterministic proof for one workload and setting."""

    if (
        workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES
        or diagnostic_setting.resource_type != AzureResourceType.MONITOR_DIAGNOSTIC_SETTING
    ):
        return []
    target, _uncertainty = _diagnostic_setting_target(diagnostic_setting, resources)
    if target is None:
        return []
    paths, _uncertainties = _app_service_diagnostic_setting_paths(
        workload,
        (target,),
        tuple(resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT),
        tuple(resource for resource in resources if resource.resource_type == AzureResourceType.MANAGEMENT_LOCK),
        context,
    )
    return paths


def _app_service_diagnostic_setting_paths(
    workload: NormalizedResource,
    targets: Sequence[_DiagnosticSettingTarget],
    assignments: Sequence[NormalizedResource],
    locks: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *(f"{workload.address}: {value}" for value in azure_facts(workload).managed_identity_uncertainties),
    ]
    runtime_identities = tuple(
        _RuntimeIdentity(identity, kind, principal_id)
        for identity, kind in identities
        if (principal_id := _known_string(azure_facts(identity).principal_id)) is not None
    )
    if not runtime_identities:
        return [], dedupe(uncertainties)

    paths: list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath] = []
    for target in targets:
        destination, destination_uncertainties = _destination_evidence(target.resource)
        relevance, relevance_uncertainties = _relevance_evidence(target)
        lock = _management_lock_evaluation(target, locks, context)
        uncertainties.extend(
            f"{workload.address}: {target.resource.address}: {value}"
            for value in (*destination_uncertainties, *relevance_uncertainties, *lock.uncertainties)
        )
        if destination is None or relevance is None or lock.state != "not_observed":
            continue

        for identity in runtime_identities:
            grants: list[AzureArmControlPlaneGrant] = []
            authorization_incomplete = False
            for assignment in assignments:
                result = model_arm_control_plane_action_authority(
                    assignment,
                    context,
                    principal_id=identity.principal_id,
                    target_arm_id=target.arm_id,
                    requested_actions=(_DELETE_DIAGNOSTIC_SETTING,),
                )
                if result.state == "unknown":
                    authorization_incomplete = True
                    _record_authorization_uncertainties(
                        workload,
                        target,
                        result,
                        uncertainties,
                    )
                if result.grant is not None:
                    grants.append(result.grant)
            if authorization_incomplete:
                continue

            for grant in grants:
                path = _disruption_path(
                    workload,
                    identity,
                    target,
                    grant,
                    destination,
                    relevance,
                )
                if path is None:
                    uncertainties.append(
                        f"{workload.address}: {grant['source_address']} returned incoherent diagnostic-setting "
                        f"deletion evidence for {target.resource.address}"
                    )
                    continue
                paths.append(path)

    paths.sort(
        key=lambda path: (
            path["diagnostic_setting_address"],
            path["identity_address"],
            path["role_assignment_address"],
        )
    )
    return _dedupe_paths(paths), dedupe(uncertainties)


def _record_authorization_uncertainties(
    workload: NormalizedResource,
    target: _DiagnosticSettingTarget,
    result: AzureArmControlPlaneAuthorityResult,
    uncertainties: list[str],
) -> None:
    uncertainties.extend(f"{workload.address}: {target.resource.address}: {value}" for value in result.uncertainties)


def _diagnostic_setting_targets(
    resources: Sequence[NormalizedResource],
) -> tuple[list[_DiagnosticSettingTarget], list[str]]:
    targets: list[_DiagnosticSettingTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type != AzureResourceType.MONITOR_DIAGNOSTIC_SETTING:
            continue
        target, uncertainty = _diagnostic_setting_target(resource, resources)
        if target is not None:
            targets.append(target)
        elif uncertainty is not None:
            uncertainties.append(uncertainty)
    targets.sort(key=lambda target: target.resource.address)
    return targets, dedupe(uncertainties)


def _diagnostic_setting_target(
    resource: NormalizedResource,
    resources: Sequence[NormalizedResource],
) -> tuple[_DiagnosticSettingTarget | None, str | None]:
    facts = azure_facts(resource)
    target_uncertainties = _matching_uncertainties(
        facts.azure_security_posture_uncertainties,
        ("name", "target_resource_id"),
        prefixes_only=True,
    )
    name = _known_string(facts.diagnostic_setting_name)
    parent_reference = _known_string(facts.diagnostic_target_resource_id)
    if target_uncertainties or name is None or "/" in name or name.casefold() == "service" or parent_reference is None:
        return (
            None,
            f"{resource.address}: exact deletable diagnostic-setting identity or parent reference is unresolved",
        )

    parents = _monitored_resource_candidates(parent_reference, resources)
    if len(parents) != 1:
        return None, f"{resource.address}: exact diagnostic-setting parent resource correlation is unresolved"
    parent = parents[0]
    parent_id = _exact_parent_resource_id(_resource_arm_id(parent))
    if parent_id is None:
        return None, f"{resource.address}: exact monitored-resource ARM identity is unresolved"

    expected_arm_id = f"{parent_id}{_DIAGNOSTIC_SETTING_MARKER}{name}"
    configured_id = _known_string(facts.diagnostic_setting_id)
    if configured_id is not None:
        provider_id = _diagnostic_setting_provider_id(configured_id)
        if provider_id is None:
            return None, f"{resource.address}: diagnostic-setting provider state identity is invalid"
        configured_parent_id, configured_name = provider_id
        if not _same_identifier(configured_parent_id, parent_id) or configured_name.casefold() != name.casefold():
            return (
                None,
                f"{resource.address}: diagnostic-setting provider state identity and parent ancestry are incoherent",
            )

    return (
        _DiagnosticSettingTarget(
            resource=resource,
            name=name,
            reference=configured_id or expected_arm_id,
            configured_id=configured_id,
            arm_id=expected_arm_id,
            monitored_resource=parent,
            monitored_resource_id=parent_id,
        ),
        None,
    )


def _monitored_resource_candidates(
    reference: str,
    resources: Sequence[NormalizedResource],
) -> list[NormalizedResource]:
    arm_reference = _known_arm_id(reference)
    symbolic_address = None if arm_reference is not None else _symbolic_resource_address(reference)
    candidates: dict[str, NormalizedResource] = {}
    for candidate in resources:
        if candidate.resource_type == AzureResourceType.MONITOR_DIAGNOSTIC_SETTING or candidate.provider != "azure":
            continue
        candidate_id = _resource_arm_id(candidate)
        if arm_reference is not None:
            matches = candidate_id is not None and _same_identifier(candidate_id, arm_reference)
        else:
            matches = symbolic_address is not None and candidate.address == symbolic_address
        if matches:
            candidates.setdefault(candidate.address, candidate)
    return [candidates[address] for address in sorted(candidates)]


def _destination_evidence(
    resource: NormalizedResource,
) -> tuple[AzureDiagnosticSettingConfiguredDestinationEvidence | None, list[str]]:
    facts = azure_facts(resource)
    uncertainties = _matching_uncertainties(
        facts.azure_security_posture_uncertainties,
        _DESTINATION_FIELDS,
    )
    log_analytics = _known_string(facts.diagnostic_log_analytics_workspace_id)
    storage = _known_string(facts.diagnostic_storage_account_id)
    eventhub_rule = _known_string(facts.diagnostic_eventhub_authorization_rule_id)
    eventhub_name = _known_string(facts.diagnostic_eventhub_name)
    marketplace = _known_string(facts.diagnostic_marketplace_partner_resource_id)
    if uncertainties:
        return None, uncertainties
    if log_analytics is not None:
        return (
            AzureDiagnosticSettingLogAnalyticsDestinationEvidence(
                destination_evidence_scope="plan_local_diagnostic_setting_destinations",
                destination_state="configured",
                destination_basis="log_analytics_workspace",
                log_analytics_workspace_id=log_analytics,
                storage_account_id=storage,
                eventhub_authorization_rule_id=eventhub_rule,
                eventhub_name=eventhub_name,
                marketplace_partner_resource_id=marketplace,
                uncertainties=[],
            ),
            [],
        )
    if storage is not None:
        return (
            AzureDiagnosticSettingStorageDestinationEvidence(
                destination_evidence_scope="plan_local_diagnostic_setting_destinations",
                destination_state="configured",
                destination_basis="storage_account",
                log_analytics_workspace_id=None,
                storage_account_id=storage,
                eventhub_authorization_rule_id=eventhub_rule,
                eventhub_name=eventhub_name,
                marketplace_partner_resource_id=marketplace,
                uncertainties=[],
            ),
            [],
        )
    if eventhub_rule is not None:
        return (
            AzureDiagnosticSettingEventHubDestinationEvidence(
                destination_evidence_scope="plan_local_diagnostic_setting_destinations",
                destination_state="configured",
                destination_basis="event_hub",
                log_analytics_workspace_id=None,
                storage_account_id=None,
                eventhub_authorization_rule_id=eventhub_rule,
                eventhub_name=eventhub_name,
                marketplace_partner_resource_id=marketplace,
                uncertainties=[],
            ),
            [],
        )
    if marketplace is not None:
        return (
            AzureDiagnosticSettingMarketplaceDestinationEvidence(
                destination_evidence_scope="plan_local_diagnostic_setting_destinations",
                destination_state="configured",
                destination_basis="marketplace_partner",
                log_analytics_workspace_id=None,
                storage_account_id=None,
                eventhub_authorization_rule_id=None,
                eventhub_name=eventhub_name,
                marketplace_partner_resource_id=marketplace,
                uncertainties=[],
            ),
            [],
        )
    return None, [f"{resource.address}: no configured modeled diagnostic destination is established"]


def _relevance_evidence(
    target: _DiagnosticSettingTarget,
) -> tuple[AzureDiagnosticSettingEstablishedAuditTelemetryRelevanceEvidence | None, list[str]]:
    resource = target.resource
    facts = azure_facts(resource)
    uncertainties = _matching_uncertainties(
        facts.azure_security_posture_uncertainties,
        ("enabled_log", "log"),
        prefixes_only=True,
    )
    enabled_records = [record for record in facts.diagnostic_log_records if record.get("enabled") is not False]
    if any(record.get("unknown_fields") for record in enabled_records):
        uncertainties.append(f"{resource.address}: enabled diagnostic log category configuration is unresolved")
    if any(
        not _known_string(record.get("category")) and not _known_string(record.get("category_group"))
        for record in enabled_records
    ):
        uncertainties.append(f"{resource.address}: an enabled diagnostic log record has no resolved category or group")

    categories = sorted(dedupe_strings(facts.diagnostic_enabled_log_categories), key=str.casefold)
    groups = sorted(dedupe_strings(facts.diagnostic_enabled_log_category_groups), key=str.casefold)
    if uncertainties:
        return None, dedupe(uncertainties)

    matched_category = next(
        (
            value
            for value in categories
            if _is_audit_or_security_category(
                value,
                target.monitored_resource.resource_type,
            )
        ),
        None,
    )
    if matched_category is not None:
        return (
            AzureDiagnosticSettingAuditCategoryRelevanceEvidence(
                relevance_evidence_scope="plan_local_diagnostic_setting_enabled_log_categories",
                relevance_basis="audit_security_category",
                matched_audit_security_category=matched_category,
                matched_audit_security_category_group=None,
                enabled_log_categories=categories,
                enabled_log_category_groups=groups,
                audit_telemetry_relevance_state="established",
                uncertainties=[],
            ),
            [],
        )
    matched_group = next(
        (
            value
            for value in groups
            if _is_audit_or_security_category_group(
                value,
                target.monitored_resource.resource_type,
            )
        ),
        None,
    )
    if matched_group is not None:
        return (
            AzureDiagnosticSettingAuditCategoryGroupRelevanceEvidence(
                relevance_evidence_scope="plan_local_diagnostic_setting_enabled_log_categories",
                relevance_basis="audit_security_category_group",
                matched_audit_security_category=None,
                matched_audit_security_category_group=matched_group,
                enabled_log_categories=categories,
                enabled_log_category_groups=groups,
                audit_telemetry_relevance_state="established",
                uncertainties=[],
            ),
            [],
        )
    return None, []


def _management_lock_evaluation(
    target: _DiagnosticSettingTarget,
    locks: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> _LockEvaluation:
    blocking = False
    uncertainties: list[str] = []
    for lock in locks:
        scope_state = _management_lock_scope_state(lock, target, context)
        if scope_state == "unrelated":
            continue
        lock_facts = azure_facts(lock)
        if scope_state == "unknown":
            uncertainties.extend(
                f"{lock.address}: {value}"
                for value in (
                    lock_facts.management_lock_uncertainties or ["management-lock scope applicability is unresolved"]
                )
            )
            continue
        if _blocking_lock_level(lock_facts.management_lock_level) is None:
            uncertainties.extend(
                f"{lock.address}: {value}"
                for value in (
                    lock_facts.management_lock_uncertainties or ["management-lock level is unsupported or unresolved"]
                )
            )
            continue
        blocking = True

    if blocking:
        return _LockEvaluation("blocking")
    if uncertainties:
        return _LockEvaluation("unknown", tuple(dedupe(uncertainties)))
    return _LockEvaluation("not_observed")


def _management_lock_scope_state(
    lock: NormalizedResource,
    target: _DiagnosticSettingTarget,
    context: AzureDecorationContext,
) -> Literal["applicable", "unrelated", "unknown"]:
    scope = _known_string(azure_facts(lock).management_lock_scope)
    if scope is None:
        return "unknown"
    if scope.startswith("/"):
        arm_scope = _known_arm_id(scope)
        if arm_scope is None:
            return "unknown"
        if arm_scope.casefold().startswith("/providers/microsoft.management/managementgroups/"):
            return "unknown"
    else:
        scope_resource = context.index.resolve(scope, source=lock)
        if scope_resource is None:
            return "unknown"
        if scope_resource.address == target.resource.address:
            arm_scope = target.arm_id
        else:
            arm_scope = _resource_arm_id(scope_resource)
        if arm_scope is None:
            return "unknown"
    return "applicable" if azure_arm_scope_contains(arm_scope, target.arm_id) else "unrelated"


def _blocking_lock_level(value: object) -> Literal["CanNotDelete", "ReadOnly"] | None:
    normalized = _known_string(value)
    if normalized is None:
        return None
    key = normalized.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if key == "cannotdelete":
        return "CanNotDelete"
    if key == "readonly":
        return "ReadOnly"
    return None


def _disruption_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: _DiagnosticSettingTarget,
    grant: AzureArmControlPlaneGrant,
    destination: AzureDiagnosticSettingConfiguredDestinationEvidence,
    relevance: AzureDiagnosticSettingEstablishedAuditTelemetryRelevanceEvidence,
) -> AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath | None:
    authorization = _authorization_grant(grant, identity, target)
    if authorization is None:
        return None
    role_definition_address = grant["role_definition_address"]
    lock_evidence = AzureDiagnosticSettingManagementLockNotObserved(
        lock_evidence_scope="plan_local_diagnostic_setting_arm_ancestry",
        modeled_management_lock_state="not_observed",
        applicable_lock_addresses=[],
        applicable_lock_levels=[],
        external_management_locks_evaluated=False,
        deletion_compatibility_state="compatible",
        uncertainties=[],
    )
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.resource.address,
        "identity_kind": identity.kind,
        "principal_id": identity.principal_id,
        "credential_context": "workload_runtime",
        "diagnostic_setting_address": target.resource.address,
        "diagnostic_setting_resource_type": target.resource.resource_type,
        "diagnostic_setting_name": target.name,
        "diagnostic_setting_reference": target.reference,
        "diagnostic_setting_id": target.configured_id,
        "diagnostic_setting_arm_id": target.arm_id,
        "monitored_resource_address": target.monitored_resource.address,
        "monitored_resource_type": target.monitored_resource.resource_type,
        "monitored_resource_id": target.monitored_resource_id,
        "operation": _DELETE_DIAGNOSTIC_SETTING,
        "operation_class": "diagnostic_setting_deletion",
        "internal_operation": "delete_diagnostic_setting",
        "management_effect": "audit_telemetry_disruption",
        "authorization_evidence_kind": "azure_rbac_action",
        "target_granularity": "diagnostic_setting",
        "target_scope": "exact_monitor_diagnostic_setting",
        "target_model_evidence_addresses": [
            target.monitored_resource.address,
            target.resource.address,
        ],
        "role_assignment_address": grant["source_address"],
        "authorization_source_addresses": dedupe_strings([grant["source_address"], role_definition_address]),
        "authorization_state": "granted",
        "modeled_allow_evidence_complete": True,
        "condition": None,
        "condition_state": "not_configured",
        "authorization_grant": authorization,
        "lifecycle_compatibility_state": "compatible",
        "management_lock_evidence": lock_evidence,
        "destination_evidence": destination,
        "audit_telemetry_relevance_evidence": relevance,
        "outcome_evidence": {
            "outcome_evidence_scope": "plan_local_diagnostic_setting_deletion_authority",
            "successful_operation_observed": False,
            "historical_log_deletion_authorized_by_operation": False,
            "historical_log_deletion_observed": False,
            "destination_resource_deletion_authorized_by_operation": False,
            "destination_resource_deletion_observed": False,
            "all_resource_diagnostic_settings_evaluated": False,
            "out_of_plan_diagnostic_settings_evaluated": False,
            "telemetry_recovery_state": "not_established_by_modeled_azure_diagnostic_setting_evidence",
            "restoration_observed": False,
            "uncertainties": [],
        },
        "posture_uncertainties": [],
    }


def _authorization_grant(
    grant: AzureArmControlPlaneGrant,
    identity: _RuntimeIdentity,
    target: _DiagnosticSettingTarget,
) -> AzureDiagnosticSettingDeletionAuthorizationGrant | None:
    principal_id = _known_string(grant["principal_id"])
    role_evidence = _role_evidence(grant)
    if (
        principal_id is None
        or not _same_identifier(principal_id, identity.principal_id)
        or not _same_identifier(grant["target_arm_id"], target.arm_id)
        or grant["requested_actions"] != [_DELETE_DIAGNOSTIC_SETTING]
        or grant["matched_actions"] != [_DELETE_DIAGNOSTIC_SETTING]
        or grant["excluded_actions"]
        or grant["principal_state"] != "resolved"
        or grant["assignment_scope_state"] != "resolved"
        or grant["assignment_condition"] is not None
        or grant["assignment_condition_version"] is not None
        or grant["assignment_condition_state"] != "not_configured"
        or grant["role_definition_condition_state"] != "not_configured"
        or grant["delegation_constraint_kind"] != "none"
        or grant["allowed_role_definition_ids"]
        or grant["authorization_state"] != "granted"
        or grant["deny_assignments_evaluated"] is not False
        or grant["evaluation_basis"] != "modeled_arm_control_plane_authority"
        or role_evidence is None
    ):
        return None
    return AzureDiagnosticSettingDeletionAuthorizationGrant(
        source_address=grant["source_address"],
        principal_id=principal_id,
        principal_type=grant["principal_type"],
        principal_state="resolved",
        assignment_scope_type=grant["assignment_scope_type"],
        assignment_scope=grant["assignment_scope"],
        assignment_scope_arm_id=grant["assignment_scope_arm_id"],
        assignment_scope_state="resolved",
        target_arm_id=target.arm_id,
        role_definition_name=grant["role_definition_name"],
        role_definition_id=grant["role_definition_id"],
        role_evidence=role_evidence,
        role_actions=list(grant["role_actions"]),
        role_not_actions=list(grant["role_not_actions"]),
        requested_actions=[_DELETE_DIAGNOSTIC_SETTING],
        matched_actions=[_DELETE_DIAGNOSTIC_SETTING],
        excluded_actions=[],
        assignment_condition=None,
        assignment_condition_version=None,
        assignment_condition_state="not_configured",
        role_definition_condition_state="not_configured",
        delegation_constraint_kind="none",
        allowed_role_definition_ids=[],
        authorization_state="granted",
        deny_assignments_evaluated=False,
        evaluation_basis="modeled_arm_control_plane_authority",
        diagnostic_settings_data_actions_authorization_effect=("not_used_for_arm_diagnostic_setting_deletion"),
    )


def _role_evidence(grant: AzureArmControlPlaneGrant) -> AzureDiagnosticSettingRoleEvidence | None:
    role_definition_address = _known_string(grant["role_definition_address"])
    if (
        grant["role_kind"] == "built_in"
        and grant["role_resolution_state"] == "modeled_subset"
        and role_definition_address is None
        and grant["assignable_scope_compatibility_state"] == "not_applicable"
    ):
        return AzureDiagnosticSettingBuiltInRoleEvidence(
            role_kind="built_in",
            role_resolution_state="modeled_subset",
            role_definition_address=None,
            assignable_scope_compatibility_state="not_applicable",
        )
    if (
        grant["role_kind"] == "custom"
        and grant["role_resolution_state"] == "resolved"
        and role_definition_address is not None
        and grant["assignable_scope_compatibility_state"] == "resolved"
    ):
        return AzureDiagnosticSettingCustomRoleEvidence(
            role_kind="custom",
            role_resolution_state="resolved",
            role_definition_address=role_definition_address,
            assignable_scope_compatibility_state="resolved",
        )
    return None


def _resource_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
        value = facts.app_service_id
    elif resource.resource_type == AzureResourceType.MONITOR_DIAGNOSTIC_SETTING:
        value = facts.diagnostic_setting_id
    else:
        value = resource.identifier
    return _known_arm_id(value) or _known_arm_id(resource.identifier)


def _exact_parent_resource_id(value: object) -> str | None:
    normalized = _known_arm_id(value)
    if normalized is None or _PARENT_RESOURCE_ID_PATTERN.fullmatch(normalized) is None:
        return None
    return normalized


def _diagnostic_setting_provider_id(value: object) -> tuple[str, str] | None:
    normalized = _known_string(value)
    if normalized is None or normalized.count("|") != 1:
        return None
    parent_value, setting_name = normalized.rsplit("|", 1)
    parent_id = _exact_parent_resource_id(parent_value)
    setting_name = _known_string(setting_name)
    if parent_id is None or setting_name is None or "/" in setting_name:
        return None
    return parent_id, setting_name


def _symbolic_resource_address(value: str) -> str | None:
    normalized = value.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        normalized = normalized[2:-1].strip()
    if not normalized.casefold().endswith(".id"):
        return None
    address = normalized[:-3].strip()
    return address or None


def _is_audit_or_security_category(
    value: str,
    monitored_resource_type: str,
) -> bool:
    supported = _AUDIT_SECURITY_CATEGORIES_BY_RESOURCE_TYPE.get(
        monitored_resource_type,
        frozenset(),
    )
    return value.strip().casefold() in supported


def _is_audit_or_security_category_group(
    value: str,
    monitored_resource_type: str,
) -> bool:
    normalized = _normalized_category_token(value)
    if normalized == "audit":
        return True
    return normalized == "alllogs" and monitored_resource_type in _ALL_LOGS_AUDIT_SECURITY_RESOURCE_TYPES


def _normalized_category_token(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum())


def _matching_uncertainties(
    uncertainties: Sequence[str],
    fields: Sequence[str],
    *,
    prefixes_only: bool = False,
) -> list[str]:
    field_keys = tuple(field.casefold() for field in fields)
    matched: list[str] = []
    for uncertainty in uncertainties:
        key = uncertainty.casefold()
        if prefixes_only:
            relevant = any(key.startswith(f"{field} ") or key.startswith(f"{field}.") for field in field_keys)
        else:
            relevant = any(field in key for field in field_keys)
        if relevant:
            matched.append(uncertainty)
    return dedupe(matched)


def _known_arm_id(value: object) -> str | None:
    normalized = _known_string(value)
    if normalized is None or "|" in normalized:
        return None
    lowered = normalized.casefold().rstrip("/")
    if not (lowered.startswith("/subscriptions/") or lowered.startswith("/providers/")):
        return None
    return normalized.rstrip("/")


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return bool(left_value and right_value and left_value.rstrip("/").casefold() == right_value.rstrip("/").casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_paths(
    paths: Sequence[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath],
) -> list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath]:
    result: list[AzureAppServiceDiagnosticSettingAuditTelemetryDisruptionPath] = []
    for path in paths:
        if path not in result:
            result.append(path)
    return result
