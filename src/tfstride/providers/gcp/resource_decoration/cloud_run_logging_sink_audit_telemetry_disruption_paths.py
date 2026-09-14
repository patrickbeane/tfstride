from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast
from urllib.parse import unquote

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.audit_telemetry_disruption_evidence import (
    GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath,
    GcpLoggingSinkActiveCustomRoleStage,
    GcpLoggingSinkActiveExplicitLifecycleEvidence,
    GcpLoggingSinkActiveLifecycleEvidence,
    GcpLoggingSinkActiveProviderDefaultLifecycleEvidence,
    GcpLoggingSinkAllLogsRelevanceEvidence,
    GcpLoggingSinkAuditFilterRelevanceEvidence,
    GcpLoggingSinkAuditTelemetryRelevanceEvidence,
    GcpLoggingSinkBuiltInRoleEvidence,
    GcpLoggingSinkCustomRoleEvidence,
    GcpLoggingSinkDeletionConstraintEvidence,
    GcpLoggingSinkDisabledLifecycleEvidence,
    GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence,
    GcpLoggingSinkIrrelevantFilterEvidence,
    GcpLoggingSinkLifecycleEvidence,
    GcpLoggingSinkRoleEvidence,
    GcpLoggingSinkSystemManagedDeletionConstraintEvidence,
    GcpLoggingSinkUnknownDeletionConstraintEvidence,
    GcpLoggingSinkUnknownLifecycleEvidence,
    GcpLoggingSinkUnknownRelevanceEvidence,
    GcpLoggingSinkUserManagedDeletionConstraintEvidence,
)
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.iam_reference_utils import (
    normalize_gcp_project,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_DELETE_SINK = "logging.sinks.delete"
_DENY_DELETE_SINK_PERMISSION = "logging.googleapis.com/sinks.delete"
_PUBLIC_ALL_PRINCIPAL_SET = "principalSet://goog/public:all"
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
_ACTIVE_CUSTOM_ROLE_STAGES = frozenset({"ALPHA", "BETA", "DEPRECATED", "EAP", "GA"})
_SINK_RESOURCE_NAME_PATTERN = re.compile(r"^projects/([^/]+)/sinks/([^/]+)$")
_NEGATIVE_FILTER_OPERATOR_PATTERN = re.compile(
    r"(?:\bnot\b|!=|!~|(?:^|[\s(])-\s*)",
    re.IGNORECASE,
)
_EXCLUSION_FIELD_UNCERTAINTY_PATTERN = re.compile(r"^exclusions\[\d+\]\.(?:filter|disabled)\b")
_SINK_RESOURCE_NAME_SEARCH = re.compile(r"(?:^|/)projects/(?P<project>[^/]+)/sinks/(?P<name>[^/?#]+)(?:$|[?#])")
_AUDIT_SECURITY_FILTER_PATTERNS = (
    (
        "cloudaudit.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?cloudaudit\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "google.cloud.audit.auditlog",
        re.compile(
            r'protopayload\.@type\s*(?::|=|=~)\s*(?:"(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog"|(?:type\.googleapis\.com/)?google\.cloud\.audit\.auditlog)(?=$|[\s)])'
        ),
    ),
    (
        "securitycenter.googleapis.com",
        re.compile(
            r'logname\s*(?::|=|=~)\s*(?:"(?:projects/[^"/\s]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^"]+)?"|(?:projects/[^\s()/]+/logs/)?securitycenter\.googleapis\.com(?:%2f[^\s()]+)?)'
        ),
    ),
    (
        "security_command_center",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"security_command_center"|security_command_center)(?=$|[\s)])'),
    ),
    (
        "securitycenter",
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"securitycenter"|securitycenter)(?=$|[\s)])'),
    ),
    (
        'resource.type="gce_firewall_rule"',
        re.compile(r'resource\.type\s*(?::|=|=~)\s*(?:"gce_firewall_rule"|gce_firewall_rule)(?=$|[\s)])'),
    ),
)
_BUILT_IN_ROLES: dict[
    str,
    Literal[
        "owner",
        "logging_admin",
        "logging_config_writer",
        "iam_devops",
        "iam_infrastructure_admin",
        "iam_network_admin",
    ],
] = {
    "roles/owner": "owner",
    "roles/logging.admin": "logging_admin",
    "roles/logging.configWriter": "logging_config_writer",
    "roles/iam.devOps": "iam_devops",
    "roles/iam.infrastructureAdmin": "iam_infrastructure_admin",
    "roles/iam.networkAdmin": "iam_network_admin",
}
_KNOWN_NON_DELETE_ROLES = frozenset(
    {
        "roles/editor",
        "roles/viewer",
        "roles/logging.bucketWriter",
        "roles/logging.fieldAccessor",
        "roles/logging.linkViewer",
        "roles/logging.logWriter",
        "roles/logging.privateLogViewer",
        "roles/logging.viewAccessor",
        "roles/logging.viewer",
        "roles/resourcemanager.projectIamAdmin",
    }
)

_ManagementMode = Literal[
    "authoritative_policy",
    "authoritative_role_binding",
    "additive_member",
]


@dataclass(frozen=True, slots=True)
class _CustomRoleLifecycle:
    resource_address: str
    project: str | None
    organization_id: str | None
    stage: str | None
    deleted: bool | None
    permissions: tuple[str, ...]
    permissions_state: str | None


@dataclass(frozen=True, slots=True)
class _LoggingSinkTarget:
    resource: NormalizedResource
    name: str
    resource_name: str
    project: str
    destination: str | None
    writer_identity: str | None
    unique_writer_identity: bool | None


@dataclass(frozen=True, slots=True)
class _IamManager:
    source_address: str
    project: str
    management_mode: _ManagementMode
    roles: tuple[str, ...]


class ModelCloudRunLoggingSinkAuditTelemetryDisruptionPathsStage:
    """Model deterministic Cloud Run authority to delete exact audit logging sinks."""

    name = "model_cloud_run_logging_sink_audit_telemetry_disruption_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        targets, target_uncertainties = _logging_sink_targets(resources)
        iam_resources = _iam_resources(resources)
        deny_policies = _iam_deny_policies(resources)
        custom_roles = build_gcp_custom_role_index(resources)
        project_organizations = _project_organizations(resources)

        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_logging_sink_audit_telemetry_disruption_paths(
                workload,
                targets,
                iam_resources,
                deny_policies,
                context,
                custom_roles,
                project_organizations,
            )
            uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in target_uncertainties)
            facts = gcp_facts(workload)
            facts.set_cloud_run_logging_sink_audit_telemetry_disruption_paths(paths)
            facts.extend_cloud_run_logging_sink_audit_telemetry_disruption_path_uncertainties(dedupe(uncertainties))


def current_cloud_run_logging_sink_audit_telemetry_disruption_paths(
    workload: NormalizedResource,
    logging_sink: NormalizedResource,
    resources: Sequence[NormalizedResource],
    context: GcpDecorationContext,
) -> list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath]:
    """Recompute every current deterministic proof for one workload and sink."""

    if (
        workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES
        or logging_sink.resource_type != GcpResourceType.LOGGING_PROJECT_SINK
    ):
        return []
    target = _logging_sink_target(logging_sink)
    if target is None:
        return []
    paths, _uncertainties = _cloud_run_logging_sink_audit_telemetry_disruption_paths(
        workload,
        (target,),
        _iam_resources(resources),
        _iam_deny_policies(resources),
        context,
        build_gcp_custom_role_index(resources),
        _project_organizations(resources),
    )
    return paths


def _cloud_run_logging_sink_audit_telemetry_disruption_paths(
    workload: NormalizedResource,
    targets: Sequence[_LoggingSinkTarget],
    iam_resources: Sequence[NormalizedResource],
    deny_policies: Sequence[NormalizedResource],
    context: GcpDecorationContext,
    custom_roles: GcpCustomRoleIndex,
    project_organizations: Mapping[str, str],
) -> tuple[list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath], list[str]]:
    del context
    workload_facts = gcp_facts(workload)
    service_account_email = _known_string(workload_facts.service_account_email)
    service_account_member = _known_string(workload_facts.service_account_member)
    if not _is_exact_service_account_identity(
        service_account_email,
        service_account_member,
    ):
        return [], [f"{workload.address}: Cloud Run service account is unresolved for logging-sink disruption modeling"]
    assert service_account_email is not None
    assert service_account_member is not None

    paths: list[GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        lifecycle = _logging_sink_lifecycle_evidence(target.resource)
        if lifecycle["lifecycle_compatibility_state"] != "compatible":
            if lifecycle["lifecycle_compatibility_state"] == "unknown":
                uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in lifecycle["uncertainties"])
            continue
        active_lifecycle = cast(GcpLoggingSinkActiveLifecycleEvidence, lifecycle)

        constraint = _logging_sink_deletion_constraint_evidence(target)
        if constraint["deletion_compatibility_state"] != "compatible":
            if constraint["deletion_compatibility_state"] == "unknown":
                uncertainties.extend(
                    f"{workload.address}: {uncertainty}" for uncertainty in constraint["uncertainties"]
                )
            continue
        user_managed_constraint = cast(
            GcpLoggingSinkUserManagedDeletionConstraintEvidence,
            constraint,
        )

        relevance = _logging_sink_audit_telemetry_relevance_evidence(target)
        if relevance["audit_telemetry_relevance_state"] != "established":
            if relevance["audit_telemetry_relevance_state"] == "unknown":
                uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in relevance["uncertainties"])
            continue
        established_relevance = cast(
            GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence,
            relevance,
        )
        destination = target.destination
        assert destination is not None

        deny_state, deny_uncertainties = _logging_sink_delete_deny_state(
            target,
            service_account_email,
            deny_policies,
            project_organizations,
        )
        if deny_state != "compatible":
            if deny_state == "unknown":
                uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in deny_uncertainties)
            continue

        ambiguous_project, ambiguous_roles, manager_uncertainties = _iam_manager_ambiguities(
            target,
            iam_resources,
            custom_roles,
        )
        uncertainties.extend(
            f"{workload.address}: {message} for {target.resource.address}" for message in manager_uncertainties
        )

        for iam_resource in iam_resources:
            iam_project, scope_uncertainty = _iam_project(iam_resource, target)
            if iam_project is None:
                if scope_uncertainty is not None and _iam_resource_may_affect_member(
                    iam_resource,
                    service_account_member,
                ):
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address} logging IAM "
                        f"project scope is unresolved for {target.resource.address}"
                    )
                continue

            source_facts = gcp_facts(iam_resource)
            if (
                iam_resource.resource_type == GcpResourceType.PROJECT_IAM_POLICY
                and source_facts.iam_policy_data_state != "configured"
            ):
                uncertainties.append(
                    f"{workload.address}: {iam_resource.address} IAM policy_data "
                    f"is {source_facts.iam_policy_data_state or 'unresolved'} for "
                    f"{target.resource.address}"
                )
                continue

            for binding in iam_bindings(iam_resource):
                source = iam_resource.address
                if binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown":
                    uncertainties.append(f"{workload.address}: {source} logging IAM role or members are unresolved")
                    continue
                if service_account_member not in binding_members(binding):
                    continue
                role = _known_string(binding.get("role"))
                if role is None:
                    uncertainties.append(f"{workload.address}: {source} logging IAM role is unresolved")
                    continue

                condition_uncertainty = _unconditional_binding_uncertainty(
                    binding,
                    target,
                )
                if condition_uncertainty is not None:
                    uncertainties.append(f"{workload.address}: {source} {condition_uncertainty}")
                    continue

                role_evidence, role_uncertainty = _role_evidence(
                    role,
                    target.project,
                    custom_roles,
                    project_organizations,
                )
                if role_evidence is None:
                    if role_uncertainty is not None:
                        uncertainties.append(f"{workload.address}: {source} {role_uncertainty}")
                    continue

                role_key = _role_reconciliation_key(role, custom_roles)
                if ambiguous_project or role_key in ambiguous_roles:
                    continue
                fingerprint = (
                    target.resource.address,
                    source,
                    role_key,
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(
                    _audit_telemetry_disruption_path(
                        workload,
                        target,
                        destination,
                        service_account_email,
                        service_account_member,
                        iam_resource,
                        role,
                        role_evidence,
                        active_lifecycle,
                        user_managed_constraint,
                        established_relevance,
                    )
                )

    paths.sort(
        key=lambda path: (
            path["logging_sink_address"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


def _logging_sink_targets(
    resources: Sequence[NormalizedResource],
) -> tuple[list[_LoggingSinkTarget], list[str]]:
    targets: list[_LoggingSinkTarget] = []
    uncertainties: list[str] = []
    for resource in resources:
        if resource.resource_type != GcpResourceType.LOGGING_PROJECT_SINK:
            continue
        target = _logging_sink_target(resource)
        if target is None:
            uncertainties.append(f"logging sink {resource.address} has unresolved exact project and sink identity")
            continue
        targets.append(target)
    return targets, uncertainties


def _logging_sink_target(
    logging_sink: NormalizedResource,
) -> _LoggingSinkTarget | None:
    if logging_sink.resource_type != GcpResourceType.LOGGING_PROJECT_SINK:
        return None
    facts = gcp_facts(logging_sink)
    if facts.logging_sink_scope_type != "project":
        return None
    project = normalize_gcp_project(facts.logging_sink_scope)
    raw_name = _known_string(facts.logging_sink_name)
    if project is None or raw_name is None:
        return None

    name = raw_name
    name_match = _SINK_RESOURCE_NAME_PATTERN.fullmatch(raw_name)
    if name_match is not None:
        if name_match.group(1) != project:
            return None
        name = name_match.group(2)
    if not name or "/" in name or "${" in name or name.startswith("google_"):
        return None

    resource_name = f"projects/{project}/sinks/{name}"
    identifier = _known_string(logging_sink.identifier)
    if identifier is not None:
        identifier_identity = _sink_identity_from_identifier(identifier)
        if identifier_identity is not None and identifier_identity != (project, name):
            return None
        if identifier.startswith("projects/") and identifier_identity is None:
            return None

    return _LoggingSinkTarget(
        logging_sink,
        name,
        resource_name,
        project,
        _known_string(facts.logging_sink_destination),
        _known_string(facts.logging_sink_writer_identity),
        facts.logging_sink_unique_writer_identity,
    )


def _sink_identity_from_identifier(value: str) -> tuple[str, str] | None:
    match = _SINK_RESOURCE_NAME_SEARCH.search(value)
    if match is None:
        return None
    return match.group("project"), match.group("name")


def _logging_sink_lifecycle_evidence(
    logging_sink: NormalizedResource,
) -> GcpLoggingSinkLifecycleEvidence:
    facts = gcp_facts(logging_sink)
    disabled_uncertainties = _field_uncertainties(
        facts.audit_security_posture_uncertainties,
        "disabled",
    )
    disabled = facts.logging_sink_disabled
    if disabled is True:
        evidence: GcpLoggingSinkDisabledLifecycleEvidence = {
            "lifecycle_evidence_scope": "plan_local_logging_sink_state",
            "disabled_configuration_state": "configured",
            "sink_disabled": True,
            "provider_default_applied": False,
            "sink_lifecycle_state": "disabled",
            "lifecycle_compatibility_state": "not_currently_disruptive",
            "uncertainties": [],
        }
        return evidence
    if disabled is False:
        active: GcpLoggingSinkActiveExplicitLifecycleEvidence = {
            "lifecycle_evidence_scope": "plan_local_logging_sink_state",
            "disabled_configuration_state": "configured",
            "sink_disabled": False,
            "provider_default_applied": False,
            "sink_lifecycle_state": "active",
            "lifecycle_compatibility_state": "compatible",
            "uncertainties": [],
        }
        return active
    if not disabled_uncertainties:
        default_active: GcpLoggingSinkActiveProviderDefaultLifecycleEvidence = {
            "lifecycle_evidence_scope": "plan_local_logging_sink_state",
            "disabled_configuration_state": "not_configured",
            "sink_disabled": False,
            "provider_default_applied": True,
            "sink_lifecycle_state": "active",
            "lifecycle_compatibility_state": "compatible",
            "uncertainties": [],
        }
        return default_active

    unknown: GcpLoggingSinkUnknownLifecycleEvidence = {
        "lifecycle_evidence_scope": "plan_local_logging_sink_state",
        "disabled_configuration_state": "unknown",
        "sink_disabled": None,
        "provider_default_applied": False,
        "sink_lifecycle_state": "unknown",
        "lifecycle_compatibility_state": "unknown",
        "uncertainties": disabled_uncertainties,
    }
    return unknown


def _logging_sink_deletion_constraint_evidence(
    target: _LoggingSinkTarget,
) -> GcpLoggingSinkDeletionConstraintEvidence:
    if target.name in {"_Default", "_Required"}:
        system: GcpLoggingSinkSystemManagedDeletionConstraintEvidence = {
            "constraint_evidence_scope": "gcp_logging_system_sink_deletion",
            "sink_kind": "system_managed",
            "system_sink_name": cast(
                Literal["_Default", "_Required"],
                target.name,
            ),
            "api_deletion_supported": False,
            "deletion_compatibility_state": "blocked",
            "uncertainties": [],
        }
        return system
    if not target.name:
        unknown: GcpLoggingSinkUnknownDeletionConstraintEvidence = {
            "constraint_evidence_scope": "gcp_logging_system_sink_deletion",
            "sink_kind": "unknown",
            "system_sink_name": None,
            "api_deletion_supported": None,
            "deletion_compatibility_state": "unknown",
            "uncertainties": [f"{target.resource.address}: logging sink kind is unresolved"],
        }
        return unknown

    user_managed: GcpLoggingSinkUserManagedDeletionConstraintEvidence = {
        "constraint_evidence_scope": "gcp_logging_system_sink_deletion",
        "sink_kind": "user_managed",
        "system_sink_name": None,
        "api_deletion_supported": True,
        "deletion_compatibility_state": "compatible",
        "uncertainties": [],
    }
    return user_managed


def _logging_sink_audit_telemetry_relevance_evidence(
    target: _LoggingSinkTarget,
) -> GcpLoggingSinkAuditTelemetryRelevanceEvidence:
    facts = gcp_facts(target.resource)
    destination_uncertainties = _field_uncertainties(
        facts.audit_security_posture_uncertainties,
        "destination",
    )
    filter_uncertainties = _field_uncertainties(
        facts.audit_security_posture_uncertainties,
        "filter",
    )
    exclusion_state, exclusion_uncertainties = _logging_sink_exclusion_relevance_state(target)
    if (
        target.destination is None
        or destination_uncertainties
        or filter_uncertainties
        or exclusion_state != "compatible"
    ):
        uncertainties = [
            *destination_uncertainties,
            *filter_uncertainties,
            *exclusion_uncertainties,
        ]
        if target.destination is None and not destination_uncertainties:
            uncertainties.append(f"{target.resource.address}: logging sink destination is not configured")
        unknown: GcpLoggingSinkUnknownRelevanceEvidence = {
            "relevance_evidence_scope": ("plan_local_logging_sink_filter_and_destination"),
            "filter_state": "unknown",
            "sink_filter": None,
            "relevance_basis": "unknown",
            "matched_audit_security_filter_signal": None,
            "matched_audit_security_filter_signals": [],
            "audit_telemetry_relevance_state": "unknown",
            "uncertainties": dedupe(uncertainties),
        }
        return unknown

    sink_filter = _known_string(facts.logging_sink_filter)
    if sink_filter is None:
        all_logs: GcpLoggingSinkAllLogsRelevanceEvidence = {
            "relevance_evidence_scope": ("plan_local_logging_sink_filter_and_destination"),
            "filter_state": "not_configured",
            "sink_filter": None,
            "relevance_basis": "all_logs",
            "matched_audit_security_filter_signal": None,
            "matched_audit_security_filter_signals": [],
            "audit_telemetry_relevance_state": "established",
            "uncertainties": [],
        }
        return all_logs

    matched_signals = _audit_security_filter_signals(sink_filter)
    if matched_signals:
        filtered: GcpLoggingSinkAuditFilterRelevanceEvidence = {
            "relevance_evidence_scope": ("plan_local_logging_sink_filter_and_destination"),
            "filter_state": "configured",
            "sink_filter": sink_filter,
            "relevance_basis": "audit_security_filter",
            "matched_audit_security_filter_signal": matched_signals[0],
            "matched_audit_security_filter_signals": matched_signals,
            "audit_telemetry_relevance_state": "established",
            "uncertainties": [],
        }
        return filtered

    irrelevant: GcpLoggingSinkIrrelevantFilterEvidence = {
        "relevance_evidence_scope": ("plan_local_logging_sink_filter_and_destination"),
        "filter_state": "configured",
        "sink_filter": sink_filter,
        "relevance_basis": "no_audit_security_filter_signal",
        "matched_audit_security_filter_signal": None,
        "matched_audit_security_filter_signals": [],
        "audit_telemetry_relevance_state": "not_established",
        "uncertainties": [],
    }
    return irrelevant


def _logging_sink_exclusion_relevance_state(
    target: _LoggingSinkTarget,
) -> tuple[Literal["compatible", "blocked", "unknown"], list[str]]:
    facts = gcp_facts(target.resource)
    uncertainties = _field_uncertainties(
        facts.audit_security_posture_uncertainties,
        "exclusions",
    )
    structural_uncertainties = [
        uncertainty for uncertainty in uncertainties if _EXCLUSION_FIELD_UNCERTAINTY_PATTERN.match(uncertainty) is None
    ]
    if structural_uncertainties:
        return "unknown", structural_uncertainties

    for index, exclusion in enumerate(facts.logging_sink_exclusions):
        disabled_state = exclusion.get("disabled_state")
        disabled = exclusion.get("disabled")
        if disabled_state == "unknown":
            return "unknown", [f"{target.resource.address}: exclusions[{index}].disabled is unresolved"]
        if disabled is True:
            continue
        if disabled is not False and disabled_state != "not_configured":
            return "unknown", [f"{target.resource.address}: exclusions[{index}].disabled is unresolved"]

        filter_state = exclusion.get("filter_state")
        exclusion_filter = _known_string(exclusion.get("filter"))
        if filter_state != "configured" or exclusion_filter is None:
            return "unknown", [f"{target.resource.address}: exclusions[{index}].filter is unresolved"]
        return "unknown", [
            f"{target.resource.address}: active exclusions[{index}] prevents "
            "deterministic audit/security export relevance"
        ]
    return "compatible", []


def _audit_security_filter_signals(filter_text: str) -> list[str]:
    normalized = _normalized_filter(filter_text)
    if _NEGATIVE_FILTER_OPERATOR_PATTERN.search(normalized):
        return []
    return [signal for signal, pattern in _AUDIT_SECURITY_FILTER_PATTERNS if pattern.fullmatch(normalized) is not None]


def _normalized_filter(filter_text: str) -> str:
    return " ".join(filter_text.lower().replace(chr(39), chr(34)).split())


def _logging_sink_delete_deny_state(
    target: _LoggingSinkTarget,
    service_account_email: str,
    deny_policies: Sequence[NormalizedResource],
    project_organizations: Mapping[str, str],
) -> tuple[Literal["compatible", "blocked", "unknown"], list[str]]:
    unknown_messages: list[str] = []
    for policy in deny_policies:
        scope_state = _deny_policy_scope_state(
            policy,
            target.project,
            project_organizations,
        )
        if scope_state == "incompatible":
            continue

        rule_state = _deny_policy_rule_state(policy, service_account_email)
        if rule_state == "compatible":
            continue
        if scope_state == "unknown":
            unknown_messages.append(
                f"{policy.address} IAM deny-policy applicability to {target.resource_name} is unresolved"
            )
            continue
        if rule_state == "blocked":
            return "blocked", []
        unknown_messages.append(
            f"{policy.address} IAM deny-policy effect on "
            f"{_DENY_DELETE_SINK_PERMISSION} for {target.resource_name} is unresolved"
        )

    if unknown_messages:
        return "unknown", dedupe(unknown_messages)
    return "compatible", []


def _deny_policy_scope_state(
    policy: NormalizedResource,
    target_project: str,
    project_organizations: Mapping[str, str],
) -> Literal["compatible", "incompatible", "unknown"]:
    facts = gcp_facts(policy)
    if facts.iam_deny_policy_parent_state != "configured":
        return "unknown"
    parent = _known_string(facts.iam_deny_policy_parent)
    if parent is None:
        return "unknown"
    scope = _deny_policy_parent_scope(parent)
    if scope is None:
        return "unknown"
    scope_type, scope_name = scope
    if scope_type == "projects":
        return "compatible" if scope_name == target_project else "incompatible"
    if scope_type == "organizations":
        target_organization = project_organizations.get(target_project)
        if target_organization is None:
            return "unknown"
        return "compatible" if scope_name == target_organization else "incompatible"
    return "unknown"


def _deny_policy_parent_scope(
    value: str,
) -> tuple[Literal["projects", "folders", "organizations"], str] | None:
    normalized = unquote(value).strip().lstrip("/")
    prefix = "cloudresourcemanager.googleapis.com/"
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix) :]
    parts = normalized.split("/")
    if len(parts) != 2 or parts[0] not in {"projects", "folders", "organizations"} or not parts[1]:
        return None
    return cast(
        tuple[Literal["projects", "folders", "organizations"], str],
        (parts[0], parts[1]),
    )


def _deny_policy_rule_state(
    policy: NormalizedResource,
    service_account_email: str,
) -> Literal["compatible", "blocked", "unknown"]:
    facts = gcp_facts(policy)
    unknown = facts.iam_deny_policy_completeness_state != "complete"
    for rule in facts.iam_deny_policy_rules:
        state = _deny_rule_state(rule, service_account_email)
        if state == "blocked":
            return "blocked"
        if state == "unknown":
            unknown = True
    return "unknown" if unknown else "compatible"


def _deny_rule_state(
    rule: Mapping[str, Any],
    service_account_email: str,
) -> Literal["compatible", "blocked", "unknown"]:
    denied_permissions = _deny_rule_values(rule, "denied_permissions")
    denied_permissions_state = _known_string(rule.get("denied_permissions_state"))
    if denied_permissions_state == "unknown":
        return "unknown"
    if denied_permissions is None:
        return "unknown"
    if not _deny_permission_matches(denied_permissions):
        return "compatible"

    exception_permissions = _deny_rule_values(rule, "exception_permissions")
    exception_permissions_state = _known_string(rule.get("exception_permissions_state"))
    if exception_permissions_state == "unknown":
        return "unknown"
    if exception_permissions is None:
        return "unknown"
    if _deny_permission_matches(exception_permissions):
        return "compatible"

    denied_principals = _deny_rule_values(rule, "denied_principals")
    denied_principals_state = _known_string(rule.get("denied_principals_state"))
    if denied_principals_state == "unknown":
        return "unknown"
    if denied_principals is None:
        return "unknown"
    principal_state = _deny_principal_match(
        denied_principals,
        service_account_email,
    )
    if principal_state == "not_matched":
        return "compatible"
    if principal_state == "unknown":
        return "unknown"

    exception_principals = _deny_rule_values(rule, "exception_principals")
    exception_principals_state = _known_string(rule.get("exception_principals_state"))
    if exception_principals_state == "unknown":
        return "unknown"
    if exception_principals is None:
        return "unknown"
    exception_state = _deny_principal_match(
        exception_principals,
        service_account_email,
    )
    if exception_state == "matched":
        return "compatible"
    if exception_state == "unknown":
        return "unknown"

    condition_state = _known_string(rule.get("condition_state"))
    if condition_state == "not_configured":
        return "blocked"
    return "unknown"


def _deny_rule_values(
    rule: Mapping[str, Any],
    key: str,
) -> tuple[str, ...] | None:
    value = rule.get(key)
    if not isinstance(value, list):
        return None
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        normalized.append(item.strip())
    return tuple(normalized)


def _deny_permission_matches(permissions: Sequence[str]) -> bool:
    return _DENY_DELETE_SINK_PERMISSION in permissions


def _deny_principal_match(
    principals: Sequence[str],
    service_account_email: str,
) -> Literal["matched", "not_matched", "unknown"]:
    runtime_principal = f"principal://iam.googleapis.com/projects/-/serviceAccounts/{service_account_email}"
    unknown = False
    for principal in principals:
        if principal in {runtime_principal, _PUBLIC_ALL_PRINCIPAL_SET}:
            return "matched"
        if principal.startswith("principal://"):
            continue
        unknown = True
    return "unknown" if unknown else "not_matched"


def _iam_manager_ambiguities(
    target: _LoggingSinkTarget,
    iam_resources: Sequence[NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[bool, set[str], list[str]]:
    managers: list[_IamManager] = []
    unresolved_managers: list[_IamManager] = []
    for iam_resource in iam_resources:
        project, scope_uncertainty = _iam_project(iam_resource, target)
        management_mode = _management_mode(iam_resource)
        bindings = iam_bindings(iam_resource)
        roles = _manager_role_keys(bindings, custom_roles)
        if project is None:
            if scope_uncertainty is not None and management_mode != "additive_member":
                unresolved_managers.append(
                    _IamManager(
                        iam_resource.address,
                        target.project,
                        management_mode,
                        roles,
                    )
                )
            continue
        managers.append(
            _IamManager(
                iam_resource.address,
                project,
                management_mode,
                roles,
            )
        )
        if management_mode != "additive_member" and _manager_has_unresolved_role(bindings):
            unresolved_managers.append(
                _IamManager(
                    iam_resource.address,
                    project,
                    management_mode,
                    roles,
                )
            )

    ambiguous_project = False
    ambiguous_roles: set[str] = set()
    uncertainties: list[str] = []
    policy_sources = {
        manager.source_address for manager in managers if manager.management_mode == "authoritative_policy"
    }
    other_sources = {
        manager.source_address for manager in managers if manager.management_mode != "authoritative_policy"
    }
    if len(policy_sources) > 1 or (policy_sources and other_sources):
        ambiguous_project = True
        uncertainties.append(
            f"effective logging IAM in project {target.project} is ambiguous "
            "because authoritative policy and other Terraform IAM managers overlap"
        )
    else:
        roles_at_project = sorted({role for manager in managers for role in manager.roles})
        for role in roles_at_project:
            binding_sources = {
                manager.source_address
                for manager in managers
                if (manager.management_mode == "authoritative_role_binding" and role in manager.roles)
            }
            member_sources = {
                manager.source_address
                for manager in managers
                if (manager.management_mode == "additive_member" and role in manager.roles)
            }
            if len(binding_sources) > 1 or (binding_sources and member_sources):
                ambiguous_roles.add(role)
                uncertainties.append(
                    f"effective logging IAM membership for role {role} in "
                    f"project {target.project} is ambiguous because authoritative "
                    "role bindings overlap with another Terraform IAM manager"
                )

    for manager in unresolved_managers:
        if manager.management_mode == "authoritative_policy" or not manager.roles:
            ambiguous_project = True
            uncertainties.append(
                f"effective logging IAM in project {target.project} is unresolved "
                f"because {manager.source_address} may be an overlapping "
                "authoritative IAM manager"
            )
            continue
        for role in manager.roles:
            ambiguous_roles.add(role)
            uncertainties.append(
                f"effective logging IAM membership for role {role} in project "
                f"{target.project} is unresolved because {manager.source_address} "
                "may be an overlapping authoritative IAM manager"
            )
    return ambiguous_project, ambiguous_roles, uncertainties


def _iam_project(
    iam_resource: NormalizedResource,
    target: _LoggingSinkTarget,
) -> tuple[str | None, str | None]:
    facts = gcp_facts(iam_resource)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return None, "scope reference is unresolved"
    project = normalize_gcp_project(facts.project)
    if project is None:
        return None, "project scope is unresolved"
    if project != target.project:
        return None, None
    return project, None


def _unconditional_binding_uncertainty(
    binding: Mapping[str, Any],
    target: _LoggingSinkTarget,
) -> str | None:
    if binding.get("condition_state") == "unknown":
        return f"IAM condition applicability to {target.resource_name} is unknown after planning"
    condition = binding.get("condition")
    if isinstance(condition, Mapping) and condition:
        return (
            f"IAM condition applicability to {target.resource_name} is not "
            "deterministic for project-scoped sink deletion"
        )
    if condition not in (None, {}, []):
        return f"IAM condition applicability to {target.resource_name} is unresolved"
    condition_state = binding.get("condition_state")
    if condition_state not in (None, "not_configured"):
        return f"IAM condition applicability to {target.resource_name} is unresolved"
    return None


def _role_evidence(
    role: str,
    target_project: str,
    custom_roles: GcpCustomRoleIndex,
    project_organizations: Mapping[str, str],
) -> tuple[GcpLoggingSinkRoleEvidence | None, str | None]:
    role_kind = _BUILT_IN_ROLES.get(role)
    if role_kind is not None:
        evidence: GcpLoggingSinkBuiltInRoleEvidence = {
            "role_kind": role_kind,
            "role_definition_address": None,
            "custom_role_permissions": [],
            "custom_role_stage": None,
            "custom_role_deleted": None,
            "custom_role_wildcard_permissions_present": False,
            "custom_role_grant_scope_compatibility_state": "not_applicable",
        }
        return evidence, None

    if role in _KNOWN_NON_DELETE_ROLES:
        return None, None
    if role.startswith("roles/"):
        return (
            None,
            f"predefined IAM role {role} logging sink-deletion coverage is unmodeled",
        )
    if not _looks_like_custom_role(role):
        return None, f"custom IAM role {role} is unresolved"

    resolution = custom_roles.resolve(role)
    if resolution.state == "ambiguous":
        return (
            None,
            f"custom IAM role reference {role} collides across multiple role definitions",
        )
    role_definition = resolution.selected_candidate
    if role_definition is None:
        return None, f"custom IAM role {role} exact identity is unresolved"
    lifecycle = _custom_role_lifecycle(role_definition)
    if lifecycle.deleted is True:
        return None, None
    if lifecycle.deleted is None:
        return None, f"custom IAM role {role} deletion state is unresolved"
    if lifecycle.stage is None:
        return None, f"custom IAM role {role} lifecycle stage is unresolved"
    stage = lifecycle.stage.upper()
    if stage == "DISABLED":
        return None, None
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return (
            None,
            f"custom IAM role {role} lifecycle stage {stage} is unsupported",
        )
    if lifecycle.permissions_state in {None, "unknown"}:
        return None, f"custom IAM role {role} permissions are unresolved"
    wildcard_permissions = tuple(permission for permission in lifecycle.permissions if "*" in permission)
    if wildcard_permissions:
        return (
            None,
            f"custom IAM role {role} contains unsupported wildcard permission(s): {', '.join(wildcard_permissions)}",
        )
    if _DELETE_SINK not in lifecycle.permissions:
        return None, None

    compatibility = _custom_role_grant_scope_compatibility(
        lifecycle,
        target_project,
        project_organizations,
    )
    if compatibility == "incompatible":
        return (
            None,
            f"custom IAM role {role} is not grantable in target project {target_project}",
        )
    if compatibility == "unknown":
        return (
            None,
            f"custom IAM role {role} grant scope compatibility is unresolved for target project {target_project}",
        )

    custom_evidence: GcpLoggingSinkCustomRoleEvidence = {
        "role_kind": "custom",
        "role_definition_address": lifecycle.resource_address,
        "custom_role_permissions": list(lifecycle.permissions),
        "custom_role_stage": cast(
            GcpLoggingSinkActiveCustomRoleStage,
            stage,
        ),
        "custom_role_deleted": False,
        "custom_role_wildcard_permissions_present": False,
        "custom_role_grant_scope_compatibility_state": "compatible",
    }
    return custom_evidence, None


def _audit_telemetry_disruption_path(
    workload: NormalizedResource,
    target: _LoggingSinkTarget,
    destination: str,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    role: str,
    role_evidence: GcpLoggingSinkRoleEvidence,
    lifecycle: GcpLoggingSinkActiveLifecycleEvidence,
    constraint: GcpLoggingSinkUserManagedDeletionConstraintEvidence,
    relevance: GcpLoggingSinkEstablishedAuditTelemetryRelevanceEvidence,
) -> GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath:
    role_definition_address = role_evidence["role_definition_address"]
    iam_source_addresses = [iam_resource.address]
    if role_definition_address is not None:
        iam_source_addresses.append(role_definition_address)

    path: GcpCloudRunLoggingSinkAuditTelemetryDisruptionPath = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "logging_sink_address": target.resource.address,
        "logging_sink_resource_type": target.resource.resource_type,
        "logging_sink_name": target.name,
        "logging_sink_resource_name": target.resource_name,
        "logging_sink_project": target.project,
        "logging_sink_destination": destination,
        "logging_sink_writer_identity": target.writer_identity,
        "logging_sink_unique_writer_identity": target.unique_writer_identity,
        "operation": "logging.sinks.delete",
        "operation_class": "project_sink_deletion",
        "internal_operation": "delete_project_logging_sink",
        "management_effect": "audit_telemetry_disruption",
        "target_granularity": "project_logging_sink",
        "target_scope": "exact_project_logging_sink",
        "target_model_evidence_addresses": [target.resource.address],
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "iam_source_addresses": iam_source_addresses,
        "role": role,
        "role_evidence": role_evidence,
        "scope_type": "project",
        "scope": target.project,
        "resource_scope": "logging_project",
        "grant_basis": "logging_project_iam",
        "matched_permissions": ["logging.sinks.delete"],
        "authorization_state": "granted",
        "policy_complete": True,
        "iam_manager_ambiguity_state": "not_detected",
        "condition": None,
        "condition_state": "not_configured",
        "condition_evaluation": "not_configured",
        "lifecycle_compatibility_state": "compatible",
        "lifecycle_evidence": lifecycle,
        "deletion_constraint_evidence": constraint,
        "audit_telemetry_relevance_evidence": relevance,
        "outcome_evidence": {
            "outcome_evidence_scope": ("plan_local_project_logging_sink_deletion_authority"),
            "successful_operation_observed": False,
            "historical_log_entry_deletion_authorized_by_operation": False,
            "historical_log_entry_deletion_observed": False,
            "destination_resource_deletion_authorized_by_operation": False,
            "destination_resource_deletion_observed": False,
            "unique_writer_identity_side_effect_evaluated": False,
            "all_project_audit_sinks_evaluated": False,
            "out_of_plan_sinks_evaluated": False,
            "telemetry_recovery_state": ("not_established_by_modeled_gcp_logging_sink_evidence"),
            "restoration_observed": False,
            "uncertainties": [],
        },
        "posture_uncertainties": [],
    }
    return path


def _custom_role_lifecycle(resource: NormalizedResource) -> _CustomRoleLifecycle:
    facts = gcp_facts(resource)
    return _CustomRoleLifecycle(
        resource.address,
        normalize_gcp_project(facts.project),
        _normalize_organization(facts.organization_id),
        facts.custom_role_stage,
        facts.custom_role_deleted,
        tuple(sorted(set(facts.custom_role_permissions))),
        facts.custom_role_permissions_state,
    )


def _project_organizations(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, str]:
    organizations: dict[str, str] = {}
    for resource in resources:
        if resource.resource_type != GcpResourceType.PROJECT:
            continue
        facts = gcp_facts(resource)
        project = normalize_gcp_project(facts.project)
        organization = _normalize_organization(facts.organization_id)
        if project is not None and organization is not None:
            organizations.setdefault(project, organization)
    return organizations


def _custom_role_grant_scope_compatibility(
    lifecycle: _CustomRoleLifecycle,
    target_project: str,
    project_organizations: Mapping[str, str],
) -> Literal["compatible", "incompatible", "unknown"]:
    if lifecycle.project is not None:
        return "compatible" if lifecycle.project == target_project else "incompatible"
    if lifecycle.organization_id is None:
        return "unknown"
    target_organization = project_organizations.get(target_project)
    if target_organization is None:
        return "unknown"
    return "compatible" if target_organization == lifecycle.organization_id else "incompatible"


def _role_reconciliation_key(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> str:
    normalized = gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES)
    resolution = custom_roles.resolve(role)
    role_definition = resolution.selected_candidate
    if role_definition is not None:
        return f"custom:{role_definition.address}"
    if resolution.state == "ambiguous":
        return f"ambiguous-custom:{normalized}"
    return f"role:{normalized}"


def _manager_role_keys(
    bindings: Sequence[Mapping[str, Any]],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _role_reconciliation_key(role, custom_roles)
                for binding in bindings
                if binding.get("role_state") != "unknown" and (role := _known_string(binding.get("role"))) is not None
            }
        )
    )


def _manager_has_unresolved_role(
    bindings: Sequence[Mapping[str, Any]],
) -> bool:
    return any(
        binding.get("role_state") == "unknown" or _known_string(binding.get("role")) is None for binding in bindings
    )


def _iam_resource_may_affect_member(
    resource: NormalizedResource,
    member: str,
) -> bool:
    if _management_mode(resource) != "additive_member":
        return True
    return any(
        binding.get("members_state") == "unknown" or member in binding_members(binding)
        for binding in iam_bindings(resource)
    )


def _management_mode(resource: NormalizedResource) -> _ManagementMode:
    if resource.resource_type == GcpResourceType.PROJECT_IAM_POLICY:
        return "authoritative_policy"
    if resource.resource_type == GcpResourceType.PROJECT_IAM_BINDING:
        return "authoritative_role_binding"
    return "additive_member"


def _iam_deny_policies(
    resources: Sequence[NormalizedResource],
) -> tuple[NormalizedResource, ...]:
    return tuple(resource for resource in resources if resource.resource_type == GcpResourceType.IAM_DENY_POLICY)


def _iam_resources(
    resources: Sequence[NormalizedResource],
) -> tuple[NormalizedResource, ...]:
    return tuple(resource for resource in resources if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES)


def _field_uncertainties(
    uncertainties: Sequence[str],
    field: str,
) -> list[str]:
    return [
        uncertainty
        for uncertainty in uncertainties
        if uncertainty == field
        or uncertainty.startswith(f"{field} ")
        or uncertainty.startswith(f"{field}.")
        or uncertainty.startswith(f"{field}[")
    ]


def _is_exact_service_account_identity(
    email: str | None,
    member: str | None,
) -> bool:
    return bool(
        email
        and member == f"serviceAccount:{email}"
        and "@" in email
        and email.endswith(_SERVICE_ACCOUNT_DOMAIN)
        and "${" not in email
        and not ("google_" in email and "." in email)
    )


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_organization(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    if text.startswith("organizations/"):
        return text.removeprefix("organizations/") or None
    return text


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or ("iam_custom_role." in role)
