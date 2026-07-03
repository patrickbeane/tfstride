from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AZURE_COMPUTE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references

_AZURE_WORKLOAD_RESOURCE_TYPES = tuple(sorted(AZURE_COMPUTE_RESOURCE_TYPES | AZURE_APP_SERVICE_RESOURCE_TYPES))


class AzureManagedIdentityRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_broad_rbac(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for identity in _managed_identity_resources(context.inventory):
            facts = azure_facts(identity)
            assignments = [
                assignment
                for assignment in facts.managed_identity_role_assignments
                if _is_broad_managed_identity_assignment(assignment)
            ]
            if not assignments:
                continue
            signals = _assignment_breadth_signals(assignments)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=3 if "broad_builtin_role" in signals else 2,
                data_sensitivity=2 if "sensitive_resource_scope" in signals else 1,
                lateral_movement=1,
                blast_radius=2 if "subscription_scope" in signals else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            identity.address,
                            *_assignment_values(assignments, "source"),
                            *_assignment_values(assignments, "target_resource_address"),
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{identity.display_name} has Azure role assignments with broad scope or high-impact "
                        "built-in roles. These grants expand what the managed identity can do if the workload "
                        "or deployment path using it is compromised."
                    ),
                    evidence=collect_evidence(
                        evidence_item("managed_identity", _managed_identity_evidence(identity)),
                        evidence_item("role_assignments", _describe_role_assignments(assignments)),
                        evidence_item("breadth_signals", signals),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_workload_sensitive_resource_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        public_workloads_by_identity = _public_workloads_by_identity_address(context.inventory)
        findings: list[Finding] = []
        for identity in _managed_identity_resources(context.inventory):
            public_workloads = public_workloads_by_identity.get(identity.address, [])
            if not public_workloads:
                continue
            assignments = [
                assignment
                for assignment in azure_facts(identity).managed_identity_role_assignments
                if _assignment_grants_sensitive_resource_access(assignment)
            ]
            if not assignments:
                continue
            boundary = _first_public_workload_boundary(public_workloads, context)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=3 if "broad_builtin_role" in _assignment_breadth_signals(assignments) else 2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            *(workload.address for workload in public_workloads),
                            *([] if identity in public_workloads else [identity.address]),
                            *_assignment_values(assignments, "source"),
                            *_assignment_values(assignments, "target_resource_address"),
                        ]
                    ),
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{identity.display_name} is usable by an internet-exposed Azure workload and has a "
                        "deterministic role assignment to a sensitive Azure resource. This creates a clear "
                        "public workload to sensitive resource path if the workload identity is abused."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_workloads", _public_workload_evidence(public_workloads)),
                        evidence_item("managed_identity", _managed_identity_evidence(identity)),
                        evidence_item("sensitive_resource_assignments", _describe_role_assignments(assignments)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _managed_identity_resources(inventory) -> list[Any]:
    return inventory.by_type(*_AZURE_WORKLOAD_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY)


def _is_broad_managed_identity_assignment(assignment: Mapping[str, Any]) -> bool:
    if not _assignment_has_known_role_and_principal(assignment):
        return False
    return bool(
        _assignment_breadth_signal_set(assignment)
        & {"broad_builtin_role", "subscription_scope", "resource_group_scope"}
    )


def _assignment_grants_sensitive_resource_access(assignment: Mapping[str, Any]) -> bool:
    if not _assignment_has_known_role_and_principal(assignment):
        return False
    if "sensitive_resource_scope" not in _assignment_breadth_signal_set(assignment):
        return False
    return _role_name(assignment) in _SENSITIVE_RESOURCE_ACCESS_ROLE_NAMES


def _assignment_has_known_role_and_principal(assignment: Mapping[str, Any]) -> bool:
    return bool(
        assignment.get("principal_id")
        and (assignment.get("role_definition_name") or assignment.get("role_definition_id"))
    )


def _assignment_breadth_signal_set(assignment: Mapping[str, Any]) -> set[str]:
    return {str(signal) for signal in assignment.get("breadth_signals", []) if signal}


def _assignment_breadth_signals(assignments: list[Mapping[str, Any]]) -> list[str]:
    return _dedupe_strings(
        signal for assignment in assignments for signal in assignment.get("breadth_signals", []) if signal
    )


def _assignment_values(assignments: list[Mapping[str, Any]], key: str) -> list[str]:
    return _dedupe_strings(str(assignment[key]) for assignment in assignments if assignment.get(key))


def _describe_role_assignments(assignments: list[Mapping[str, Any]]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"source={assignment.get('source')}",
                f"role={assignment.get('role_definition_name') or assignment.get('role_definition_id')}",
                f"scope={assignment.get('scope')}",
                f"scope_kind={assignment.get('scope_kind')}",
                f"target={assignment.get('target_resource_address')}",
                f"signals={','.join(str(signal) for signal in assignment.get('breadth_signals', []))}",
            )
            if part and not part.endswith("=None") and not part.endswith("=")
        )
        for assignment in assignments
    ]


def _managed_identity_evidence(identity) -> list[str]:
    facts = azure_facts(identity)
    return [
        value
        for value in (
            f"address={identity.address}",
            f"identity_type={facts.identity_type}" if facts.identity_type else None,
            f"principal_id={facts.principal_id}" if facts.principal_id else None,
            f"client_id={facts.client_id}" if facts.client_id else None,
        )
        if value
    ]


def _public_workloads_by_identity_address(inventory) -> dict[str, list[Any]]:
    identity_by_reference = _identity_resources_by_reference(inventory)
    public_workloads_by_identity: dict[str, list[Any]] = {}
    for workload in inventory.by_type(*_AZURE_WORKLOAD_RESOURCE_TYPES):
        if not _is_public_workload(workload):
            continue
        facts = azure_facts(workload)
        if facts.has_system_assigned_identity and facts.principal_id:
            public_workloads_by_identity.setdefault(workload.address, []).append(workload)
        for reference in facts.attached_identity_references:
            identity = identity_by_reference.get(azure_reference_key(reference))
            if identity is None:
                continue
            _append_unique_resource(public_workloads_by_identity.setdefault(identity.address, []), workload)
    return public_workloads_by_identity


def _identity_resources_by_reference(inventory) -> dict[str, Any]:
    references: dict[str, Any] = {}
    for identity in inventory.by_type(AzureResourceType.USER_ASSIGNED_IDENTITY):
        for reference in azure_resource_references(identity):
            references.setdefault(reference, identity)
    return references


def _is_public_workload(workload: Any) -> bool:
    if workload.resource_type in AZURE_COMPUTE_RESOURCE_TYPES:
        return bool(workload.public_exposure)
    if workload.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
        return azure_facts(workload).public_network_access_enabled is True
    return False


def _append_unique_resource(resources: list[Any], resource: Any) -> None:
    if all(existing.address != resource.address for existing in resources):
        resources.append(resource)


def _public_workload_evidence(workloads: list[Any]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"address={workload.address}",
                "public_exposure=true" if workload.public_exposure else None,
                "public_network_access_enabled=true"
                if azure_facts(workload).public_network_access_enabled is True
                else None,
                f"public_exposure_reasons={','.join(workload.public_exposure_reasons)}"
                if workload.public_exposure_reasons
                else None,
            )
            if part
        )
        for workload in workloads
    ]


def _first_public_workload_boundary(public_workloads: list[Any], context: RuleEvaluationContext):
    for workload in public_workloads:
        boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", workload.address))
        if boundary is not None:
            return boundary
    return None


def _role_name(assignment: Mapping[str, Any]) -> str:
    return str(assignment.get("role_definition_name") or "").strip().lower()


def _dedupe_strings(values) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            deduped.append(text)
            seen.add(text)
    return deduped


_SENSITIVE_RESOURCE_ACCESS_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault administrator",
        "key vault certificates officer",
        "key vault crypto officer",
        "key vault data access administrator",
        "key vault secrets officer",
        "owner",
        "storage account contributor",
        "storage blob data contributor",
        "storage blob data owner",
    }
)
