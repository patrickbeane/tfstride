from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)


class AzureAppServiceContainerRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_container_image_not_digest_pinned(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            for image_reference in facts.container_image_references:
                if not _is_resolved_unpinned_reference(image_reference):
                    continue

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=0,
                    data_sensitivity=0,
                    lateral_movement=0,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[app.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{app.display_name} deploys container image "
                            f"{image_reference.get('raw') or 'with an unresolved image value'} without a digest pin. "
                            "A tag or registry resolution can change the artifact selected by a future deployment; "
                            "pin deployment images to immutable digests for reproducible workload integrity."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(app)),
                            evidence_item("image_reference", _image_reference_evidence(image_reference)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_container_image_self_modification_path(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            for write_path in azure_facts(app).acr_write_paths:
                if not _is_reportable_acr_self_modification_path(write_path):
                    continue

                registry = _resource_by_address(
                    context,
                    write_path.get("container_registry_address"),
                    expected_type=AzureResourceType.CONTAINER_REGISTRY,
                )
                identity = _resource_by_address(
                    context,
                    write_path.get("identity_address"),
                    expected_types=(
                        *AZURE_APP_SERVICE_RESOURCE_TYPES,
                        AzureResourceType.USER_ASSIGNED_IDENTITY,
                    ),
                )
                role_assignment = _resource_by_address(
                    context,
                    write_path.get("role_assignment_address"),
                    expected_type=AzureResourceType.ROLE_ASSIGNMENT,
                )
                if registry is None or identity is None or role_assignment is None:
                    continue

                affected_resources = [app.address, registry.address]
                if identity.address != app.address:
                    affected_resources.append(identity.address)
                affected_resources.append(role_assignment.address)
                role_definition = _resource_by_address(
                    context,
                    write_path.get("role_definition_address"),
                    expected_type=AzureResourceType.ROLE_DEFINITION,
                )
                if write_path.get("role_definition_address") and role_definition is None:
                    continue
                if role_definition is not None:
                    affected_resources.append(role_definition.address)

                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=1,
                    data_sensitivity=1,
                    lateral_movement=2,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{app.display_name} deploys the unpinned ACR image "
                            f"{write_path.get('image_reference')} from {registry.display_name}, and its runtime "
                            f"managed identity has modeled registry content-write access through "
                            f"{write_path.get('role_definition_name') or 'an Azure role assignment'}. A compromised "
                            "workload can publish a replacement artifact selected by a future deployment, creating "
                            "a self-modification and persistence path."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(app)),
                            evidence_item("image_reference", _acr_write_path_image_evidence(write_path)),
                            evidence_item("runtime_identity", _acr_write_path_identity_evidence(write_path)),
                            evidence_item("acr_write_path", _acr_write_path_evidence(write_path)),
                            evidence_item("container_registry", _acr_registry_evidence(write_path)),
                            evidence_item(
                                "custom_role_permissions",
                                _custom_role_permission_evidence(write_path),
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _target_resource_evidence(app: NormalizedResource) -> list[str]:
    return [f"address={app.address}", f"type={app.resource_type}"]


def _resource_by_address(
    context: RuleEvaluationContext,
    address: object,
    *,
    expected_type: str | None = None,
    expected_types: tuple[str, ...] = (),
) -> NormalizedResource | None:
    if not isinstance(address, str) or not address:
        return None
    resource = context.inventory.get_by_address(address)
    if resource is None:
        return None
    allowed_types = expected_types or ((expected_type,) if expected_type is not None else ())
    if allowed_types and resource.resource_type not in allowed_types:
        return None
    return resource


def _is_reportable_acr_self_modification_path(path: Mapping[str, Any]) -> bool:
    return (
        path.get("grant_basis")
        in {
            "azure_registry_scoped_rbac",
            "azure_custom_role_registry_scoped_rbac",
        }
        and path.get("registry_scope") == "exact_container_registry"
        and path.get("role_kind") in {"writer", "custom_writer"}
        and path.get("image_digest_pinned") is False
        and isinstance(path.get("image_reference"), str)
        and bool(path.get("image_reference"))
    )


def _acr_write_path_image_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"raw={path.get('image_reference') or 'unknown'}",
        f"path={path.get('image_reference_path') or 'unknown'}",
        f"tag={path.get('image_tag') or 'unset'}",
        f"digest={path.get('image_digest') or 'unset'}",
        f"digest_pinned={path.get('image_digest_pinned')}",
    ]


def _acr_write_path_identity_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"identity_address={path.get('identity_address') or 'unknown'}",
        f"identity_kind={path.get('identity_kind') or 'unknown'}",
        f"principal_id={path.get('principal_id') or 'unknown'}",
        f"role_definition_name={path.get('role_definition_name') or 'unknown'}",
        f"role_kind={path.get('role_kind') or 'unknown'}",
    ]


def _acr_write_path_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"role_assignment_address={path.get('role_assignment_address') or 'unknown'}",
        f"role_definition_id={path.get('role_definition_id') or 'unknown'}",
        f"grant_basis={path.get('grant_basis') or 'unknown'}",
        f"registry_scope={path.get('registry_scope') or 'unknown'}",
    ]


def _acr_registry_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"address={path.get('container_registry_address') or 'unknown'}",
        f"id={path.get('container_registry_id') or 'unknown'}",
        f"login_server={path.get('container_registry_login_server') or 'unknown'}",
    ]


def _custom_role_permission_evidence(path: Mapping[str, Any]) -> list[str]:
    role_definition_address = path.get("role_definition_address")
    if not role_definition_address:
        return []
    return [
        f"role_definition_address={role_definition_address}",
        f"permission_patterns={path.get('permission_patterns') or []}",
        f"not_permission_patterns={path.get('not_permission_patterns') or []}",
        f"matched_write_actions={path.get('matched_write_actions') or []}",
    ]


def _is_resolved_unpinned_reference(reference: Mapping[str, Any]) -> bool:
    return reference.get("is_resolved") is True and reference.get("digest_pinned") is False


def _image_reference_evidence(reference: Mapping[str, Any]) -> list[str]:
    return [
        f"source={reference.get('source') or 'unknown'}",
        f"path={reference.get('path') or 'unknown'}",
        f"raw={reference.get('raw') or 'unknown'}",
        f"registry_host={reference.get('registry_host') or 'implicit'}",
        f"repository={reference.get('repository') or 'unknown'}",
        f"tag={reference.get('tag') or 'unset'}",
        f"digest={reference.get('digest') or 'unset'}",
        f"digest_pinned={reference.get('digest_pinned')}",
        f"container_registry_login_server={reference.get('container_registry_login_server') or 'unset'}",
    ]
