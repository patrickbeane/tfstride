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
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)

_MUTATION_ACCESS_CLASSES = frozenset({"write", "delete", "administrative"})
_MUTATING_ROLE_KINDS = frozenset({"blob_data_contributor", "blob_data_owner", "custom"})
_STORAGE_TARGET_TYPES = (
    AzureResourceType.STORAGE_ACCOUNT,
    AzureResourceType.STORAGE_CONTAINER,
)
_STORAGE_GRANT_BASES = frozenset(
    {
        "azure_storage_scoped_rbac",
        "azure_custom_role_storage_scoped_rbac",
    }
)


class AzureAppServiceStorageRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_storage_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            if facts.public_network_access_enabled is not True:
                continue

            mutation_paths = [
                path
                for path in facts.app_service_storage_access_paths
                if _is_deterministic_mutation_path(path, app, context)
            ]
            if not mutation_paths:
                continue

            storage_targets = _path_string_values(mutation_paths, "storage_resource_address")
            storage_accounts = _path_string_values(mutation_paths, "storage_account_address")
            identity_addresses = _path_string_values(mutation_paths, "identity_address")
            assignment_addresses = _path_string_values(mutation_paths, "role_assignment_address")
            role_definition_addresses = _path_string_values(mutation_paths, "role_definition_address")
            mutation_classes = _mutation_classes(mutation_paths)
            has_read_access = _has_deterministic_read_access(
                facts.app_service_storage_access_paths,
                set(storage_targets),
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if {"delete", "administrative"} & set(mutation_classes) else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(storage_targets) > 1 else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *storage_accounts,
                            *storage_targets,
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_mutation_rationale(
                        app,
                        mutation_classes,
                        storage_targets,
                        has_read_access=has_read_access,
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_endpoint", _public_endpoint_evidence(app)),
                        evidence_item("runtime_identity", _runtime_identity_evidence(mutation_paths)),
                        evidence_item("storage_mutation_paths", _mutation_path_evidence(mutation_paths)),
                        evidence_item("custom_role_permissions", _custom_role_permission_evidence(mutation_paths)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("grant_basis") not in _STORAGE_GRANT_BASES
        or path.get("evaluation_basis") != "modeled_rbac_assignment"
        or path.get("resource_scope") not in {"exact_storage_account", "exact_storage_container"}
        or path.get("assignment_scope_kind") != "resource"
        or path.get("access_state") != "granted"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("role_kind") not in _MUTATING_ROLE_KINDS
        or not _path_mutation_classes(path)
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    storage_address = _known_string(path.get("storage_resource_address"))
    assignment_address = _known_string(path.get("role_assignment_address"))
    role_name = _known_string(path.get("role_definition_name"))
    if not all((identity_address, principal_id, storage_address, assignment_address, role_name)):
        return False

    identity = _resource_by_address(
        context,
        identity_address,
        expected_types=(
            *AZURE_APP_SERVICE_RESOURCE_TYPES,
            AzureResourceType.USER_ASSIGNED_IDENTITY,
        ),
    )
    storage_target = _resource_by_address(
        context,
        storage_address,
        expected_types=_STORAGE_TARGET_TYPES,
    )
    role_assignment = _resource_by_address(
        context,
        assignment_address,
        expected_type=AzureResourceType.ROLE_ASSIGNMENT,
    )
    if identity is None or storage_target is None or role_assignment is None:
        return False
    if path.get("identity_kind") == "system_assigned" and identity.address != app.address:
        return False
    if (
        path.get("identity_kind") == "user_assigned"
        and identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
    ):
        return False
    if path.get("storage_resource_type") != storage_target.resource_type:
        return False

    storage_account_address = _known_string(path.get("storage_account_address"))
    if (
        storage_account_address is not None
        and _resource_by_address(
            context,
            storage_account_address,
            expected_type=AzureResourceType.STORAGE_ACCOUNT,
        )
        is None
    ):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if (
        role_definition_address is not None
        and _resource_by_address(
            context,
            role_definition_address,
            expected_type=AzureResourceType.ROLE_DEFINITION,
        )
        is None
    ):
        return False
    if path.get("role_kind") == "custom" and (
        role_definition_address is None or not _string_values(path.get("matched_data_actions"))
    ):
        return False
    return True


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


def _mutation_rationale(
    app: NormalizedResource,
    mutation_classes: list[str],
    storage_targets: list[str],
    *,
    has_read_access: bool,
) -> str:
    rationale = (
        f"{app.display_name} has public network access enabled and its runtime managed identity has deterministic "
        f"{', '.join(mutation_classes)} access to {len(storage_targets)} exact modeled Azure Blob Storage target(s). "
        "A compromise through an allowed public application path could tamper with stored blob data by "
        f"{_mutation_impact(mutation_classes)} within the modeled grants. "
        "This path does not mean that the Storage Account or container itself is public; configured App Service "
        "access restrictions may still narrow which clients can reach the endpoint."
    )
    if not has_read_access:
        rationale += (
            " The modeled grant is write-only: it represents tampering risk and does not establish read access "
            "or information disclosure."
        )
    return rationale


def _mutation_impact(mutation_classes: list[str]) -> str:
    impacts = {
        "write": "writing blobs",
        "delete": "deleting blobs or blob versions",
        "administrative": "changing blob ownership or permissions",
    }
    values = [impacts[access_class] for access_class in mutation_classes]
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + f", or {values[-1]}"


def _has_deterministic_read_access(
    paths: list[dict[str, Any]],
    storage_addresses: set[str],
) -> bool:
    return any(
        path.get("storage_resource_address") in storage_addresses
        and path.get("access_state") == "granted"
        and path.get("condition_state") == "not_configured"
        and "read" in _string_values(path.get("access_classes"))
        for path in paths
    )


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in ("write", "delete", "administrative") if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    return [
        access_class
        for access_class in _string_values(path.get("access_classes"))
        if access_class in _MUTATION_ACCESS_CLASSES
    ]


def _path_string_values(paths: list[dict[str, Any]], key: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(key))) is not None})


def _public_endpoint_evidence(app: NormalizedResource) -> list[str]:
    facts = azure_facts(app)
    return [
        f"address={app.address}",
        f"type={app.resource_type}",
        "public_network_access_enabled=true",
        f"public_network_fallback_state={facts.public_network_fallback_state or 'unknown'}",
        f"ip_restriction_default_action={facts.app_service_ip_restriction_default_action or 'not_configured'}",
        f"ip_restriction_count={len(facts.app_service_access_restrictions)}",
    ]


def _runtime_identity_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path['identity_address']}",
                    f"identity_kind={path['identity_kind']}",
                    f"principal_id={path['principal_id']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    "credential_context=workload_runtime",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"storage_resource_address={path['storage_resource_address']}",
                    f"storage_resource_type={path['storage_resource_type']}",
                    f"storage_resource_id={path.get('storage_resource_id') or 'unknown'}",
                    f"storage_account_address={path.get('storage_account_address') or 'unknown'}",
                    f"container_address={path.get('container_address') or 'not_applicable'}",
                    f"role_assignment_address={path['role_assignment_address']}",
                    f"role_definition_name={path['role_definition_name']}",
                    f"role_kind={path['role_kind']}",
                    f"mutation_classes={','.join(_path_mutation_classes(path))}",
                    f"access_classes={','.join(_string_values(path.get('access_classes')))}",
                    f"assignment_scope={path.get('assignment_scope') or 'unknown'}",
                    f"resource_scope={path['resource_scope']}",
                    f"grant_basis={path['grant_basis']}",
                    "access_state=granted",
                    "condition_state=not_configured",
                )
            )
            for path in paths
        }
    )


def _custom_role_permission_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"role_definition_address={path['role_definition_address']}",
                    f"data_actions={','.join(_string_values(path.get('custom_role_data_actions')))}",
                    f"not_data_actions={','.join(_string_values(path.get('custom_role_not_data_actions'))) or 'none'}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')))}",
                    f"excluded_data_actions={','.join(_string_values(path.get('excluded_data_actions'))) or 'none'}",
                )
            )
            for path in paths
            if path.get("role_kind") == "custom" and path.get("role_definition_address")
        }
    )


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
