from __future__ import annotations

import re
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
from tfstride.providers.azure.object_storage_deletion_evidence import (
    AzureAppServiceBlobDeletionPath,
    AzureBlobDeletionRecoveryEvidence,
)
from tfstride.providers.azure.protected_data_evidence import AzureAppServiceStorageAccessPath
from tfstride.providers.azure.resource_decoration.app_service_blob_deletion_paths import (
    storage_access_path_deletion_operations,
)
from tfstride.providers.azure.resource_decoration.app_service_storage_access_paths import (
    current_app_service_storage_access_paths,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_RULE_OPERATIONS = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action",
)
_OPERATION_CLASSES = {
    _RULE_OPERATIONS[0]: "logical_blob_deletion",
    _RULE_OPERATIONS[1]: "blob_version_deletion",
    _RULE_OPERATIONS[2]: "soft_deleted_blob_data_permanent_deletion",
}
_CURRENT_DELETE = _RULE_OPERATIONS[0]
_VERSION_DELETE = _RULE_OPERATIONS[1]
_PERMANENT_DELETE = _RULE_OPERATIONS[2]
_STANDARD_TARGETS = {
    _CURRENT_DELETE: ("logical_blob_deletion", "container_blob_namespace"),
    _VERSION_DELETE: ("blob_version_deletion", "container_blob_version_namespace"),
}
_OPERATION_ORDER = (_CURRENT_DELETE, _VERSION_DELETE, _PERMANENT_DELETE)
_STORAGE_BLOB_RESOURCE_TYPE = "azurerm_storage_blob"
_ACCOUNT_ID_PATTERN = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.Storage/storageAccounts/[^/]+/?\Z",
    re.IGNORECASE,
)
_CONTAINER_ID_PATTERN = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.Storage/storageAccounts/[^/]+/blobServices/default/containers/[^/]+/?\Z",
    re.IGNORECASE,
)
_RECOVERY_UNCERTAINTY_PREFIXES = (
    "is_hns_enabled ",
    "blob_properties.versioning_enabled ",
    "blob_properties.delete_retention_policy.days ",
    "blob_properties.delete_retention_policy.permanent_delete_enabled ",
)


class AzureAppServiceBlobRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_blob_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        decoration_context = AzureDecorationContext(
            AzureResourceIndexBuilder().build(list(context.inventory.resources))
        )
        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            current_access_paths, authority_uncertainties = current_app_service_storage_access_paths(
                app, decoration_context
            )
            paths = [
                path
                for path in app_facts.app_service_blob_deletion_paths
                if _is_current_deterministic_path(path, app, context, current_access_paths)
            ]
            if not paths:
                continue

            account_addresses = _path_addresses(paths, "storage_account_address")
            container_addresses = _path_addresses(paths, "container_address")
            identity_addresses = _path_addresses(paths, "identity_address")
            assignment_addresses = _path_addresses(paths, "role_assignment_address")
            role_definition_addresses = _path_addresses(paths, "role_definition_address")
            operations = _operations(paths)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if _VERSION_DELETE in operations or _PERMANENT_DELETE in operations else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(container_addresses) > 1 or len(account_addresses) > 1 else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *account_addresses,
                            *container_addresses,
                            *_target_model_evidence_addresses(paths),
                            *assignment_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(app, paths, operations),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("storage_blob_deletion_paths", _deletion_path_evidence(paths)),
                        evidence_item("recovery_posture", _recovery_evidence(paths)),
                        evidence_item("authorization_scope", _authorization_scope_evidence(paths)),
                        evidence_item(
                            "storage_blob_deletion_path_uncertainties",
                            dedupe([*app_facts.app_service_blob_deletion_path_uncertainties, *authority_uncertainties]),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_current_deterministic_path(
    path: AzureAppServiceBlobDeletionPath,
    app: NormalizedResource,
    context: RuleEvaluationContext,
    current_access_paths: Sequence[AzureAppServiceStorageAccessPath],
) -> bool:
    operation = path.get("operation")
    if operation not in _RULE_OPERATIONS:
        return False
    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("management_effect") != "disruption"
        or path.get("authorization_state") != "granted"
        or path.get("policy_complete") is not True
        or path.get("condition") is not None
        or path.get("condition_state") != "not_configured"
        or path.get("assignment_scope_kind") not in {"resource", "resource_group", "subscription"}
        or path.get("grant_basis")
        not in {
            "azure_storage_scoped_rbac",
            "azure_custom_role_storage_scoped_rbac",
        }
        or path.get("matched_data_actions") != [operation]
    ):
        return False

    if path.get("operation_class") != _OPERATION_CLASSES[operation]:
        return False
    if _runtime_identity(path, app, context) is None:
        return False

    account, container = _current_storage_target(path, context)
    if account is None or container is None:
        return False
    if not _current_storage_access_authority(path, operation, current_access_paths):
        return False
    if not _recovery_evidence_is_current(path, account, container, operation, context):
        return False
    return _target_contract_is_current(path, account, container, operation, context)


def _runtime_identity(
    path: Mapping[str, object],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    if identity_address is None or principal_id is None:
        return None
    identity = context.inventory.get_by_address(identity_address)
    if identity is None or _known_string(azure_facts(identity).principal_id) != principal_id:
        return None

    app_facts = azure_facts(app)
    identity_kind = path.get("identity_kind")
    if identity_kind == "system_assigned":
        if identity.address != app.address or app_facts.has_system_assigned_identity is not True:
            return None
    elif identity_kind == "user_assigned":
        if (
            identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
            or app_facts.has_user_assigned_identity is not True
            or not _user_identity_is_attached(app_facts, identity.address)
        ):
            return None
    else:
        return None
    return identity


def _user_identity_is_attached(facts: object, address: str) -> bool:
    resolved = getattr(facts, "resolved_attached_identity_addresses", [])
    references = getattr(facts, "attached_identity_references", [])
    if isinstance(resolved, list) and address in resolved:
        return True
    return isinstance(references, list) and any(
        isinstance(reference, str) and (reference == address or reference.startswith(f"{address}."))
        for reference in references
    )


def _current_storage_target(
    path: Mapping[str, object],
    context: RuleEvaluationContext,
) -> tuple[NormalizedResource | None, NormalizedResource | None]:
    account_address = _known_string(path.get("storage_account_address"))
    container_address = _known_string(path.get("container_address"))
    account = context.inventory.get_by_address(account_address) if account_address is not None else None
    container = context.inventory.get_by_address(container_address) if container_address is not None else None
    if (
        account is None
        or account.resource_type != AzureResourceType.STORAGE_ACCOUNT
        or container is None
        or container.resource_type != AzureResourceType.STORAGE_CONTAINER
    ):
        return None, None

    account_facts = azure_facts(account)
    container_facts = azure_facts(container)
    account_id = _known_string(account_facts.storage_account_id)
    container_id = _known_string(container_facts.storage_container_resource_manager_id)
    if (
        not _is_exact_identifier(account_id, _ACCOUNT_ID_PATTERN)
        or not _is_exact_identifier(container_id, _CONTAINER_ID_PATTERN)
        or container_facts.resolved_storage_account_address != account.address
        or not _same_identifier(path.get("storage_account_id"), account_id)
        or not _same_identifier(path.get("container_resource_id"), container_id)
    ):
        return None, None

    target_model_evidence_addresses = path.get("target_model_evidence_addresses")
    if (
        not isinstance(target_model_evidence_addresses, list)
        or len(target_model_evidence_addresses) < 2
        or target_model_evidence_addresses[:2] != [account.address, container.address]
    ):
        return None, None
    container_name = _known_string(container_facts.bucket_name)
    if container_name is None:
        return None, None
    assert account_id is not None
    assert container_id is not None
    if not _same_identifier(
        container_id,
        f"{account_id.rstrip('/')}/blobServices/default/containers/{container_name}",
    ):
        return None, None
    return account, container


def _current_storage_access_authority(
    path: Mapping[str, object],
    operation: str,
    current_paths: Sequence[AzureAppServiceStorageAccessPath],
) -> bool:
    # These records were rebuilt by the shared Blob authority evaluator in this
    # invocation. Scope, assignability, conditions and exclusions belong to each
    # assignment alternative; cached attachment summaries cannot prove authority.
    for current in current_paths:
        if (
            not _access_path_matches(path, current)
            or current["access_state"] != "granted"
            or current["condition_state"] != "not_configured"
            or current["condition"] is not None
            or operation not in storage_access_path_deletion_operations(current)
        ):
            continue
        sources = [current["role_assignment_address"]]
        role_address = current["role_definition_address"]
        if role_address is not None:
            sources.append(role_address)
        if path.get("authorization_source_addresses") == sources:
            return True
    return False


def _access_path_matches(
    deletion_path: Mapping[str, object],
    access_path: AzureAppServiceStorageAccessPath,
) -> bool:
    fields = (
        "workload_address",
        "workload_type",
        "identity_address",
        "identity_kind",
        "principal_id",
        "credential_context",
        "storage_account_address",
        "storage_account_id",
        "role_assignment_address",
        "role_definition_name",
        "role_definition_id",
        "grant_basis",
        "assignment_scope",
        "assignment_scope_kind",
        "condition",
        "condition_state",
        "role_definition_address",
        "excluded_data_actions",
    )
    if not all(deletion_path.get(field) == access_path.get(field) for field in fields):
        return False
    if access_path["resource_scope"] == "exact_storage_container":
        return deletion_path.get("container_address") == access_path["container_address"]
    return access_path["resource_scope"] == "exact_storage_account"


def _target_contract_is_current(
    path: Mapping[str, object],
    account: NormalizedResource,
    container: NormalizedResource,
    operation: str,
    context: RuleEvaluationContext,
) -> bool:
    if operation in _STANDARD_TARGETS:
        expected_class, expected_granularity = _STANDARD_TARGETS[operation]
        container_id = _known_string(azure_facts(container).storage_container_resource_manager_id)
        if container_id is None:
            return False
        return (
            path.get("operation_class") == expected_class
            and path.get("target_granularity") == expected_granularity
            and path.get("blob_name") is None
            and path.get("blob_version") is None
            and path.get("snapshot") is None
            and path.get("target_model_evidence_addresses") == [account.address, container.address]
            and path.get("target_scope") == f"{container_id.rstrip('/')}/blobs/*"
        )

    if path.get("target_granularity") not in {"blob_version", "snapshot"}:
        return False
    target_addresses = path.get("target_model_evidence_addresses")
    if (
        not isinstance(target_addresses, list)
        or len(target_addresses) != 3
        or target_addresses[:2] != [account.address, container.address]
    ):
        return False
    target_address = target_addresses[-1]
    target = context.inventory.get_by_address(target_address) if isinstance(target_address, str) else None
    if target is None or target.resource_type != _STORAGE_BLOB_RESOURCE_TYPE:
        return False
    if not _known_string(path.get("blob_name")):
        return False
    if path.get("target_granularity") == "blob_version":
        if not _known_string(path.get("blob_version")) or path.get("snapshot") is not None:
            return False
    elif not _known_string(path.get("snapshot")) or path.get("blob_version") is not None:
        return False
    if path.get("permanent_delete_enabled") is not True or path.get("soft_deleted_target_state") != "soft_deleted":
        return False
    return path.get("lifecycle_compatibility_state") == "compatible"


def _recovery_evidence_is_current(
    path: Mapping[str, object],
    account: NormalizedResource,
    container: NormalizedResource,
    operation: str,
    context: RuleEvaluationContext,
) -> bool:
    expected = _current_recovery_evidence(account)
    actual = path.get("recovery_evidence")
    if not isinstance(actual, Mapping) or dict(actual) != expected:
        return False
    if path.get("posture_uncertainties") != expected["uncertainties"]:
        return False

    hns = expected["hierarchical_namespace_enabled"]
    if operation == _CURRENT_DELETE:
        return path.get("lifecycle_compatibility_state") == "compatible"
    if operation == _VERSION_DELETE:
        if hns is True:
            return False
        return path.get("lifecycle_compatibility_state") == ("unknown" if hns is None else "compatible")
    return _target_contract_is_current(path, account, container, operation, context)


def _current_recovery_evidence(account: NormalizedResource) -> AzureBlobDeletionRecoveryEvidence:
    facts = azure_facts(account)
    uncertainties = dedupe(
        uncertainty
        for uncertainty in facts.storage_posture_uncertainties
        if uncertainty.startswith(_RECOVERY_UNCERTAINTY_PREFIXES)
    )
    return {
        "recovery_evidence_scope": "azure_blob_versioning_and_soft_delete",
        "versioning_enabled": facts.storage_blob_versioning_enabled,
        "blob_delete_retention_days": facts.storage_blob_delete_retention_days,
        "permanent_delete_enabled": facts.storage_blob_permanent_delete_enabled,
        "hierarchical_namespace_enabled": facts.storage_hierarchical_namespace_enabled,
        "uncertainties": uncertainties,
    }


def _operations(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _path_addresses(paths: Sequence[Mapping[str, object]], field: str) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(field))) is not None})


def _target_model_evidence_addresses(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {address for path in paths for address in _string_values(path.get("target_model_evidence_addresses"))}
    )


def _runtime_identity_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"identity_address={path.get('identity_address')}",
                    f"identity_kind={path.get('identity_kind')}",
                    f"principal_id={path.get('principal_id')}",
                    "credential_context=workload_runtime",
                    "authorization_state=granted",
                )
            )
            for path in paths
        }
    )


def _deletion_path_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"storage_account_address={path.get('storage_account_address')}",
                    f"container_address={path.get('container_address')}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_model_evidence_addresses={','.join(_string_values(path.get('target_model_evidence_addresses'))) or 'none'}",
                    f"target_scope={path.get('target_scope')}",
                    f"role_assignment_address={path.get('role_assignment_address')}",
                    f"role_definition_name={path.get('role_definition_name')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')))}",
                    f"lifecycle_compatibility_state={path.get('lifecycle_compatibility_state')}",
                    "authorization_state=granted",
                )
            )
            for path in paths
        }
    )


def _recovery_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        recovery = path.get("recovery_evidence")
        if not isinstance(recovery, Mapping):
            continue
        recovery_map = cast(Mapping[str, object], recovery)
        operation = path.get("operation")
        values.add(
            "; ".join(
                (
                    f"container_address={path.get('container_address')}",
                    f"operation={operation}",
                    f"operation_class={path.get('operation_class')}",
                    f"recovery_state={_recovery_state(path)}",
                    f"versioning_enabled={str(recovery_map.get('versioning_enabled')).lower()}",
                    f"blob_delete_retention_days={recovery_map.get('blob_delete_retention_days')}",
                    f"permanent_delete_enabled={str(recovery_map.get('permanent_delete_enabled')).lower()}",
                    f"hns_enabled={str(recovery_map.get('hierarchical_namespace_enabled')).lower()}",
                    f"lifecycle_compatibility_state={path.get('lifecycle_compatibility_state')}",
                    f"uncertainties={','.join(_string_values(recovery_map.get('uncertainties'))) or 'none'}",
                    f"permanent_loss_established={'true' if operation == _PERMANENT_DELETE else 'false'}",
                )
            )
        )
    return sorted(values)


def _recovery_state(path: Mapping[str, object]) -> str:
    recovery = path.get("recovery_evidence")
    if not isinstance(recovery, Mapping):
        return "recovery_posture_unknown"
    recovery = cast(Mapping[str, object], recovery)
    versioning = recovery.get("versioning_enabled")
    retention = recovery.get("blob_delete_retention_days")
    operation = path.get("operation")
    if operation == _CURRENT_DELETE:
        if versioning is True:
            return "live_blob_delete_may_leave_noncurrent_version"
        if versioning is None:
            return "recovery_posture_unknown"
        if isinstance(retention, int) and retention > 0:
            return "soft_delete_recoverable_during_retention"
        return "recovery_control_not_observed"
    if operation == _VERSION_DELETE:
        if path.get("lifecycle_compatibility_state") == "unknown":
            return "recovery_posture_unknown"
        if isinstance(retention, int) and retention > 0:
            return "soft_delete_recoverable_during_retention"
        if retention is None and _blob_retention_is_unknown(recovery):
            return "recovery_posture_unknown"
        return "version_delete_recovery_not_observed"
    if operation == _PERMANENT_DELETE:
        return "permanent_loss_capability_established"
    return "recovery_posture_unknown"


def _blob_retention_is_unknown(recovery: Mapping[str, object]) -> bool:
    return any(
        uncertainty.startswith("blob_properties.delete_retention_policy.days ")
        for uncertainty in _string_values(recovery.get("uncertainties"))
    )


def _authorization_scope_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"storage_account_address={path.get('storage_account_address')}",
                    f"container_address={path.get('container_address')}",
                    f"assignment_scope={path.get('assignment_scope') or 'unknown'}",
                    f"assignment_scope_kind={path.get('assignment_scope_kind') or 'unknown'}",
                    f"target_scope={path.get('target_scope')}",
                    f"grant_basis={path.get('grant_basis')}",
                    f"authorization_sources={','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}",
                )
            )
            for path in paths
        }
    )


def _rationale(
    app: NormalizedResource,
    paths: Sequence[Mapping[str, object]],
    operations: Sequence[str],
) -> str:
    classes = [
        operation_class
        for operation_class in (
            "logical_blob_deletion",
            "blob_version_deletion",
            "soft_deleted_blob_data_permanent_deletion",
        )
        if any(path.get("operation_class") == operation_class for path in paths)
    ]
    operation_text = _operation_text(classes)
    containers = _path_addresses(paths, "container_address")
    rationale = (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"Azure Blob deletion authority ({operation_text}) across {len(containers)} exact modeled container scope(s). "
        "A compromise of the public workload could disrupt Blob availability within the modeled account and container "
        "grants. Recovery evidence remains operation-specific: ordinary blob deletion is not treated as permanent loss, "
        "while version deletion depends on the current soft-delete and HNS posture."
    )
    if _PERMANENT_DELETE in operations:
        rationale += " Permanent loss capability is described only for an exact modeled soft-deleted version or snapshot with all prerequisites validated."
    else:
        rationale += (
            " The modeled ordinary and version-deletion paths do not establish permanent loss of a particular blob."
        )
    rationale += " This does not establish that the Storage Account or container is public, or that deletion succeeds outside the modeled scope."
    return rationale


def _operation_text(values: Sequence[str]) -> str:
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _is_exact_identifier(value: str | None, pattern: re.Pattern[str]) -> bool:
    return bool(value and pattern.fullmatch(value.rstrip("/")))


def _same_identifier(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and left.strip().rstrip("/").casefold() == right.strip().rstrip("/").casefold()
    )


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]
