from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, cast

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
from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultOperationPath,
    AzureKeyVaultGrantBasis,
    AzureKeyVaultGrantKind,
    AzureKeyVaultOperation,
    AzureKeyVaultPathScopeType,
)
from tfstride.providers.azure.protected_data_evidence import (
    AzureAppServiceServiceBusAccessPath,
    AzureAppServiceServiceBusProtectedDataConvergence,
    AzureAppServiceStorageAccessPath,
    AzureAppServiceStorageProtectedDataConvergence,
)
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)

_RuleOperationClass = Literal["decrypt", "sign"]
_PathAddressKey = Literal[
    "key_address",
    "key_vault_address",
    "identity_address",
    "grant_source_address",
    "role_definition_address",
]
_GrantFingerprint = tuple[
    str,
    AzureKeyVaultGrantKind,
    AzureKeyVaultGrantBasis,
    str | None,
    str | None,
]
_AzureProtectedDataConvergence = (
    AzureAppServiceStorageProtectedDataConvergence | AzureAppServiceServiceBusProtectedDataConvergence
)


@dataclass(frozen=True, slots=True)
class _AzureLogicalProtectedDataDependency:
    protected_resources: tuple[tuple[str, str], ...]
    parent_address: str
    key_address: str
    key_uri: str | None
    key_versionless_uri: str
    dependency_source_address: str
    configuration_path: str
    proof_count: int
    operations: tuple[AzureKeyVaultOperation, ...]
    authorization_scopes: tuple[str, ...]


_DECRYPT_OPERATION: _RuleOperationClass = "decrypt"
_DECRYPT_OPERATIONS: frozenset[AzureKeyVaultOperation] = frozenset({"decrypt", "unwrap"})
_SIGN_OPERATION: _RuleOperationClass = "sign"
_OPERATION_ORDER: tuple[AzureKeyVaultOperation, ...] = ("decrypt", "unwrap", "sign")
_SUPPORTED_SCOPE_TYPES: frozenset[AzureKeyVaultPathScopeType] = frozenset(
    {"subscription", "resource_group", "vault", "key"}
)
_PARENT_SCOPE_TYPES: frozenset[AzureKeyVaultPathScopeType] = frozenset({"subscription", "resource_group", "vault"})
_ACCESS_POLICY_SOURCE_TYPES = frozenset({AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY})
_VAULT_ID_PATTERN = re.compile(
    r"^(?P<subscription>/subscriptions/[^/]+)"
    r"(?P<resource_group>/resourceGroups/[^/]+)"
    r"/providers/Microsoft\.KeyVault/vaults/[^/]+$",
    re.IGNORECASE,
)


class AzureAppServiceKeyVaultOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_key_vault_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(context, rule_id, _DECRYPT_OPERATION)

    def detect_public_app_service_key_vault_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(context, rule_id, _SIGN_OPERATION)

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operation_class: _RuleOperationClass,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths: list[AzureAppServiceKeyVaultOperationPath] = [
                path
                for path in facts.app_service_key_vault_operation_paths
                if _is_deterministic_operation_path(path, app, context, operation_class)
            ]
            if not paths:
                continue

            key_addresses = _path_values(paths, "key_address")
            vault_addresses = _path_values(paths, "key_vault_address")
            identity_addresses = _path_values(paths, "identity_address")
            grant_addresses = _path_values(paths, "grant_source_address")
            role_definition_addresses = _path_values(paths, "role_definition_address")
            operations = _path_operations(paths)
            parent_scope = any(path.get("scope_type") in _PARENT_SCOPE_TYPES for path in paths)
            protected_data_convergences = (
                _resolved_protected_data_convergences(paths, app, context)
                if operation_class == _DECRYPT_OPERATION
                else []
            )
            logical_protected_data_dependencies = (
                _logical_protected_data_dependencies(protected_data_convergences)
                if operation_class == _DECRYPT_OPERATION
                else []
            )
            protected_data_dependent_addresses = _protected_data_dependent_addresses(
                logical_protected_data_dependencies,
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=1,
                data_sensitivity=2 if operation_class == _DECRYPT_OPERATION else 1,
                lateral_movement=1,
                blast_radius=(2 if parent_scope or len(protected_data_dependent_addresses) > 1 else 1),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *(address for address in identity_addresses if address != app.address),
                            *vault_addresses,
                            *key_addresses,
                            *grant_addresses,
                            *role_definition_addresses,
                            *protected_data_dependent_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(
                        app,
                        operation_class,
                        operations,
                        key_addresses,
                        parent_scope=parent_scope,
                        downstream_dependent_count=len(protected_data_dependent_addresses),
                        downstream_dependency_count=len(logical_protected_data_dependencies),
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("key_vault_operation_paths", _operation_path_evidence(paths)),
                        evidence_item("scope_breadth", _scope_breadth_evidence(paths)),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(operation_class, operations, parent_scope),
                        ),
                        *(
                            [
                                evidence_item(
                                    "downstream_dependencies",
                                    _protected_data_dependency_evidence(
                                        logical_protected_data_dependencies,
                                    ),
                                ),
                                evidence_item(
                                    "downstream_dependency_uncertainties",
                                    _protected_data_uncertainties(app),
                                ),
                            ]
                            if operation_class == _DECRYPT_OPERATION
                            else []
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_operation_path(
    path: AzureAppServiceKeyVaultOperationPath,
    app: NormalizedResource,
    context: RuleEvaluationContext,
    operation_class: _RuleOperationClass,
) -> bool:
    operation = path["operation"]
    if operation_class == _DECRYPT_OPERATION:
        if operation not in _DECRYPT_OPERATIONS or path.get("operation_class") != "plaintext_recovery":
            return False
        expected_key_operation = "decrypt" if operation == "decrypt" else "unwrapKey"
    else:
        if operation != _SIGN_OPERATION or path.get("operation_class") != "authenticator_generation":
            return False
        expected_key_operation = "sign"

    if (
        path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("key_resource_type") != AzureResourceType.KEY_VAULT_KEY
        or path.get("authorization_state") != "granted"
        or path.get("authorization_model_state") != "active"
        or path.get("condition_state") != "not_configured"
        or path.get("condition") is not None
        or path.get("grant_kind") not in {"access_policy", "rbac"}
        or path.get("evaluation_basis") != "modeled_key_vault_key_authorization"
        or path.get("scope_type") not in _SUPPORTED_SCOPE_TYPES
        or path.get("matched_key_operation") != expected_key_operation
    ):
        return False

    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    key_address = _known_string(path.get("key_address"))
    vault_address = _known_string(path.get("key_vault_address"))
    grant_source_address = _known_string(path.get("grant_source_address"))
    if (
        identity_address is None
        or principal_id is None
        or key_address is None
        or vault_address is None
        or grant_source_address is None
    ):
        return False

    identity = context.inventory.get_by_address(identity_address)
    key = context.inventory.get_by_address(key_address)
    vault = context.inventory.get_by_address(vault_address)
    grant_source = context.inventory.get_by_address(grant_source_address)
    if (
        identity is None
        or key is None
        or vault is None
        or grant_source is None
        or key.resource_type != AzureResourceType.KEY_VAULT_KEY
        or vault.resource_type != AzureResourceType.KEY_VAULT
    ):
        return False

    app_facts = azure_facts(app)
    identity_facts = azure_facts(identity)
    key_facts = azure_facts(key)
    vault_facts = azure_facts(vault)
    identity_principal_id = _known_string(identity_facts.principal_id)
    path_vault_id = _known_string(path.get("key_vault_id"))
    vault_id = _known_string(vault_facts.key_vault_id)
    if (
        identity_principal_id is None
        or not _same_identifier(identity_principal_id, principal_id)
        or key_facts.key_vault_key_identity_state != "resolved"
        or key_facts.resolved_key_vault_address != vault.address
        or not _same_identifier(path_vault_id, vault_id)
        or not _has_exact_versionless_key_identity(key_facts)
        or not _path_matches_key_identity(path, key_facts)
        or not _key_operation_is_supported(key_facts, expected_key_operation)
    ):
        return False

    if path.get("identity_kind") == "system_assigned":
        if identity.address != app.address or not app_facts.has_system_assigned_identity:
            return False
    elif (
        identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY
        or not app_facts.has_user_assigned_identity
        or not _user_identity_is_attached(app_facts, identity.address)
    ):
        return False

    if not _grant_source_is_valid(path, grant_source, vault):
        return False
    if not _scope_is_exact(path, key, vault):
        return False

    role_definition_address = _known_string(path.get("role_definition_address"))
    if role_definition_address is not None:
        role_definition = context.inventory.get_by_address(role_definition_address)
        if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
            return False
    return True


def _user_identity_is_attached(facts: AzureResourceFacts, address: str) -> bool:
    if address in facts.resolved_attached_identity_addresses:
        return True
    return any(
        reference == address or reference.startswith(f"{address}.") for reference in facts.attached_identity_references
    )


def _path_matches_key_identity(
    path: AzureAppServiceKeyVaultOperationPath,
    facts: AzureResourceFacts,
) -> bool:
    identity_pairs = (
        (path["key_uri"], facts.key_vault_key_uri),
        (path["key_versionless_uri"], facts.key_vault_key_versionless_uri),
        (path["key_resource_id"], facts.key_vault_key_resource_id),
        (path["key_versionless_resource_id"], facts.key_vault_key_versionless_resource_id),
        (path["key_version"], facts.key_vault_key_version),
    )
    return all(_same_optional_identifier(left, right) for left, right in identity_pairs)


def _same_optional_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    if left_value is None or right_value is None:
        return left_value is None and right_value is None
    return left_value.casefold() == right_value.casefold()


def _same_identifier(left: str | None, right: str | None) -> bool:
    return _same_optional_identifier(left, right) and left is not None and right is not None


def _has_exact_versionless_key_identity(facts: AzureResourceFacts) -> bool:
    return bool(
        _known_string(facts.key_vault_key_versionless_uri) or _known_string(facts.key_vault_key_versionless_resource_id)
    )


def _key_operation_is_supported(facts: AzureResourceFacts, operation: str) -> bool:
    return operation.casefold() in {value.casefold() for value in facts.key_vault_key_ops}


def _grant_source_is_valid(
    path: AzureAppServiceKeyVaultOperationPath,
    source: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    grant_kind = path.get("grant_kind")
    if path.get("grant_source_type") != source.resource_type:
        return False
    if grant_kind == "access_policy":
        return (
            source.resource_type in _ACCESS_POLICY_SOURCE_TYPES
            and path.get("authorization_model") == "access_policy"
            and path.get("management_state") == "unambiguous"
            and path.get("scope_type") == "vault"
        )
    return (
        grant_kind == "rbac"
        and source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        and path.get("authorization_model") == "azure_rbac"
        and path.get("key_vault_address") == vault.address
    )


def _scope_is_exact(
    path: AzureAppServiceKeyVaultOperationPath,
    key: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    scope_type = path.get("scope_type")
    scope_arm_id = _known_string(path.get("scope_arm_id"))
    if scope_arm_id is None:
        return False

    key_facts = azure_facts(key)
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if scope_type == "key":
        expected = _known_string(key_facts.key_vault_key_versionless_resource_id)
    elif scope_type == "vault":
        expected = vault_id
    else:
        match = _VAULT_ID_PATTERN.fullmatch(vault_id.rstrip("/")) if vault_id is not None else None
        if match is None:
            expected = None
        elif scope_type == "subscription":
            expected = match.group("subscription")
        elif scope_type == "resource_group":
            expected = f"{match.group('subscription')}{match.group('resource_group')}"
        else:
            expected = None
    return expected is not None and expected.casefold() == scope_arm_id.casefold()


def _rationale(
    app: NormalizedResource,
    operation_class: _RuleOperationClass,
    operations: Sequence[AzureKeyVaultOperation],
    key_addresses: list[str],
    *,
    parent_scope: bool,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
) -> str:
    operation_text = _operation_text(operations)
    if operation_class == _DECRYPT_OPERATION:
        authority_text = operation_text
        capability = _plaintext_recovery_capability(operations)
    else:
        authority_text = "signing"
        capability = "could generate Key Vault signatures, creating spoofing potential"
    if parent_scope:
        scope_text = (
            "At least one modeled grant is subscription-, resource-group-, or vault-scoped, so its potential "
            "blast radius is broader than an exact-key grant. The modeled key count is not an inventory of every "
            "out-of-plan key covered by that parent scope."
        )
    else:
        scope_text = "The modeled grants are limited to exact versionless Key Vault key scope."
    qualification = (
        "This establishes cryptographic-operation authority, not proof that the workload possesses useful "
        "ciphertext, can recover application plaintext, or can produce a signature accepted by a relying "
        "application."
    )
    downstream = (
        f" The exact plaintext-recovery evidence converges with {downstream_dependent_count} unique "
        "Key Vault-protected Storage or Service Bus resource(s) across "
        f"{downstream_dependency_count} unique encryption dependency relationship(s)."
        if operation_class == _DECRYPT_OPERATION and downstream_dependent_count
        else (
            " No resolved Key Vault-protected Storage or Service Bus access convergence is modeled for these keys."
            if operation_class == _DECRYPT_OPERATION
            else ""
        )
    )
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"Key Vault {authority_text} authority "
        f"on {len(key_addresses)} exact modeled key(s). A compromise of the "
        f"public workload {capability}. {scope_text} {qualification}{downstream}"
    )


def _resolved_protected_data_convergences(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[_AzureProtectedDataConvergence]:
    facts = azure_facts(app)
    candidates: list[_AzureProtectedDataConvergence] = [
        *facts.app_service_storage_protected_data_convergences,
        *facts.app_service_service_bus_protected_data_convergences,
    ]
    resolved = [
        convergence
        for convergence in candidates
        if _is_valid_protected_data_convergence(convergence, paths, app, context)
    ]
    return sorted(
        resolved,
        key=lambda convergence: (
            _protected_resource_address(convergence),
            convergence["key_address"],
            convergence["operation"],
            convergence["key_operation_path"].get("grant_source_address") or "",
        ),
    )


def _is_valid_protected_data_convergence(
    convergence: _AzureProtectedDataConvergence,
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        convergence["convergence_state"] != "resolved"
        or convergence["workload_address"] != app.address
        or convergence["workload_type"] != app.resource_type
        or convergence["operation"] not in _DECRYPT_OPERATIONS
        or convergence["runtime_identity_match"] is not True
        or convergence["protected_resource_match"] is not True
        or convergence["key_identity_match"] is not True
    ):
        return False

    access_path = convergence["access_path"]
    operation_path = convergence["key_operation_path"]
    if (
        operation_path not in paths
        or operation_path["operation"] != convergence["operation"]
        or operation_path["key_address"] != convergence["key_address"]
        or operation_path["identity_address"] != convergence["identity_address"]
        or operation_path["principal_id"] != convergence["principal_id"]
        or access_path["workload_address"] != app.address
        or access_path["identity_address"] != convergence["identity_address"]
        or access_path["identity_kind"] != convergence["identity_kind"]
        or access_path["principal_id"] != convergence["principal_id"]
    ):
        return False

    key = context.inventory.get_by_address(convergence["key_address"])
    if key is None or key.provider != "azure" or key.resource_type != AzureResourceType.KEY_VAULT_KEY:
        return False
    key_facts = azure_facts(key)
    if (
        operation_path["key_vault_address"] != key_facts.resolved_key_vault_address
        or operation_path["key_name"] != key_facts.key_vault_key_name
        or operation_path["key_identity_state"] != key_facts.key_vault_key_identity_state
        or not _same_optional_identifier(operation_path["key_uri"], key_facts.key_vault_key_uri)
        or not _same_optional_identifier(
            operation_path["key_versionless_uri"],
            key_facts.key_vault_key_versionless_uri,
        )
        or convergence["key_uri"]
        != (
            key_facts.key_vault_key_uri
            if convergence["encryption_dependency"]["target_kind"] == "key_version"
            else None
        )
        or convergence["key_versionless_uri"] != key_facts.key_vault_key_versionless_uri
    ):
        return False

    if "storage_resource_address" in convergence:
        return _is_valid_storage_convergence(
            convergence,
            convergence["access_path"],
            key,
            app,
            context,
        )
    return _is_valid_service_bus_convergence(
        convergence,
        convergence["access_path"],
        key,
        app,
        context,
    )


def _is_valid_storage_convergence(
    convergence: AzureAppServiceStorageProtectedDataConvergence,
    access_path: AzureAppServiceStorageAccessPath,
    key: NormalizedResource,
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    facts = azure_facts(app)
    if (
        convergence not in facts.app_service_storage_protected_data_convergences
        or access_path not in facts.app_service_storage_access_paths
    ):
        return False
    account = context.inventory.get_by_address(convergence["storage_account_address"])
    target = context.inventory.get_by_address(convergence["storage_resource_address"])
    if (
        account is None
        or account.provider != "azure"
        or account.resource_type != AzureResourceType.STORAGE_ACCOUNT
        or target is None
        or target.provider != "azure"
        or target.resource_type
        not in {
            AzureResourceType.STORAGE_ACCOUNT,
            AzureResourceType.STORAGE_CONTAINER,
        }
        or target.address != convergence["storage_resource_address"]
        or convergence["storage_account_address"] != account.address
        or access_path.get("storage_account_address") != account.address
        or access_path.get("storage_resource_address") != target.address
        or access_path.get("storage_account_id") != convergence["storage_account_id"]
    ):
        return False
    if target.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        if (
            target.address != account.address
            or access_path.get("resource_scope") != "exact_storage_account"
            or access_path.get("container_address") is not None
        ):
            return False
    elif (
        access_path.get("resource_scope") != "exact_storage_container"
        or access_path.get("container_address") != target.address
        or azure_facts(target).resolved_storage_account_address != account.address
    ):
        return False
    return _dependency_is_current(convergence["encryption_dependency"], account, key, context)


def _is_valid_service_bus_convergence(
    convergence: AzureAppServiceServiceBusProtectedDataConvergence,
    access_path: AzureAppServiceServiceBusAccessPath,
    key: NormalizedResource,
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    facts = azure_facts(app)
    if (
        convergence not in facts.app_service_service_bus_protected_data_convergences
        or access_path not in facts.app_service_service_bus_access_paths
    ):
        return False
    namespace = context.inventory.get_by_address(convergence["service_bus_namespace_address"])
    target = context.inventory.get_by_address(convergence["service_bus_resource_address"])
    if (
        namespace is None
        or namespace.provider != "azure"
        or namespace.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE
        or target is None
        or target.provider != "azure"
        or target.resource_type
        not in {
            AzureResourceType.SERVICE_BUS_NAMESPACE,
            AzureResourceType.SERVICE_BUS_QUEUE,
            AzureResourceType.SERVICE_BUS_TOPIC,
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
        }
        or target.address != convergence["service_bus_resource_address"]
        or convergence["service_bus_namespace_address"] != namespace.address
        or access_path.get("service_bus_namespace_address") != namespace.address
        or access_path.get("service_bus_resource_address") != target.address
        or access_path.get("service_bus_namespace_id") != convergence["service_bus_namespace_id"]
    ):
        return False
    if target.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        if access_path.get("resource_scope") != "exact_service_bus_namespace" or any(
            access_path.get(field) is not None for field in ("queue_address", "topic_address", "subscription_address")
        ):
            return False
    elif (
        azure_facts(target).resolved_service_bus_namespace_address != namespace.address
        or access_path.get("resource_scope")
        != {
            AzureResourceType.SERVICE_BUS_QUEUE: "exact_service_bus_queue",
            AzureResourceType.SERVICE_BUS_TOPIC: "exact_service_bus_topic",
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION: "exact_service_bus_subscription",
        }[target.resource_type]
    ):
        return False
    return _dependency_is_current(convergence["encryption_dependency"], namespace, key, context)


def _dependency_is_current(
    dependency: AzureKeyVaultEncryptionDependency,
    parent: NormalizedResource,
    key: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    if (
        dependency not in azure_facts(parent).key_vault_encryption_dependencies
        or dependency["resolution_state"] != "resolved"
        or dependency["customer_managed_key_state"] != "configured"
        or dependency["dependent_address"] != parent.address
        or dependency["dependent_resource_type"] != parent.resource_type
        or dependency["key_address"] != key.address
        or dependency["candidate_key_addresses"] != [key.address]
        or not _dependency_source_is_current(dependency, parent, context)
    ):
        return False
    key_facts = azure_facts(key)
    vault_address = key_facts.resolved_key_vault_address
    if (
        vault_address is None
        or dependency["key_vault_address"] != vault_address
        or dependency["key_name"] != key_facts.key_vault_key_name
        or not _same_optional_identifier(
            dependency["key_versionless_uri"],
            key_facts.key_vault_key_versionless_uri,
        )
        or not _same_optional_identifier(
            dependency["key_versionless_resource_id"],
            key_facts.key_vault_key_versionless_resource_id,
        )
        or not _dependency_target_is_current(dependency, key_facts)
        or not _dependency_reference_is_coherent(dependency, key)
    ):
        return False
    vault = context.inventory.get_by_address(vault_address)
    if vault is None or vault.provider != "azure" or vault.resource_type != AzureResourceType.KEY_VAULT:
        return False
    vault_facts = azure_facts(vault)
    return _same_optional_identifier(
        dependency["key_vault_id"], vault_facts.key_vault_id
    ) and _same_optional_identifier(dependency["key_vault_uri"], vault_facts.key_vault_uri)


def _dependency_target_is_current(
    dependency: AzureKeyVaultEncryptionDependency,
    key_facts: AzureResourceFacts,
) -> bool:
    target_kind = dependency["target_kind"]
    if target_kind == "key":
        return True
    if target_kind != "key_version":
        return False

    versioned_fields = (
        (dependency["key_uri"], key_facts.key_vault_key_uri),
        (dependency["key_resource_id"], key_facts.key_vault_key_resource_id),
        (dependency["key_version"], key_facts.key_vault_key_version),
    )
    return all(
        _known_string(dependency_value) is not None
        and _known_string(key_value) is not None
        and _same_optional_identifier(dependency_value, key_value)
        for dependency_value, key_value in versioned_fields
    )


def _dependency_source_is_current(
    dependency: AzureKeyVaultEncryptionDependency,
    parent: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    source = context.inventory.get_by_address(dependency["dependency_source_address"])
    if source is None or source.provider != "azure" or source.resource_type != dependency["dependency_source_type"]:
        return False
    if parent.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return source.address == parent.address
    if parent.resource_type != AzureResourceType.SERVICE_BUS_NAMESPACE:
        return False
    if source.address == parent.address:
        return True
    return bool(
        source.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY
        and azure_facts(source).resolved_service_bus_namespace_address == parent.address
    )


def _dependency_reference_is_coherent(
    dependency: AzureKeyVaultEncryptionDependency,
    key: NormalizedResource,
) -> bool:
    configured = _known_string(dependency["configured_key_reference"])
    target_kind = dependency["target_kind"]
    provenance = dependency["reference_provenance"]
    reference_kind = dependency["reference_kind"]
    if configured is None:
        return False
    if provenance == "planned_value":
        if target_kind == "key":
            if reference_kind == "versionless_uri":
                return _same_identifier(configured, dependency["key_versionless_uri"])
            if reference_kind == "versionless_resource_id":
                return _same_identifier(configured, dependency["key_versionless_resource_id"])
            return False
        if target_kind == "key_version":
            if reference_kind == "versioned_uri":
                return _same_identifier(configured, dependency["key_uri"])
            if reference_kind == "versioned_resource_id":
                return _same_identifier(configured, dependency["key_resource_id"])
            return False
        return False
    if provenance != "configuration_reference" or reference_kind != "terraform_reference":
        return False
    if target_kind == "key":
        return configured in {
            f"{key.address}.versionless_id",
            f"{key.address}.resource_versionless_id",
        }
    if target_kind == "key_version":
        return configured in {f"{key.address}.id", f"{key.address}.resource_id"}
    return False


def _logical_protected_data_dependencies(
    convergences: Sequence[_AzureProtectedDataConvergence],
) -> list[_AzureLogicalProtectedDataDependency]:
    grouped: dict[tuple[str, str, str, str, str, str], list[_AzureProtectedDataConvergence]] = {}
    for convergence in convergences:
        dependency = convergence["encryption_dependency"]
        fingerprint = (
            _protected_parent_address(convergence),
            convergence["key_address"],
            dependency["dependency_source_address"],
            repr(dependency["configuration_path"]),
            dependency["target_kind"] or "unknown",
            convergence["key_uri"] or "",
        )
        grouped.setdefault(fingerprint, []).append(convergence)

    logical: list[_AzureLogicalProtectedDataDependency] = []
    for (
        parent_address,
        key_address,
        source_address,
        configuration_path,
        _target_kind,
        _key_uri,
    ), proofs in grouped.items():
        representative = proofs[0]
        operation_scopes = tuple(
            sorted(
                {
                    f"{proof['key_operation_path']['scope_type']}:{proof['key_operation_path']['scope_arm_id']}"
                    for proof in proofs
                }
            )
        )
        operations: tuple[AzureKeyVaultOperation, ...] = tuple(
            cast(AzureKeyVaultOperation, operation)
            for operation in _OPERATION_ORDER
            if any(proof["operation"] == operation for proof in proofs)
        )
        authorization_proofs = {
            (
                proof["key_operation_path"]["grant_source_address"],
                proof["key_operation_path"]["grant_kind"],
                proof["key_operation_path"]["grant_basis"],
                proof["key_operation_path"]["scope_type"],
                proof["key_operation_path"]["scope_arm_id"] or "",
                proof["key_operation_path"]["role_definition_address"] or "",
            )
            for proof in proofs
        }
        protected_resources = tuple(
            sorted(
                {
                    (
                        _protected_resource_address(proof),
                        _protected_resource_type(proof),
                    )
                    for proof in proofs
                }
            )
        )
        logical.append(
            _AzureLogicalProtectedDataDependency(
                protected_resources=protected_resources,
                parent_address=parent_address,
                key_address=key_address,
                key_uri=representative["key_uri"],
                key_versionless_uri=representative["key_versionless_uri"],
                dependency_source_address=source_address,
                configuration_path=configuration_path,
                proof_count=len(authorization_proofs),
                operations=operations,
                authorization_scopes=operation_scopes,
            )
        )
    return sorted(
        logical,
        key=lambda dependency: (
            dependency.parent_address,
            dependency.key_address,
            dependency.dependency_source_address,
            dependency.configuration_path,
        ),
    )


def _protected_resource_address(convergence: _AzureProtectedDataConvergence) -> str:
    if "storage_resource_address" in convergence:
        return convergence["storage_resource_address"]
    return convergence["service_bus_resource_address"]


def _protected_resource_type(convergence: _AzureProtectedDataConvergence) -> str:
    if "storage_resource_address" in convergence:
        return convergence["access_path"]["storage_resource_type"]
    return convergence["service_bus_resource_type"]


def _protected_parent_address(convergence: _AzureProtectedDataConvergence) -> str:
    if "storage_resource_address" in convergence:
        return convergence["storage_account_address"]
    return convergence["service_bus_namespace_address"]


def _protected_data_dependent_addresses(
    dependencies: Sequence[_AzureLogicalProtectedDataDependency],
) -> list[str]:
    return sorted(
        {address for dependency in dependencies for address, _resource_type in dependency.protected_resources}
    )


def _protected_data_dependency_evidence(
    dependencies: Sequence[_AzureLogicalProtectedDataDependency],
) -> list[str]:
    dependent_addresses = _protected_data_dependent_addresses(dependencies)
    values = [
        (
            f"unique_dependency_count={len(dependencies)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            "downstream_dependency_state="
            f"{'resolved_dependents' if dependent_addresses else 'no_resolved_dependents'}"
        )
    ]
    values.extend(
        "; ".join(
            (
                "protected_resource_addresses="
                f"{','.join(address for address, _resource_type in dependency.protected_resources)}",
                "protected_resource_types="
                f"{','.join(resource_type for _address, resource_type in dependency.protected_resources)}",
                f"parent_address={dependency.parent_address}",
                f"key_address={dependency.key_address}",
                f"key_uri={dependency.key_uri or 'none'}",
                f"key_versionless_uri={dependency.key_versionless_uri}",
                f"dependency_source={dependency.dependency_source_address}",
                f"configuration_path={dependency.configuration_path}",
                f"operations={','.join(dependency.operations)}",
                f"authorization_proof_count={dependency.proof_count}",
                f"authorization_scopes={','.join(dependency.authorization_scopes)}",
            )
        )
        for dependency in dependencies
    )
    return values


def _protected_data_uncertainties(app: NormalizedResource) -> list[str]:
    facts = azure_facts(app)
    return sorted(
        {
            *facts.app_service_storage_protected_data_convergence_uncertainties,
            *facts.app_service_service_bus_protected_data_convergence_uncertainties,
        }
    )


def _authorization_scope(
    operation_class: _RuleOperationClass,
    operations: Sequence[AzureKeyVaultOperation],
    parent_scope: bool,
) -> list[str]:
    operation_text = _operation_text(operations) if operation_class == _DECRYPT_OPERATION else "signing"
    values = [
        f"establishes=deterministic Key Vault {operation_text} authority for the App Service runtime identity",
        "key_scope=versionless_key_authorization; key_versions_are_evidence_not_iam_scope",
        (
            "does_not_establish=useful ciphertext, plaintext recovery, accepted application signatures, key "
            "material possession, or runtime success outside modeled authorization evidence"
        ),
    ]
    if parent_scope:
        values.append(
            "blast_radius=parent-scope grant is broader than exact-key scope; out_of_plan_keys_are_not_modeled"
        )
    return values


def _path_operations(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
) -> list[AzureKeyVaultOperation]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _operation_text(operations: Sequence[AzureKeyVaultOperation]) -> str:
    if len(operations) == 1:
        return operations[0]
    if len(operations) == 2:
        return f"{operations[0]} and {operations[1]}"
    return ", ".join(operations[:-1]) + f", and {operations[-1]}"


def _plaintext_recovery_capability(operations: Sequence[AzureKeyVaultOperation]) -> str:
    operation_text = _operation_text(operations)
    if operations == ["decrypt"]:
        return "could submit ciphertext to Key Vault decrypt operations, creating plaintext-recovery and information-disclosure potential"
    if operations == ["unwrap"]:
        return "could submit wrapped key material to Key Vault unwrap operations, creating plaintext-recovery and information-disclosure potential"
    return (
        f"could submit ciphertext or wrapped key material to Key Vault {operation_text} operations, creating "
        "plaintext-recovery and information-disclosure potential"
    )


def _runtime_identity_evidence(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
) -> list[str]:
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


def _operation_path_evidence(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path.get('key_address')}",
                    f"key_vault_address={path.get('key_vault_address')}",
                    f"key_name={path.get('key_name') or 'unknown'}",
                    f"key_type={path.get('key_type') or 'unknown'}",
                    f"key_uri={path.get('key_uri') or 'none'}",
                    f"key_versionless_uri={path.get('key_versionless_uri') or 'none'}",
                    f"key_resource_id={path.get('key_resource_id') or 'none'}",
                    f"key_versionless_resource_id={path.get('key_versionless_resource_id') or 'none'}",
                    f"key_version={path.get('key_version') or 'none'}",
                    f"key_operations={','.join(_string_values(path.get('key_operations')))}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"matched_key_operation={path.get('matched_key_operation')}",
                    f"grant_kind={path.get('grant_kind')}",
                    f"grant_source={path.get('grant_source_address')}",
                    f"grant_source_type={path.get('grant_source_type')}",
                    f"scope_type={path.get('scope_type')}",
                    f"scope={path.get('scope')}",
                    f"scope_arm_id={path.get('scope_arm_id')}",
                    f"authorization_model={path.get('authorization_model')}",
                    f"authorization_state={path.get('authorization_state')}",
                    f"authorization_model_state={path.get('authorization_model_state')}",
                    f"management_state={path.get('management_state')}",
                    f"role={path.get('role_definition_name') or path.get('role_definition_id') or 'none'}",
                    f"role_definition_address={path.get('role_definition_address') or 'none'}",
                    f"matched_data_actions={','.join(_string_values(path.get('matched_data_actions')) or ['none'])}",
                    f"key_permissions={','.join(_string_values(path.get('key_permissions')) or ['none'])}",
                    f"condition_state={path.get('condition_state')}",
                    f"condition_applicability_state={path.get('condition_applicability_state') or 'not_applicable'}",
                    f"evaluation_basis={path.get('evaluation_basis')}",
                )
            )
            for path in paths
        }
    )


def _scope_breadth_evidence(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
) -> list[str]:
    grants_by_scope: dict[AzureKeyVaultPathScopeType, set[_GrantFingerprint]] = {
        scope_type: set() for scope_type in ("subscription", "resource_group", "vault", "key")
    }
    modeled_keys: set[str] = {path["key_address"] for path in paths}
    for path in paths:
        scope_type = path["scope_type"]
        if scope_type not in grants_by_scope:
            continue
        grants_by_scope[scope_type].add(
            (
                path.get("grant_source_address"),
                path.get("grant_kind"),
                path.get("grant_basis"),
                path.get("scope"),
                path.get("role_definition_id") or path.get("role_definition_name"),
            )
        )
    parent_grants = sum(len(grants_by_scope[value]) for value in _PARENT_SCOPE_TYPES)
    broadest_scope = next(
        (value for value in ("subscription", "resource_group", "vault", "key") if grants_by_scope[value]),
        "unknown",
    )
    return [
        (
            f"subscription_grants={len(grants_by_scope['subscription'])}; "
            f"resource_group_grants={len(grants_by_scope['resource_group'])}; "
            f"vault_grants={len(grants_by_scope['vault'])}; "
            f"exact_key_grants={len(grants_by_scope['key'])}; "
            f"parent_scope_grants={parent_grants}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"broadest_scope={broadest_scope}; "
            f"out_of_plan_keys_not_modeled=true; "
            f"blast_radius_basis={'parent_scope_grant' if parent_grants else 'exact_key_grant'}"
        )
    ]


def _path_values(
    paths: Sequence[AzureAppServiceKeyVaultOperationPath],
    key: _PathAddressKey,
) -> list[str]:
    return sorted({value for path in paths if (value := path.get(key)) is not None})


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
