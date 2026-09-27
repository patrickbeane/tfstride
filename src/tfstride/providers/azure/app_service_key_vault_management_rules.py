from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, SeverityReasoning
from tfstride.providers.azure.app_service_ingress_helpers import app_service_ingress
from tfstride.providers.azure.key_vault_dependency_evidence import (
    AzureKeyVaultEncryptionDependency,
)
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultManagementPath,
    AzureKeyVaultManagementEffect,
    AzureKeyVaultManagementOperation,
    AzureKeyVaultManagementOperationClass,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_ManagementRuleEffect = AzureKeyVaultManagementEffect
_ParentScopeTypes = frozenset({"subscription", "resource_group", "vault"})
_SupportedScopeTypes = frozenset({"subscription", "resource_group", "vault", "key"})
_RBAC_ROLE_ASSIGNMENTS_WRITE = "Microsoft.Authorization/roleAssignments/write"
_VAULT_WRITE = "Microsoft.KeyVault/vaults/write"
_ACCESS_POLICIES_WRITE = "Microsoft.KeyVault/vaults/accessPolicies/write"
_DataPlaneManagementOperation = Literal["update", "delete", "purge"]

_MANAGEMENT_OPERATION_DEFINITIONS: dict[
    AzureKeyVaultManagementOperation,
    tuple[AzureKeyVaultManagementOperationClass, AzureKeyVaultManagementEffect],
] = {
    "update": ("configuration_administration", "disruption"),
    "delete": ("destructive_administration", "disruption"),
    "delete_plus_purge": ("destructive_administration", "disruption"),
    "rbac_role_assignment_management": ("authorization_administration", "delegation"),
    "legacy_access_policy_mutation": ("authorization_administration", "delegation"),
    "authorization_model_mutation": ("authorization_administration", "delegation"),
}
_MANAGEMENT_OPERATION_ORDER: tuple[AzureKeyVaultManagementOperation, ...] = (
    "update",
    "delete",
    "delete_plus_purge",
    "rbac_role_assignment_management",
    "legacy_access_policy_mutation",
    "authorization_model_mutation",
)
_EXPECTED_DATA_PLANE_STEPS: dict[
    AzureKeyVaultManagementOperation,
    frozenset[_DataPlaneManagementOperation],
] = {
    "update": frozenset({"update"}),
    "delete": frozenset({"delete"}),
    "delete_plus_purge": frozenset({"delete", "purge"}),
}


class AzureAppServiceKeyVaultManagementRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_key_vault_key_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def detect_public_app_service_key_vault_authorization_delegation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "delegation")

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: _ManagementRuleEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths = [
                path
                for path in azure_facts(app).app_service_key_vault_management_paths
                if path.get("management_effect") == management_effect
                and _is_deterministic_management_path(path, app, context, management_effect)
            ]
            if not paths:
                continue

            target_addresses = _path_addresses(paths, "target_address")
            key_addresses = _path_addresses(paths, "key_address")
            vault_addresses = _path_addresses(paths, "key_vault_address")
            identity_addresses = _path_addresses(paths, "identity_address")
            grant_addresses = _grant_source_addresses(paths)
            role_definition_addresses = _role_definition_addresses(paths)
            downstream_dependencies = (
                _resolved_downstream_dependencies(paths, context) if management_effect == "disruption" else []
            )
            downstream_dependent_addresses = _downstream_dependent_addresses(downstream_dependencies)
            recovery_evidence = _recovery_evidence(paths, context) if management_effect == "disruption" else []
            parent_scope = any(
                scope_type in _ParentScopeTypes
                for path in paths
                for scope_type in _string_values(path.get("scope_types"))
            )
            operations = _management_operations(paths)
            severity_reasoning = _management_severity(
                management_effect,
                parent_scope=parent_scope,
                target_count=len(target_addresses),
                downstream_dependent_count=len(downstream_dependent_addresses),
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *identity_addresses,
                            *vault_addresses,
                            *key_addresses,
                            *target_addresses,
                            *grant_addresses,
                            *role_definition_addresses,
                            *downstream_dependent_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_management_rationale(
                        app,
                        operations,
                        len(target_addresses),
                        management_effect,
                        parent_scope=parent_scope,
                        downstream_dependent_count=len(downstream_dependent_addresses),
                        downstream_dependency_count=len(downstream_dependencies),
                        recovery_evidence=recovery_evidence,
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("key_vault_management_paths", _management_path_evidence(paths)),
                        evidence_item("scope_breadth", _scope_breadth_evidence(paths)),
                        evidence_item(
                            "authorization_scope",
                            _authorization_scope(
                                operations,
                                management_effect,
                                paths,
                                parent_scope=parent_scope,
                            ),
                        ),
                        *(
                            [
                                evidence_item(
                                    "downstream_dependencies",
                                    _downstream_dependency_evidence(downstream_dependencies),
                                ),
                                evidence_item(
                                    "recovery_posture",
                                    recovery_evidence,
                                ),
                            ]
                            if management_effect == "disruption"
                            else []
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_management_path(
    path: AzureAppServiceKeyVaultManagementPath,
    app: NormalizedResource,
    context: RuleEvaluationContext,
    management_effect: _ManagementRuleEffect,
) -> bool:
    operation = path.get("operation")
    operation_definition = _MANAGEMENT_OPERATION_DEFINITIONS.get(operation) if isinstance(operation, str) else None
    if (
        operation_definition is None
        or operation_definition != (path.get("operation_class"), path.get("management_effect"))
        or path.get("management_effect") != management_effect
        or path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("authorization_state") != "granted"
        or path.get("authorization_model_state") != "active"
        or path.get("target_type") not in {"key", "vault"}
        or path.get("scope_types") == []
        or path.get("scope_arm_ids") == []
    ):
        return False

    identity = _runtime_identity(path, app, context)
    if identity is None:
        return False

    target_address = _known_string(path.get("target_address"))
    target = context.inventory.get_by_address(target_address) if target_address is not None else None
    if target is None or not _target_matches_path(path, target, context):
        return False

    if management_effect == "disruption":
        return _is_deterministic_disruption_path(path, target, context)
    return _is_deterministic_delegation_path(path, target, context)


def _runtime_identity(
    path: AzureAppServiceKeyVaultManagementPath,
    app: NormalizedResource,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    identity_address = _known_string(path.get("identity_address"))
    principal_id = _known_string(path.get("principal_id"))
    if identity_address is None or principal_id is None:
        return None

    identity = context.inventory.get_by_address(identity_address)
    if identity is None:
        return None
    identity_facts = azure_facts(identity)
    if _known_string(identity_facts.principal_id) != principal_id:
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


def _target_matches_path(
    path: AzureAppServiceKeyVaultManagementPath,
    target: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    target_type = path.get("target_type")
    target_resource_id = _known_string(path.get("target_resource_id"))
    key_vault_address = _known_string(path.get("key_vault_address"))
    key_vault_id = _known_string(path.get("key_vault_id"))
    vault = context.inventory.get_by_address(key_vault_address) if key_vault_address is not None else None
    if (
        vault is None
        or vault.resource_type != AzureResourceType.KEY_VAULT
        or _known_string(azure_facts(vault).key_vault_id) is None
        or key_vault_id is None
        or not _same_identifier(key_vault_id, azure_facts(vault).key_vault_id)
    ):
        return False

    if target_type == "vault":
        return bool(
            target.resource_type == AzureResourceType.KEY_VAULT
            and target.address == vault.address
            and target_resource_id is not None
            and _same_identifier(target_resource_id, azure_facts(vault).key_vault_id)
            and path.get("key_address") is None
            and path.get("key_resource_type") is None
            and path.get("authorization_basis") == "azure_control_plane_role_assignment"
        )

    if target_type != "key" or target.resource_type != AzureResourceType.KEY_VAULT_KEY:
        return False
    key_facts = azure_facts(target)
    expected_key_id = _known_string(key_facts.key_vault_key_versionless_resource_id)
    if (
        expected_key_id is None
        or target_resource_id is None
        or not _same_identifier(target_resource_id, expected_key_id)
        or path.get("key_address") != target.address
        or path.get("key_resource_type") != AzureResourceType.KEY_VAULT_KEY
        or key_facts.key_vault_key_identity_state != "resolved"
        or key_facts.resolved_key_vault_address != vault.address
        or path.get("authorization_basis") not in {"key_vault_data_plane_grant", "azure_control_plane_role_assignment"}
    ):
        return False
    return _key_identity_matches_path(path, key_facts)


def _key_identity_matches_path(
    path: AzureAppServiceKeyVaultManagementPath,
    facts: object,
) -> bool:
    pairs = (
        (path.get("key_name"), getattr(facts, "key_vault_key_name", None)),
        (path.get("key_uri"), getattr(facts, "key_vault_key_uri", None)),
        (path.get("key_versionless_uri"), getattr(facts, "key_vault_key_versionless_uri", None)),
        (path.get("key_resource_id"), getattr(facts, "key_vault_key_resource_id", None)),
        (path.get("key_versionless_resource_id"), getattr(facts, "key_vault_key_versionless_resource_id", None)),
        (path.get("key_version"), getattr(facts, "key_vault_key_version", None)),
    )
    return all(_same_optional_identifier(left, right) for left, right in pairs)


def _is_deterministic_disruption_path(
    path: AzureAppServiceKeyVaultManagementPath,
    target: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    if operation not in {"update", "delete", "delete_plus_purge"}:
        return False
    expected_operations = _EXPECTED_DATA_PLANE_STEPS.get(operation)
    actual_operations = frozenset(_string_values(path.get("step_operations")))
    if expected_operations is None or actual_operations != expected_operations:
        return False
    if (
        path.get("authorization_basis") != "key_vault_data_plane_grant"
        or path.get("delegation_mechanism") != "not_applicable"
        or path.get("evaluation_basis") != "modeled_key_vault_key_authorization"
        or path.get("target_type") != "key"
        or target.resource_type != AzureResourceType.KEY_VAULT_KEY
        or path.get("lifecycle_compatibility_state") != "compatible"
        or path.get("control_plane_grants") != []
    ):
        return False
    vault_address = _known_string(path.get("key_vault_address"))
    vault = context.inventory.get_by_address(vault_address) if vault_address is not None else None
    current_purge_protection = (
        azure_facts(vault).purge_protection_enabled
        if vault is not None and vault.resource_type == AzureResourceType.KEY_VAULT
        else None
    )
    if path.get("purge_protection_enabled") is not current_purge_protection:
        return False
    if operation == "delete_plus_purge" and current_purge_protection is not False:
        return False
    grants = path.get("data_plane_grants")
    if not isinstance(grants, list) or not grants or not all(isinstance(grant, Mapping) for grant in grants):
        return False
    typed_grants = [cast(Mapping[str, object], grant) for grant in grants]
    matched_operations = {
        operation_name for grant in typed_grants for operation_name in _string_values(grant.get("matched_operations"))
    }
    return expected_operations <= matched_operations and all(
        _is_valid_data_grant(grant, path, target, context) for grant in typed_grants
    )


def _is_valid_data_grant(
    grant: Mapping[str, object],
    path: AzureAppServiceKeyVaultManagementPath,
    key: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    source_address = _known_string(grant.get("grant_source_address"))
    path_sources = set(_string_values(path.get("grant_source_addresses")))
    source = context.inventory.get_by_address(source_address) if source_address is not None else None
    if (
        source is None
        or source_address not in path_sources
        or grant.get("key_address") != key.address
        or grant.get("key_vault_address") != path.get("key_vault_address")
        or grant.get("authorization_state") != "granted"
        or grant.get("authorization_model_state") != "active"
        or grant.get("principal_state") != "resolved"
        or grant.get("condition_state") != "not_configured"
        or grant.get("grant_scope_type") not in _SupportedScopeTypes
        or _known_string(grant.get("principal_id")) != _known_string(path.get("principal_id"))
    ):
        return False
    if grant.get("grant_kind") == "access_policy":
        return bool(
            source.resource_type in {AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY}
            and grant.get("authorization_model") == "access_policy"
            and grant.get("management_state") == "unambiguous"
            and grant.get("grant_scope_type") == "vault"
        )
    if grant.get("grant_kind") == "rbac":
        return bool(
            source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
            and grant.get("authorization_model") == "azure_rbac"
            and grant.get("key_vault_address") == path.get("key_vault_address")
        )
    return False


def _is_deterministic_delegation_path(
    path: AzureAppServiceKeyVaultManagementPath,
    target: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    operation = path.get("operation")
    if operation not in {
        "rbac_role_assignment_management",
        "legacy_access_policy_mutation",
        "authorization_model_mutation",
    }:
        return False
    if (
        path.get("authorization_basis") != "azure_control_plane_role_assignment"
        or path.get("evaluation_basis") != "modeled_arm_control_plane_authority"
        or path.get("data_plane_grants") != []
        or path.get("lifecycle_compatibility_state") != "not_applicable"
        or path.get("authorization_model_transition")
        != ("azure_rbac_to_access_policy" if operation == "authorization_model_mutation" else None)
    ):
        return False
    if operation == "rbac_role_assignment_management":
        if (
            path.get("target_type") not in {"vault", "key"}
            or path.get("delegation_mechanism") != "azure_rbac_role_assignment"
        ):
            return False
    elif operation == "legacy_access_policy_mutation":
        if path.get("target_type") != "vault" or path.get("delegation_mechanism") != "legacy_access_policy":
            return False
    elif operation == "authorization_model_mutation":
        if (
            path.get("target_type") != "vault"
            or path.get("delegation_mechanism") != "authorization_model_transition"
            or path.get("authorization_model_transition") != "azure_rbac_to_access_policy"
        ):
            return False
    grants = path.get("control_plane_grants")
    if not isinstance(grants, list) or not grants or not all(isinstance(grant, Mapping) for grant in grants):
        return False
    typed_grants = [cast(Mapping[str, object], grant) for grant in grants]
    return all(_is_valid_control_grant(grant, path, target, operation, context) for grant in typed_grants)


def _is_valid_control_grant(
    grant: Mapping[str, object],
    path: AzureAppServiceKeyVaultManagementPath,
    target: NormalizedResource,
    operation: object,
    context: RuleEvaluationContext,
) -> bool:
    source_address = _known_string(grant.get("source_address"))
    path_sources = set(_string_values(path.get("grant_source_addresses")))
    source = context.inventory.get_by_address(source_address) if source_address is not None else None
    target_id = _known_string(path.get("target_resource_id"))
    matched_actions = set(_string_values(grant.get("matched_actions")))
    if (
        source is None
        or source.resource_type != AzureResourceType.ROLE_ASSIGNMENT
        or source_address not in path_sources
        or target_id is None
        or not _same_identifier(grant.get("target_arm_id"), target_id)
        or grant.get("authorization_state") != "granted"
        or grant.get("assignment_scope_state") != "resolved"
        or grant.get("evaluation_basis") != "modeled_arm_control_plane_authority"
        or grant.get("principal_state") != "resolved"
        or grant.get("assignment_condition_state") != "not_configured"
        or _known_string(grant.get("principal_id")) != _known_string(path.get("principal_id"))
    ):
        return False
    if operation == "rbac_role_assignment_management":
        return _RBAC_ROLE_ASSIGNMENTS_WRITE in matched_actions and path.get("authorization_model") == "azure_rbac"
    if operation == "legacy_access_policy_mutation":
        return (
            bool(matched_actions & {_VAULT_WRITE, _ACCESS_POLICIES_WRITE})
            and path.get("authorization_model") == "access_policy"
        )
    if operation == "authorization_model_mutation":
        return _VAULT_WRITE in matched_actions and path.get("authorization_model") == "azure_rbac"
    return False


def _management_operations(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[AzureKeyVaultManagementOperation]:
    return [
        operation
        for operation in _MANAGEMENT_OPERATION_ORDER
        if any(path.get("operation") == operation for path in paths)
    ]


def _management_severity(
    management_effect: _ManagementRuleEffect,
    *,
    parent_scope: bool,
    target_count: int,
    downstream_dependent_count: int = 0,
) -> SeverityReasoning:
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=2,
        data_sensitivity=1,
        lateral_movement=1,
        blast_radius=(2 if parent_scope or target_count > 1 or downstream_dependent_count > 1 else 1),
    )


def _management_rationale(
    app: NormalizedResource,
    operations: Sequence[AzureKeyVaultManagementOperation],
    target_count: int,
    management_effect: _ManagementRuleEffect,
    *,
    parent_scope: bool,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
    recovery_evidence: Sequence[str] = (),
) -> str:
    operation_text = _operation_text(operations)
    if management_effect == "disruption":
        capability = "deterministic Key Vault disruption authority"
        consequence = "could alter or destroy Key Vault key availability"
    else:
        capability = "deterministic Key Vault authorization-delegation authority"
        consequence = "could grant or transition further Key Vault authorization"
    if parent_scope:
        scope_text = (
            "At least one modeled grant is parent-scoped, so its potential blast radius is broader than an exact-key "
            "grant; out-of-plan keys are not modeled."
        )
    else:
        scope_text = "The modeled grant targets are limited to exact Key Vault key or vault scope."
    downstream_text = ""
    recovery_text = ""
    if management_effect == "disruption":
        downstream_text = (
            f" The modeled keys have {downstream_dependent_count} unique downstream encrypted "
            f"dependent resource(s) across {downstream_dependency_count} unique dependency relationship(s)."
            if downstream_dependent_count
            else " No resolved downstream encrypted dependent resources are modeled for these keys."
        )
        recovery_text = (
            f" Recovery evidence: {', '.join(recovery_evidence)}."
            if recovery_evidence
            else " Recovery evidence is unavailable or not applicable to these operations."
        )
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has {capability} "
        f"({operation_text}) on {target_count} exact modeled Key Vault management target(s). A compromise of the "
        f"public workload {consequence}. {scope_text}{downstream_text}{recovery_text} This establishes modeled "
        "management authority, not proof that an operation will succeed outside the preserved Azure scope, role, "
        "grant, lifecycle, and condition evidence, and not that the Key Vault or key is itself public."
    )


def _authorization_scope(
    operations: Sequence[AzureKeyVaultManagementOperation],
    management_effect: _ManagementRuleEffect,
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
    *,
    parent_scope: bool,
) -> list[str]:
    effect_text = "key disruption" if management_effect == "disruption" else "authorization delegation"
    scope_types = sorted({scope_type for path in paths for scope_type in _string_values(path.get("scope_types"))})
    target_types = sorted({value for path in paths if (value := _known_string(path.get("target_type"))) is not None})
    values = [
        f"establishes=deterministic {_operation_text(operations)} authority with {effect_text} effect for the App Service runtime identity",
        f"target_granularity={','.join(target_types) or 'unknown'}; target_count={len({path.get('target_address') for path in paths})}",
        f"native_scopes={','.join(scope_types) or 'unknown'}",
        "key_versions_are_evidence_not_independent_authorization_scope",
        (
            "does_not_establish=successful operation completion, authority over out-of-plan keys, external deny-state "
            "evaluation, or runtime impact beyond modeled Azure authorization evidence"
        ),
    ]
    if parent_scope:
        values.append(
            "blast_radius=parent-scope grant is broader than exact-key scope; out_of_plan_keys_not_modeled=true"
        )
    return values


def _operation_text(operations: Sequence[AzureKeyVaultManagementOperation]) -> str:
    labels = {
        "update": "key update",
        "delete": "key deletion",
        "delete_plus_purge": "key deletion and purge",
        "rbac_role_assignment_management": "RBAC role-assignment management",
        "legacy_access_policy_mutation": "legacy access-policy mutation",
        "authorization_model_mutation": "RBAC-to-access-policy model transition",
    }
    values = [labels[operation] for operation in operations]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _runtime_identity_evidence(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
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


def _management_path_evidence(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"management_effect={path.get('management_effect')}",
                    f"target_type={path.get('target_type')}",
                    f"target_address={path.get('target_address')}",
                    f"target_resource_id={path.get('target_resource_id')}",
                    f"key_address={path.get('key_address') or 'none'}",
                    f"key_uri={path.get('key_uri') or 'none'}",
                    f"key_versionless_uri={path.get('key_versionless_uri') or 'none'}",
                    f"key_resource_id={path.get('key_resource_id') or 'none'}",
                    f"key_versionless_resource_id={path.get('key_versionless_resource_id') or 'none'}",
                    f"key_version={path.get('key_version') or 'none'}",
                    f"authorization_basis={path.get('authorization_basis')}",
                    f"authorization_model={path.get('authorization_model')}",
                    f"authorization_state={path.get('authorization_state')}",
                    f"delegation_mechanism={path.get('delegation_mechanism')}",
                    f"grant_sources={','.join(_string_values(path.get('grant_source_addresses')) or ['none'])}",
                    f"scope_types={','.join(_string_values(path.get('scope_types')) or ['none'])}",
                    f"scope_arm_ids={','.join(_string_values(path.get('scope_arm_ids')) or ['none'])}",
                    f"step_operations={','.join(_string_values(path.get('step_operations')) or ['none'])}",
                    f"deletion_impact={_deletion_impact(path)}",
                    f"purge_protection_enabled={path.get('purge_protection_enabled')}",
                    f"lifecycle_compatibility={path.get('lifecycle_compatibility_state')}",
                    f"authorization_model_transition={path.get('authorization_model_transition') or 'none'}",
                    f"data_plane_grants={','.join(_data_grant_evidence(path) or ['none'])}",
                    f"control_plane_grants={','.join(_control_grant_evidence(path) or ['none'])}",
                )
            )
            for path in paths
        }
    )


def _deletion_impact(path: AzureAppServiceKeyVaultManagementPath) -> str:
    operation = path.get("operation")
    if operation == "delete":
        return "recoverable_soft_delete"
    if operation == "delete_plus_purge":
        return "permanent_delete_sequence"
    return "not_applicable"


def _resolved_downstream_dependencies(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
    context: RuleEvaluationContext,
) -> list[AzureKeyVaultEncryptionDependency]:
    dependencies: list[AzureKeyVaultEncryptionDependency] = []
    seen: set[tuple[str, str, str, str]] = set()
    destructive_key_addresses = {
        key_address
        for path in paths
        if path.get("operation") in {"delete", "delete_plus_purge"}
        if (key_address := _known_string(path.get("key_address"))) is not None
    }
    update_paths_by_key: dict[str, list[AzureAppServiceKeyVaultManagementPath]] = {}
    for path in paths:
        if path.get("operation") != "update":
            continue
        key_address = _known_string(path.get("key_address"))
        if key_address is not None:
            update_paths_by_key.setdefault(key_address, []).append(path)

    for key_address in destructive_key_addresses | set(update_paths_by_key):
        key = context.inventory.get_by_address(key_address)
        if key is None or key.resource_type != AzureResourceType.KEY_VAULT_KEY:
            continue
        key_facts = azure_facts(key)
        for dependency in key_facts.key_vault_encryption_dependencies:
            if (
                dependency.get("resolution_state") != "resolved"
                or dependency.get("key_address") != key_address
                or not _dependency_reference_contract_is_coherent(dependency)
                or not _dependency_matches_key_identity(dependency, key, context)
            ):
                continue

            target_kind = dependency.get("target_kind")
            applicable = key_address in destructive_key_addresses and target_kind in {"key", "key_version"}
            if not applicable and key_address in update_paths_by_key:
                applicable = any(
                    target_kind == "key_version" and _dependency_matches_update_version(dependency, update_path)
                    for update_path in update_paths_by_key[key_address]
                )
            if not applicable:
                continue

            dependent_address = dependency.get("dependent_address")
            source_address = dependency.get("dependency_source_address")
            configuration_path = repr(dependency.get("configuration_path"))
            if not isinstance(dependent_address, str) or not isinstance(source_address, str):
                continue
            dependent = context.inventory.get_by_address(dependent_address)
            source = context.inventory.get_by_address(source_address)
            if (
                dependent is None
                or source is None
                or dependent.provider != "azure"
                or source.provider != "azure"
                or dependency.get("dependent_resource_type") != dependent.resource_type
                or dependency.get("dependency_source_type") != source.resource_type
            ):
                continue

            fingerprint = (key_address, dependent_address, source_address, configuration_path)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            dependencies.append(dependency)

    return sorted(
        dependencies,
        key=lambda dependency: (
            str(dependency.get("dependent_address")),
            str(dependency.get("dependency_source_address")),
            repr(dependency.get("configuration_path")),
            str(dependency.get("key_address")),
        ),
    )


def _dependency_matches_update_version(
    dependency: AzureKeyVaultEncryptionDependency,
    path: AzureAppServiceKeyVaultManagementPath,
) -> bool:
    if dependency.get("target_kind") != "key_version":
        return False
    return all(
        (expected := _known_string(path.get(field))) is not None and _same_identifier(dependency.get(field), expected)
        for field in ("key_uri", "key_resource_id", "key_version")
    )


def _dependency_reference_contract_is_coherent(
    dependency: AzureKeyVaultEncryptionDependency,
) -> bool:
    provenance = dependency.get("reference_provenance")
    reference_kind = dependency.get("reference_kind")
    configured = _known_string(dependency.get("configured_key_reference"))
    target_kind = dependency.get("target_kind")

    if provenance == "planned_value":
        if target_kind == "key":
            if reference_kind == "versionless_uri":
                return _same_identifier(configured, dependency.get("key_versionless_uri"))
            if reference_kind == "versionless_resource_id":
                return _same_identifier(
                    configured,
                    dependency.get("key_versionless_resource_id"),
                )
            return False
        if target_kind == "key_version":
            if reference_kind == "versioned_uri":
                return _same_identifier(configured, dependency.get("key_uri"))
            if reference_kind == "versioned_resource_id":
                return _same_identifier(configured, dependency.get("key_resource_id"))
            return False
        return False

    if provenance != "configuration_reference" or reference_kind != "terraform_reference" or configured is None:
        return False
    normalized = configured.casefold()
    if target_kind == "key":
        return normalized.endswith(".versionless_id") or normalized.endswith(".resource_versionless_id")
    if target_kind == "key_version":
        return (normalized.endswith(".id") or normalized.endswith(".resource_id")) and not (
            normalized.endswith(".versionless_id") or normalized.endswith(".resource_versionless_id")
        )
    return False


def _dependency_matches_key_identity(
    dependency: AzureKeyVaultEncryptionDependency,
    key: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    key_facts = azure_facts(key)
    if dependency.get("candidate_key_addresses") != [key.address]:
        return False
    target_kind = dependency.get("target_kind")
    if target_kind == "key":
        if not any(
            dependency.get(field) is not None for field in ("key_versionless_uri", "key_versionless_resource_id")
        ):
            return False
    elif target_kind == "key_version":
        if not any(dependency.get(field) is not None for field in ("key_uri", "key_resource_id", "key_version")):
            return False
    else:
        return False
    recorded_vault_address = dependency.get("key_vault_address")
    if recorded_vault_address is not None and recorded_vault_address != key_facts.resolved_key_vault_address:
        return False

    identity_pairs = (
        ("key_name", key_facts.key_vault_key_name),
        ("key_version", key_facts.key_vault_key_version),
        ("key_uri", key_facts.key_vault_key_uri),
        ("key_versionless_uri", key_facts.key_vault_key_versionless_uri),
        ("key_resource_id", key_facts.key_vault_key_resource_id),
        ("key_versionless_resource_id", key_facts.key_vault_key_versionless_resource_id),
    )
    if any(
        recorded is not None and not _same_identifier(recorded, expected)
        for field, expected in identity_pairs
        if (recorded := dependency.get(field)) is not None
    ):
        return False

    vault_address = key_facts.resolved_key_vault_address
    if vault_address is None:
        return True
    vault = context.inventory.get_by_address(vault_address)
    if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
        return False
    vault_facts = azure_facts(vault)
    vault_pairs = (
        ("key_vault_id", vault_facts.key_vault_id),
        ("key_vault_uri", vault_facts.key_vault_uri),
    )
    return all(
        recorded is None or _same_identifier(recorded, expected)
        for field, expected in vault_pairs
        if (recorded := dependency.get(field)) is not None
    )


def _downstream_dependent_addresses(
    dependencies: Sequence[AzureKeyVaultEncryptionDependency],
) -> list[str]:
    return sorted(
        {
            value
            for dependency in dependencies
            if isinstance(value := dependency.get("dependent_address"), str) and value
        }
    )


def _downstream_dependency_evidence(
    dependencies: Sequence[AzureKeyVaultEncryptionDependency],
) -> list[str]:
    dependent_addresses = _downstream_dependent_addresses(dependencies)
    values = [
        (
            f"unique_dependency_count={len(dependencies)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            "blast_radius_basis="
            f"{'downstream_encrypted_dependents' if dependent_addresses else 'no_resolved_downstream_dependents'}"
        )
    ]
    values.extend(
        "; ".join(
            (
                f"key_address={dependency.get('key_address') or 'unknown'}",
                f"dependent_address={dependency.get('dependent_address') or 'unknown'}",
                f"dependency_source={dependency.get('dependency_source_address') or 'unknown'}",
                f"configuration_path={dependency.get('configuration_path') or 'unknown'}",
                f"reference_kind={dependency.get('reference_kind') or 'unknown'}",
                f"target_kind={dependency.get('target_kind') or 'unknown'}",
                f"key_uri={dependency.get('key_uri') or 'none'}",
                f"key_versionless_uri={dependency.get('key_versionless_uri') or 'none'}",
            )
        )
        for dependency in dependencies
    )
    return values


def _recovery_evidence(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
    context: RuleEvaluationContext,
) -> list[str]:
    values: list[str] = []
    for path in paths:
        operation = path.get("operation")
        if operation not in {"delete", "delete_plus_purge"}:
            continue
        vault_address = _known_string(path.get("key_vault_address"))
        vault = context.inventory.get_by_address(vault_address) if vault_address is not None else None
        if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
            continue
        current_purge_protection = azure_facts(vault).purge_protection_enabled
        if path.get("purge_protection_enabled") is not current_purge_protection:
            continue
        if operation == "delete_plus_purge" and current_purge_protection is not False:
            continue
        values.append(
            "; ".join(
                (
                    f"key_address={path.get('key_address') or 'unknown'}",
                    f"key_vault_address={path.get('key_vault_address') or 'unknown'}",
                    f"operation={operation}",
                    f"purge_protection_enabled={path.get('purge_protection_enabled')}",
                    (
                        "recovery_state=recoverable_soft_delete"
                        if operation == "delete"
                        else "recovery_state=permanent_delete_sequence"
                    ),
                )
            )
        )
    return sorted(set(values))


def _scope_breadth_evidence(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[str]:
    grants_by_scope: dict[str, set[tuple[str, ...]]] = {
        scope_type: set() for scope_type in ("subscription", "resource_group", "vault", "key")
    }
    modeled_targets = {
        (path.get("target_type"), path.get("target_address"))
        for path in paths
        if _known_string(path.get("target_address")) is not None
    }
    modeled_keys = {value for path in paths if (value := _known_string(path.get("key_address"))) is not None}
    target_paths = len(paths)
    for path in paths:
        data_grants = path.get("data_plane_grants")
        control_grants = path.get("control_plane_grants")
        if isinstance(data_grants, list):
            for grant in data_grants:
                if not isinstance(grant, Mapping):
                    continue
                fingerprint = (
                    _known_string(grant.get("grant_source_address")) or "",
                    _known_string(grant.get("grant_kind")) or "",
                    _known_string(grant.get("grant_basis")) or "",
                    _known_string(grant.get("grant_scope")) or "",
                    _known_string(grant.get("role_definition_id"))
                    or _known_string(grant.get("role_definition_name"))
                    or "",
                )
                scope_type = _known_string(grant.get("grant_scope_type"))
                if scope_type in grants_by_scope:
                    grants_by_scope[scope_type].add(fingerprint)
        if isinstance(control_grants, list):
            for grant in control_grants:
                if not isinstance(grant, Mapping):
                    continue
                fingerprint = (
                    _known_string(grant.get("source_address")) or "",
                    _known_string(grant.get("assignment_scope")) or "",
                    _known_string(grant.get("role_definition_id"))
                    or _known_string(grant.get("role_definition_name"))
                    or "",
                    _known_string(grant.get("target_arm_id")) or "",
                )
                scope_type = _known_string(grant.get("assignment_scope_type"))
                if scope_type in grants_by_scope:
                    grants_by_scope[scope_type].add(fingerprint)
    parent_grants = sum(len(grants_by_scope[scope_type]) for scope_type in ("subscription", "resource_group", "vault"))
    broadest_scope = next(
        (
            scope_type
            for scope_type in ("subscription", "resource_group", "vault", "key")
            if grants_by_scope[scope_type]
        ),
        "unknown",
    )
    return [
        (
            f"subscription_grants={len(grants_by_scope['subscription'])}; "
            f"resource_group_grants={len(grants_by_scope['resource_group'])}; "
            f"vault_grants={len(grants_by_scope['vault'])}; "
            f"exact_key_grants={len(grants_by_scope['key'])}; "
            f"target_paths={target_paths}; "
            f"modeled_targets={len(modeled_targets)}; "
            f"modeled_keys={len(modeled_keys)}; "
            f"broadest_scope={broadest_scope}; "
            "out_of_plan_keys_not_modeled=true; "
            f"blast_radius_basis={'parent_scope_grant' if parent_grants else 'exact_target_grant'}"
        )
    ]


def _data_grant_evidence(path: AzureAppServiceKeyVaultManagementPath) -> list[str]:
    grants = path.get("data_plane_grants")
    if not isinstance(grants, list):
        return []
    return sorted(
        {
            ";".join(
                (
                    f"source={grant.get('grant_source_address')}",
                    f"kind={grant.get('grant_kind')}",
                    f"operations={','.join(_string_values(grant.get('matched_operations')))}",
                    f"scope_type={grant.get('grant_scope_type')}",
                    f"scope={grant.get('grant_scope') or 'none'}",
                    f"principal_id={grant.get('principal_id') or 'none'}",
                    f"condition_state={grant.get('condition_state')}",
                )
            )
            for grant in grants
            if isinstance(grant, Mapping)
        }
    )


def _control_grant_evidence(path: AzureAppServiceKeyVaultManagementPath) -> list[str]:
    grants = path.get("control_plane_grants")
    if not isinstance(grants, list):
        return []
    return sorted(
        {
            ";".join(
                (
                    f"source={grant.get('source_address')}",
                    f"scope_type={grant.get('assignment_scope_type')}",
                    f"scope_arm_id={grant.get('assignment_scope_arm_id')}",
                    f"target_arm_id={grant.get('target_arm_id')}",
                    f"role={grant.get('role_definition_name') or grant.get('role_definition_id') or 'none'}",
                    f"role_definition_address={grant.get('role_definition_address') or 'none'}",
                    f"matched_actions={','.join(_string_values(grant.get('matched_actions')))}",
                    f"role_resolution_state={grant.get('role_resolution_state')}",
                    f"assignment_condition_state={grant.get('assignment_condition_state')}",
                    f"role_definition_condition_state={grant.get('role_definition_condition_state')}",
                    f"delegation_constraint={grant.get('delegation_constraint_kind')}",
                    f"allowed_role_definition_ids={','.join(_string_values(grant.get('allowed_role_definition_ids')) or ['none'])}",
                    f"deny_assignments_evaluated={str(grant.get('deny_assignments_evaluated')).lower()}",
                )
            )
            for grant in grants
            if isinstance(grant, Mapping)
        }
    )


def _path_addresses(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
    field: Literal["target_address", "key_address", "key_vault_address", "identity_address"],
) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(field))) is not None})


def _grant_source_addresses(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[str]:
    return sorted({address for path in paths for address in _string_values(path.get("grant_source_addresses"))})


def _role_definition_addresses(
    paths: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[str]:
    addresses: set[str] = set()
    for path in paths:
        grants = path.get("control_plane_grants")
        if not isinstance(grants, list):
            continue
        addresses.update(
            address
            for grant in grants
            if isinstance(grant, Mapping)
            if (address := _known_string(grant.get("role_definition_address"))) is not None
        )
    return sorted(addresses)


def _same_optional_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    if left_value is None or right_value is None:
        return left_value is None and right_value is None
    return left_value.casefold() == right_value.casefold()


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return left_value is not None and right_value is not None and left_value.casefold() == right_value.casefold()


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
