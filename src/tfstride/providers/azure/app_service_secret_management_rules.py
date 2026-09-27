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
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.azure.app_service_ingress_helpers import app_service_ingress
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.azure.secret_management_evidence import (
    AzureAppServiceKeyVaultSecretManagementPath,
    AzureKeyVaultSecretAuthorizationGrant,
    AzureKeyVaultSecretGrantOperation,
    AzureKeyVaultSecretManagementEffect,
    AzureKeyVaultSecretManagementOperation,
    AzureKeyVaultSecretOperationClass,
)

_SecretManagementRuleEffect = AzureKeyVaultSecretManagementEffect
_ScopeType = Literal["subscription", "resource_group", "vault", "secret"]
_SCOPE_ORDER: tuple[_ScopeType, ...] = (
    "subscription",
    "resource_group",
    "vault",
    "secret",
)
_SECRET_MANAGEMENT_DEFINITIONS: dict[
    AzureKeyVaultSecretManagementOperation,
    tuple[AzureKeyVaultSecretOperationClass, AzureKeyVaultSecretManagementEffect],
] = {
    "set": ("value_mutation", "tampering"),
    "delete": ("destructive_administration", "disruption"),
    "delete_plus_purge": ("destructive_administration", "disruption"),
}
_OPERATION_ORDER: tuple[AzureKeyVaultSecretManagementOperation, ...] = (
    "set",
    "delete",
    "delete_plus_purge",
)
_EXPECTED_STEPS: dict[
    AzureKeyVaultSecretManagementOperation,
    tuple[AzureKeyVaultSecretGrantOperation, ...],
] = {
    "set": ("set",),
    "delete": ("delete",),
    "delete_plus_purge": ("delete", "purge"),
}
_SUPPORTED_GRANT_SCOPES = frozenset(_SCOPE_ORDER)
_SUPPORTED_GRANT_OPERATIONS = frozenset({"set", "delete", "purge"})


class AzureAppServiceSecretManagementRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_app_service_secret_tampering(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "tampering")

    def detect_public_app_service_secret_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: _SecretManagementRuleEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            app_facts = azure_facts(app)
            ingress = app_service_ingress(app, context)
            if not ingress.is_public:
                continue

            paths = [
                path
                for path in app_facts.app_service_key_vault_secret_management_paths
                if _is_deterministic_management_path(
                    path,
                    app,
                    context,
                    management_effect,
                )
            ]
            if not paths:
                continue

            secret_addresses = _path_addresses(paths, "secret_address")
            vault_addresses = _path_addresses(paths, "key_vault_address")
            identity_addresses = _path_addresses(paths, "identity_address")
            grant_addresses = _grant_source_addresses(paths)
            role_definition_addresses = _role_definition_addresses(paths)
            operations = _management_operations(paths)
            parent_scope = any(
                scope_type in {"subscription", "resource_group", "vault"}
                for path in paths
                for scope_type in _string_values(path.get("scope_types"))
            )
            recovery_evidence = _recovery_evidence(paths, context) if management_effect == "disruption" else []
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=2 if management_effect == "disruption" else 1,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if parent_scope or len(secret_addresses) > 1 else 1,
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
                            *secret_addresses,
                            *grant_addresses,
                            *role_definition_addresses,
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=_rationale(
                        app,
                        operations,
                        len(secret_addresses),
                        management_effect,
                        parent_scope=parent_scope,
                        recovery_evidence=recovery_evidence,
                    ),
                    evidence=collect_evidence(
                        *ingress.evidence,
                        evidence_item("runtime_identity", _runtime_identity_evidence(paths)),
                        evidence_item("secret_management_paths", _management_path_evidence(paths)),
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
                        (
                            evidence_item("recovery_posture", recovery_evidence)
                            if management_effect == "disruption"
                            else None
                        ),
                        evidence_item(
                            "secret_management_path_uncertainties",
                            list(app_facts.app_service_key_vault_secret_management_path_uncertainties),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_management_path(
    path: AzureAppServiceKeyVaultSecretManagementPath,
    app: NormalizedResource,
    context: RuleEvaluationContext,
    management_effect: _SecretManagementRuleEffect,
) -> bool:
    operation = path.get("operation")
    definition = _SECRET_MANAGEMENT_DEFINITIONS.get(operation) if isinstance(operation, str) else None
    if (
        definition is None
        or definition != (path.get("operation_class"), path.get("management_effect"))
        or path.get("management_effect") != management_effect
        or path.get("workload_address") != app.address
        or path.get("workload_type") != app.resource_type
        or path.get("identity_kind") not in {"system_assigned", "user_assigned"}
        or path.get("credential_context") != "workload_runtime"
        or path.get("target_type") != "secret"
        or path.get("authorization_model_state") != "active"
        or path.get("authorization_state") != "granted"
        or path.get("evaluation_basis") != "modeled_key_vault_secret_authorization"
        or path.get("lifecycle_compatibility_state") != "compatible"
    ):
        return False

    expected_steps = _EXPECTED_STEPS.get(operation)
    raw_steps = path.get("step_operations")
    if expected_steps is None or not isinstance(raw_steps, list):
        return False
    if not all(isinstance(step, str) for step in raw_steps):
        return False
    actual_steps = tuple(cast(AzureKeyVaultSecretGrantOperation, step) for step in raw_steps)
    if actual_steps != expected_steps:
        return False

    if _runtime_identity(path, app, context) is None:
        return False

    secret_address = _known_string(path.get("secret_address"))
    secret = context.inventory.get_by_address(secret_address) if secret_address is not None else None
    vault_address = _known_string(path.get("key_vault_address"))
    vault = context.inventory.get_by_address(vault_address) if vault_address is not None else None
    if (
        secret is None
        or secret.resource_type != AzureResourceType.KEY_VAULT_SECRET
        or vault is None
        or vault.resource_type != AzureResourceType.KEY_VAULT
        or not _secret_identity_is_current(path, secret, vault)
        or not _vault_identity_is_current(path, vault)
    ):
        return False

    active_model = _active_authorization_model(vault)
    if active_model is None or path.get("authorization_model") != active_model:
        return False

    purge_protection = azure_facts(vault).purge_protection_enabled
    if path.get("purge_protection_enabled") is not purge_protection:
        return False
    if operation == "delete_plus_purge" and purge_protection is not False:
        return False

    return _authorization_is_current(path, secret, vault, context, expected_steps)


def _runtime_identity(
    path: AzureAppServiceKeyVaultSecretManagementPath,
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
    if not _same_identifier(azure_facts(identity).principal_id, principal_id):
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


def _secret_identity_is_current(
    path: AzureAppServiceKeyVaultSecretManagementPath,
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    facts = azure_facts(secret)
    secret_id = _known_string(facts.key_vault_secret_resource_id)
    secret_name = _known_string(facts.key_vault_secret_name)
    versionless_uri = _known_string(facts.key_vault_secret_versionless_uri)
    if secret_id is None or secret_name is None or versionless_uri is None:
        return False
    return (
        path.get("secret_address") == secret.address
        and path.get("secret_resource_type") == secret.resource_type
        and path.get("target_address") == secret.address
        and path.get("target_resource_id") == secret_id
        and path.get("secret_resource_id") == secret_id
        and path.get("secret_name") == secret_name
        and _same_optional_identifier(path.get("secret_uri"), facts.key_vault_secret_uri)
        and _same_identifier(path.get("secret_versionless_uri"), versionless_uri)
        and _same_optional_identifier(path.get("secret_version"), facts.key_vault_secret_version)
        and path.get("key_vault_address") == vault.address
    )


def _active_authorization_model(vault: NormalizedResource) -> str | None:
    rbac_enabled = azure_facts(vault).rbac_authorization_enabled
    if rbac_enabled is True:
        return "azure_rbac"
    if rbac_enabled is False:
        return "access_policy"
    return None


def _vault_identity_is_current(
    path: AzureAppServiceKeyVaultSecretManagementPath,
    vault: NormalizedResource,
) -> bool:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    path_vault_id = _known_string(path.get("key_vault_id"))
    return (
        vault_id is not None
        and path.get("key_vault_address") == vault.address
        and _same_identifier(path_vault_id, vault_id)
    )


def _authorization_is_current(
    path: AzureAppServiceKeyVaultSecretManagementPath,
    secret: NormalizedResource,
    vault: NormalizedResource,
    context: RuleEvaluationContext,
    expected_steps: tuple[AzureKeyVaultSecretGrantOperation, ...],
) -> bool:
    raw_grants = path.get("data_plane_grants")
    if (
        not isinstance(raw_grants, list)
        or not raw_grants
        or not all(isinstance(grant, Mapping) for grant in raw_grants)
    ):
        return False

    grants = [cast(AzureKeyVaultSecretAuthorizationGrant, grant) for grant in raw_grants]
    current_grants = azure_facts(secret).key_vault_secret_authorization_grants
    if not all(any(dict(current) == dict(grant) for current in current_grants) for grant in grants):
        return False

    source_addresses = sorted(
        {
            source
            for grant in grants
            for source in [_known_string(grant.get("grant_source_address"))]
            if source is not None
        }
    )
    if _string_values(path.get("grant_source_addresses")) != source_addresses:
        return False

    scope_types = {
        scope for grant in grants for scope in [_known_string(grant.get("grant_scope_type"))] if scope is not None
    }
    if set(_string_values(path.get("scope_types"))) != scope_types:
        return False

    expected_scope_ids = sorted(
        {scope_id for grant in grants if (scope_id := _grant_scope_arm_id(grant, secret, vault)) is not None}
    )
    if _string_values(path.get("scope_arm_ids")) != expected_scope_ids:
        return False

    expected_scopes = sorted(
        {scope for grant in grants for scope in [_known_string(grant.get("grant_scope"))] if scope is not None}
    )
    if _string_values(path.get("scopes")) != expected_scopes:
        return False

    required_operations = set(expected_steps)
    matched_operations: set[AzureKeyVaultSecretGrantOperation] = set()
    for grant in grants:
        if not _grant_is_current(grant, path, secret, vault, context):
            return False
        for operation in _string_values(grant.get("matched_operations")):
            if operation in _SUPPORTED_GRANT_OPERATIONS:
                matched_operations.add(cast(AzureKeyVaultSecretGrantOperation, operation))
    return required_operations <= matched_operations


def _grant_is_current(
    grant: AzureKeyVaultSecretAuthorizationGrant,
    path: AzureAppServiceKeyVaultSecretManagementPath,
    secret: NormalizedResource,
    vault: NormalizedResource,
    context: RuleEvaluationContext,
) -> bool:
    source_address = _known_string(grant.get("grant_source_address"))
    source = context.inventory.get_by_address(source_address) if source_address is not None else None
    secret_facts = azure_facts(secret)
    vault_facts = azure_facts(vault)
    active_model = _active_authorization_model(vault)
    principal_id = _known_string(path.get("principal_id"))
    if (
        source is None
        or source_address is None
        or grant.get("secret_address") != secret.address
        or grant.get("key_vault_address") != vault.address
        or not _same_optional_identifier(
            grant.get("key_vault_id"),
            vault_facts.key_vault_id,
        )
        or not _same_optional_identifier(
            grant.get("secret_uri"),
            secret_facts.key_vault_secret_uri,
        )
        or not _same_identifier(
            grant.get("secret_versionless_uri"),
            secret_facts.key_vault_secret_versionless_uri,
        )
        or not _same_optional_identifier(
            grant.get("secret_resource_id"),
            secret_facts.key_vault_secret_resource_id,
        )
        or not _same_optional_identifier(
            grant.get("secret_version"),
            secret_facts.key_vault_secret_version,
        )
        or grant.get("authorization_model") != active_model
        or grant.get("authorization_model_state") != "active"
        or grant.get("authorization_state") != "granted"
        or grant.get("principal_state") != "resolved"
        or grant.get("condition_state") != "not_configured"
        or grant.get("condition") is not None
        or not _same_identifier(grant.get("principal_id"), principal_id)
        or grant.get("grant_scope_type") not in _SUPPORTED_GRANT_SCOPES
    ):
        return False

    if grant.get("grant_kind") == "access_policy":
        return (
            source.resource_type in {AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY}
            and grant.get("authorization_model") == "access_policy"
            and grant.get("management_state") == "unambiguous"
            and grant.get("grant_scope_type") == "vault"
        )
    if grant.get("grant_kind") == "rbac":
        source_facts = azure_facts(source)
        return (
            source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
            and grant.get("authorization_model") == "azure_rbac"
            and grant.get("scope_resolution_state") == "resolved"
            and grant.get("condition_applicability_state") == "not_configured"
            and _same_identifier(
                grant.get("principal_id"),
                source_facts.principal_id,
            )
        )
    return False


def _grant_scope_arm_id(
    grant: AzureKeyVaultSecretAuthorizationGrant,
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    scope_type = grant.get("grant_scope_type")
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    secret_id = _known_string(azure_facts(secret).key_vault_secret_resource_id)
    if scope_type == "secret":
        return secret_id
    if scope_type == "vault":
        return vault_id
    if vault_id is None:
        return None
    parts = vault_id.strip().rstrip("/").split("/")
    if len(parts) < 5 or parts[1].casefold() != "subscriptions" or parts[3].casefold() != "resourcegroups":
        return None
    if scope_type == "subscription":
        return f"/subscriptions/{parts[2]}"
    if scope_type == "resource_group":
        return f"/subscriptions/{parts[2]}/resourceGroups/{parts[4]}"
    return None


def _management_operations(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
) -> list[AzureKeyVaultSecretManagementOperation]:
    return [operation for operation in _OPERATION_ORDER if any(path.get("operation") == operation for path in paths)]


def _path_addresses(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
    field: Literal["secret_address", "key_vault_address", "identity_address"],
) -> list[str]:
    return sorted({value for path in paths if (value := _known_string(path.get(field))) is not None})


def _grant_source_addresses(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
) -> list[str]:
    return sorted({source for path in paths for source in _string_values(path.get("grant_source_addresses"))})


def _role_definition_addresses(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
) -> list[str]:
    return sorted(
        {
            address
            for path in paths
            for grant in _mapping_values(path.get("data_plane_grants"))
            if (address := _known_string(grant.get("role_definition_address"))) is not None
        }
    )


def _recovery_evidence(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
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
        purge_protection = azure_facts(vault).purge_protection_enabled
        if path.get("purge_protection_enabled") is not purge_protection:
            continue
        if operation == "delete_plus_purge" and purge_protection is not False:
            continue
        values.append(
            "; ".join(
                (
                    f"secret_address={path.get('secret_address') or 'unknown'}",
                    f"operation={operation}",
                    f"purge_protection_enabled={purge_protection}",
                    (
                        "recovery_state=recoverable_soft_delete"
                        if operation == "delete"
                        else "recovery_state=permanent_delete_sequence"
                    ),
                )
            )
        )
    return sorted(set(values))


def _rationale(
    app: NormalizedResource,
    operations: Sequence[AzureKeyVaultSecretManagementOperation],
    secret_count: int,
    management_effect: _SecretManagementRuleEffect,
    *,
    parent_scope: bool,
    recovery_evidence: Sequence[str],
) -> str:
    operation_text = _operation_text(operations)
    if management_effect == "tampering":
        capability = (
            "could replace Key Vault secret values, creating secret-integrity and credential-tampering potential"
        )
        recovery = ""
    else:
        capability = "could delete Key Vault secrets, interrupting secret delivery and availability"
        recovery = (
            " Permanent deletion is represented only where delete-plus-purge authority is deterministic and purge "
            "protection is disabled."
            if any("recovery_state=permanent_delete_sequence" in value for value in recovery_evidence)
            else ""
        )
    if parent_scope:
        scope_text = (
            "At least one modeled grant is subscription-, resource-group-, or vault-scoped, so its potential "
            "blast radius is broader than an exact-secret grant; out-of-plan secrets are not modeled."
        )
    else:
        scope_text = "The modeled grants are limited to exact Key Vault vault or secret scope."
    return (
        f"{app.display_name} permits external ingress within the evidenced scope and its runtime managed identity has deterministic "
        f"Key Vault {operation_text} authority on {secret_count} exact modeled secret(s). A compromise of the "
        f"public workload {capability}. {scope_text}{recovery} This establishes modeled secret-management "
        "authority, not proof that secret payloads are public, that an operation will succeed outside the preserved "
        "Azure scope and authorization evidence, or that the workload can read plaintext."
    )


def _scope_breadth_evidence(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
) -> list[str]:
    grants_by_scope: dict[str, set[tuple[str, ...]]] = {scope_type: set() for scope_type in _SCOPE_ORDER}
    for path in paths:
        for grant in _mapping_values(path.get("data_plane_grants")):
            scope_type = _known_string(grant.get("grant_scope_type"))
            if scope_type not in grants_by_scope:
                continue
            grants_by_scope[scope_type].add(
                (
                    _known_string(grant.get("grant_source_address")) or "unknown",
                    _known_string(grant.get("grant_kind")) or "unknown",
                    _known_string(grant.get("grant_basis")) or "unknown",
                    _known_string(grant.get("grant_scope")) or "unknown",
                    _known_string(grant.get("role_definition_id"))
                    or _known_string(grant.get("role_definition_name"))
                    or "unknown",
                )
            )
    secret_targets = {address for path in paths if (address := _known_string(path.get("target_address"))) is not None}
    broadest_scope = next(
        (scope_type for scope_type in _SCOPE_ORDER if grants_by_scope[scope_type]),
        "unknown",
    )
    return [
        (
            f"subscription_grants={len(grants_by_scope['subscription'])}; "
            f"resource_group_grants={len(grants_by_scope['resource_group'])}; "
            f"vault_grants={len(grants_by_scope['vault'])}; "
            f"secret_grants={len(grants_by_scope['secret'])}; "
            f"target_paths={len(paths)}; "
            f"modeled_secrets={len(secret_targets)}; "
            f"broadest_scope={broadest_scope}; "
            f"out_of_plan_secrets_not_modeled={'true' if broadest_scope != 'secret' else 'false'}; "
            f"blast_radius_basis="
            f"{'parent_scope_grant' if broadest_scope != 'secret' and broadest_scope != 'unknown' else 'exact_secret_grant'}"
        )
    ]


def _authorization_scope(
    operations: Sequence[AzureKeyVaultSecretManagementOperation],
    management_effect: _SecretManagementRuleEffect,
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
    *,
    parent_scope: bool,
) -> list[str]:
    effect_text = "secret tampering" if management_effect == "tampering" else "secret disruption"
    scope_types = sorted({scope_type for path in paths for scope_type in _string_values(path.get("scope_types"))})
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority with {effect_text} effect for the "
            "App Service runtime identity"
        ),
        f"target_granularity=secret; target_count={len({path.get('target_address') for path in paths})}",
        f"native_scopes={','.join(scope_types) or 'unknown'}",
        (
            "does_not_establish=secret payload possession, secret publicity, operation success outside modeled "
            "Azure evidence, or runtime recovery authority"
        ),
    ] + (
        ["blast_radius=parent-scope grant is broader than exact-secret scope; out_of_plan_secrets_not_modeled=true"]
        if parent_scope
        else ["blast_radius=grants are limited to modeled Key Vault secret scope"]
    )


def _runtime_identity_evidence(
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
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
    paths: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
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
                    f"secret_uri={path.get('secret_uri') or 'none'}",
                    f"secret_versionless_uri={path.get('secret_versionless_uri') or 'none'}",
                    f"secret_version={path.get('secret_version') or 'none'}",
                    f"authorization_model={path.get('authorization_model')}",
                    f"authorization_state={path.get('authorization_state')}",
                    f"grant_sources={','.join(_string_values(path.get('grant_source_addresses')) or ['none'])}",
                    f"scope_types={','.join(_string_values(path.get('scope_types')) or ['none'])}",
                    f"scope_arm_ids={','.join(_string_values(path.get('scope_arm_ids')) or ['none'])}",
                    f"step_operations={','.join(_ordered_string_values(path.get('step_operations')) or ['none'])}",
                    f"purge_protection_enabled={path.get('purge_protection_enabled')}",
                    f"lifecycle_compatibility={path.get('lifecycle_compatibility_state')}",
                    f"data_plane_grants={','.join(_grant_evidence(path) or ['none'])}",
                )
            )
            for path in paths
        }
    )


def _ordered_string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _grant_evidence(
    path: AzureAppServiceKeyVaultSecretManagementPath,
) -> list[str]:
    return [
        ";".join(
            (
                f"source={grant.get('grant_source_address') or 'unknown'}",
                f"kind={grant.get('grant_kind') or 'unknown'}",
                f"scope={grant.get('grant_scope_type') or 'unknown'}",
                f"operations={','.join(_string_values(grant.get('matched_operations')) or ['unknown'])}",
                f"condition_state={grant.get('condition_state') or 'unknown'}",
            )
        )
        for grant in _mapping_values(path.get("data_plane_grants"))
    ]


def _operation_text(
    operations: Sequence[AzureKeyVaultSecretManagementOperation],
) -> str:
    labels = {
        "set": "secret value mutation",
        "delete": "recoverable secret deletion",
        "delete_plus_purge": "secret deletion and purge",
    }
    values = [labels[operation] for operation in operations]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _user_identity_is_attached(facts: object, address: str) -> bool:
    resolved = getattr(facts, "resolved_attached_identity_addresses", [])
    references = getattr(facts, "attached_identity_references", [])
    if isinstance(resolved, list) and address in resolved:
        return True
    return isinstance(references, list) and any(
        isinstance(reference, str) and (reference == address or reference.startswith(f"{address}."))
        for reference in references
    )


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return bool(left_value and right_value and left_value.casefold().rstrip("/") == right_value.casefold().rstrip("/"))


def _same_optional_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    if left_value is None or right_value is None:
        return left_value is right_value
    return left_value.casefold().rstrip("/") == right_value.casefold().rstrip("/")


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def _mapping_values(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping)]
