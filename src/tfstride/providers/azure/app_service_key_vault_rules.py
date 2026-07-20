from __future__ import annotations

import json
from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, ResourceInventory
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES
from tfstride.providers.coercion import dedupe_strings

_BROAD_SCOPE_TYPES = frozenset({"subscription", "resource_group"})
_KEY_VAULT_WRITE_ROLE_NAMES = frozenset({"key vault administrator", "key vault secrets officer"})
_KEY_VAULT_SECRET_WRITE_ACTIONS = (
    "microsoft.keyvault/vaults/secrets/backup/action",
    "microsoft.keyvault/vaults/secrets/delete",
    "microsoft.keyvault/vaults/secrets/purge/action",
    "microsoft.keyvault/vaults/secrets/recover/action",
    "microsoft.keyvault/vaults/secrets/restore/action",
    "microsoft.keyvault/vaults/secrets/setsecret/action",
)
_ACCESS_POLICY_WRITE_PERMISSIONS = frozenset({"all", "*", "backup", "delete", "purge", "recover", "restore", "set"})


class AzureAppServiceKeyVaultRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_reference_identity_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            facts = azure_facts(app)
            references = _exact_key_vault_references(facts.app_service_secret_references)
            if not references:
                continue
            if facts.has_system_assigned_identity or facts.app_service_key_vault_reference_identity_id:
                continue
            if not facts.has_user_assigned_identity or _reference_identity_is_unknown(facts):
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=2,
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
                        f"{app.display_name} uses exact Key Vault secret references and has a user-assigned "
                        "identity, but does not configure `key_vault_reference_identity_id`. App Service uses "
                        "the system-assigned identity for Key Vault references by default, so the attached "
                        "user-assigned identity is not a deterministic reference identity for this plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("key_vault_references", _key_vault_reference_evidence(references)),
                        evidence_item("identity_posture", _reference_identity_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_secret_access_overprivileged(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for app in context.inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES):
            paths = [
                path
                for path in azure_facts(app).app_service_key_vault_access_paths
                if _path_grants_excess_secret_privilege(path) and path.get("grant_scope_type") not in _BROAD_SCOPE_TYPES
            ]
            if not paths:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses(
                        [
                            app.address,
                            *_path_values(paths, "identity_address"),
                            *_path_values(paths, "grant_source_address"),
                            *_path_values(paths, "key_vault_address"),
                            *_path_values(paths, "secret_resource_address"),
                        ]
                    ),
                    trust_boundary_id=None,
                    rationale=(
                        f"{app.display_name} uses a managed identity to read exact Key Vault secret references, "
                        "but the modeled vault authorization path also grants secret write, deletion, recovery, "
                        "or administration capability. A read-only secret role or access policy is sufficient "
                        "for App Service Key Vault reference resolution."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(app)),
                        evidence_item("key_vault_access_paths", key_vault_access_path_evidence(paths)),
                        evidence_item("excess_privilege", _excess_privilege_evidence(paths)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def app_service_key_vault_paths_for_assignments(
    inventory: ResourceInventory,
    identity_address: str,
    assignments: list[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    assignment_sources = {
        str(assignment["source"])
        for assignment in assignments
        if isinstance(assignment.get("source"), str) and assignment.get("source")
    }
    if not assignment_sources:
        return []
    return [
        path
        for app in inventory.by_type(*AZURE_APP_SERVICE_RESOURCE_TYPES)
        for path in azure_facts(app).app_service_key_vault_access_paths
        if path.get("identity_address") == identity_address and path.get("grant_source_address") in assignment_sources
    ]


def key_vault_access_path_evidence(paths: list[Mapping[str, Any]]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"workload={path.get('workload_address')}",
                f"identity={path.get('identity_address')}",
                f"identity_kind={path.get('identity_kind')}",
                f"principal_id={path.get('principal_id')}",
                f"vault={path.get('key_vault_address')}",
                f"secret={path.get('secret_resource_address') or path.get('secret_versionless_uri')}",
                f"grant={path.get('grant_source_address')}",
                f"grant_kind={path.get('grant_kind')}",
                f"role={path.get('role_definition_name') or path.get('role_definition_id')}",
                f"secret_permissions={','.join(sorted(_normalized_strings(path.get('secret_permissions'))))}",
                f"scope_type={path.get('grant_scope_type')}",
                f"scope={path.get('grant_scope')}",
                f"access_state={path.get('access_state')}",
                f"condition_state={path.get('condition_state')}",
                _condition_evidence(path.get("condition")),
            )
            if part and not part.endswith("=None") and not part.endswith("=")
        )
        for path in paths
    ]


def _condition_evidence(value: object) -> str | None:
    if value in (None, "", {}, []):
        return None
    return f"condition={json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)}"


def _exact_key_vault_references(records: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        record
        for record in records
        if record.get("state") == "reference"
        and record.get("reference_kind") == "key_vault_secret_uri"
        and record.get("target_resolution") == "resolved"
        and record.get("key_vault_uri")
    ]


def _reference_identity_is_unknown(facts: Any) -> bool:
    return any(
        "key_vault_reference_identity_id" in uncertainty
        for uncertainty in facts.app_service_secret_posture_uncertainties
    )


def _path_grants_excess_secret_privilege(path: Mapping[str, Any]) -> bool:
    if path.get("access_state") != "granted":
        return False
    if path.get("grant_kind") == "access_policy":
        permissions = _normalized_strings(path.get("secret_permissions"))
        return bool(permissions & _ACCESS_POLICY_WRITE_PERMISSIONS)
    if path.get("grant_kind") != "rbac":
        return False
    role_name = str(path.get("role_definition_name") or "").strip().lower()
    if role_name in _KEY_VAULT_WRITE_ROLE_NAMES:
        return True
    actions = _normalized_strings(path.get("custom_role_data_actions"))
    return any(fnmatchcase(action, pattern) for action in _KEY_VAULT_SECRET_WRITE_ACTIONS for pattern in actions)


def _excess_privilege_evidence(paths: list[Mapping[str, Any]]) -> list[str]:
    values: list[str] = []
    for path in paths:
        source = path.get("grant_source_address") or "unknown"
        if path.get("grant_kind") == "access_policy":
            permissions = sorted(_normalized_strings(path.get("secret_permissions")))
            values.append(f"grant={source}; secret_permissions={','.join(permissions)}")
            continue
        role = path.get("role_definition_name") or path.get("role_definition_id") or "unknown"
        actions = sorted(_normalized_strings(path.get("custom_role_data_actions")))
        suffix = f"; data_actions={','.join(actions)}" if actions else ""
        values.append(f"grant={source}; role={role}{suffix}")
    return dedupe_strings(values)


def _key_vault_reference_evidence(references: list[Mapping[str, Any]]) -> list[str]:
    return [
        "; ".join(
            part
            for part in (
                f"setting_key={reference.get('setting_name')}",
                f"path={reference.get('path')}",
                f"vault_uri={reference.get('key_vault_uri')}",
                f"secret_uri={reference.get('key_vault_secret_versionless_uri')}",
            )
            if part and not part.endswith("=None") and not part.endswith("=")
        )
        for reference in references
    ]


def _reference_identity_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        f"identity_type={facts.identity_type or 'unknown'}",
        "system_assigned_identity=false",
        "user_assigned_identity=true",
        "key_vault_reference_identity_id=not_configured",
    ]


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    return [f"address={resource.address}", f"type={resource.resource_type}"]


def _path_values(paths: list[Mapping[str, Any]], key: str) -> list[str]:
    return dedupe_strings(str(path[key]) for path in paths if path.get(key))


def _normalized_strings(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    return {str(item).strip().lower() for item in value if str(item).strip()}
