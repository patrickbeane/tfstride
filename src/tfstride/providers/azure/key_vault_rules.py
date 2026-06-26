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
from tfstride.providers.azure.resource_types import AzureResourceType


class AzureKeyVaultRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_network_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for vault in context.inventory.by_type(AzureResourceType.KEY_VAULT):
            facts = azure_facts(vault)
            default_action = facts.network_default_action
            if (
                facts.public_network_access_enabled is not True
                or default_action is None
                or default_action.strip().lower() != "allow"
            ):
                continue
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", vault.address))
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[vault.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{vault.display_name} enables its public endpoint with an effective "
                        f"`{default_action}` network ACL default action. Network reachability does not itself "
                        "grant data access, but it exposes the sensitive service endpoint to internet clients."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_exposure",
                            [
                                "public_network_access_enabled is true",
                                f"effective network_acls.default_action is {default_action}",
                                "network exposure is evaluated separately from identity authorization",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_privileged_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for vault in context.inventory.by_type(AzureResourceType.KEY_VAULT):
            facts = azure_facts(vault)
            privileged_policies = [
                policy for policy in facts.key_vault_access_policies if _access_policy_is_privileged(policy)
            ]
            privileged_assignments = [
                assignment
                for assignment in facts.key_vault_role_assignments
                if _role_assignment_is_privileged(assignment)
            ]
            if not privileged_policies and not privileged_assignments:
                continue
            source_addresses = [
                str(record.get("source"))
                for record in (*privileged_policies, *privileged_assignments)
                if record.get("source")
            ]
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=3,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=dedupe_addresses([vault.address, *source_addresses]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{vault.display_name} grants broad data-plane or authorization-management authority "
                        "through a Key Vault access policy or vault-scoped Azure role assignment. This "
                        "identity risk is present independently of whether the vault public endpoint is reachable."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "privileged_access_policies",
                            [_describe_access_policy(policy) for policy in privileged_policies],
                        ),
                        evidence_item(
                            "privileged_role_assignments",
                            [_describe_role_assignment(assignment) for assignment in privileged_assignments],
                        ),
                        evidence_item(
                            "authorization_scope",
                            ["identity authorization is evaluated separately from network exposure"],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_purge_protection_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for vault in context.inventory.by_type(AzureResourceType.KEY_VAULT):
            facts = azure_facts(vault)
            if facts.purge_protection_enabled is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[vault.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{vault.display_name} does not enable purge protection. A principal with sufficient "
                        "deletion authority could permanently remove vault contents during the retention window."
                    ),
                    evidence=collect_evidence(
                        evidence_item("recovery_posture", ["purge_protection_enabled is false"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


_PRIVILEGED_KEY_VAULT_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault administrator",
        "key vault certificates officer",
        "key vault crypto officer",
        "key vault data access administrator",
        "key vault secrets officer",
        "owner",
        "user access administrator",
    }
)
_PRIVILEGED_KEY_VAULT_PERMISSIONS = frozenset(
    {
        "all",
        "*",
        "backup",
        "delete",
        "import",
        "managecontacts",
        "manageissuers",
        "purge",
        "recover",
        "regeneratekey",
        "release",
        "restore",
        "rotate",
        "set",
        "setissuers",
        "setrotationpolicy",
        "setsas",
    }
)


def _access_policy_is_privileged(policy: Mapping[str, Any]) -> bool:
    for field in (
        "key_permissions",
        "secret_permissions",
        "certificate_permissions",
        "storage_permissions",
    ):
        permissions = {str(permission).strip().lower() for permission in policy.get(field, [])}
        if permissions & _PRIVILEGED_KEY_VAULT_PERMISSIONS:
            return True
    return False


def _role_assignment_is_privileged(assignment: Mapping[str, Any]) -> bool:
    role_name = str(assignment.get("role_definition_name") or "").strip().lower()
    return role_name in _PRIVILEGED_KEY_VAULT_ROLE_NAMES


def _describe_access_policy(policy: Mapping[str, Any]) -> str:
    permission_parts = []
    for field in (
        "key_permissions",
        "secret_permissions",
        "certificate_permissions",
        "storage_permissions",
    ):
        permissions = [str(permission) for permission in policy.get(field, [])]
        if permissions:
            permission_parts.append(f"{field}=[{', '.join(permissions)}]")
    return "; ".join(
        part
        for part in (
            f"source={policy.get('source')}",
            f"object_id={policy.get('object_id')}",
            *permission_parts,
        )
        if part and not part.endswith("=None")
    )


def _describe_role_assignment(assignment: Mapping[str, Any]) -> str:
    return "; ".join(
        part
        for part in (
            f"source={assignment.get('source')}",
            f"role={assignment.get('role_definition_name') or assignment.get('role_definition_id')}",
            f"principal_id={assignment.get('principal_id')}",
            f"principal_type={assignment.get('principal_type')}",
        )
        if not part.endswith("=None")
    )
