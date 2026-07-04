from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
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

    def detect_secret_certificate_lifecycle_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for item in context.inventory.by_type(*_KEY_VAULT_LIFECYCLE_RESOURCE_TYPES):
            facts = azure_facts(item)
            lifecycle_issues = _key_vault_lifecycle_issues(item.resource_type, facts)
            if not lifecycle_issues:
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
                    affected_resources=dedupe_addresses([item.address, facts.resolved_key_vault_address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{item.display_name} does not show deterministic Key Vault secret or certificate "
                        "lifecycle posture. Explicit expiry and bounded validity reduce stale secret and "
                        "certificate material, but do not replace identity review or rotation automation."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _key_vault_lifecycle_target_evidence(item, facts)),
                        evidence_item("lifecycle_issues", lifecycle_issues),
                        evidence_item("lifecycle_posture", _key_vault_lifecycle_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_key_strength_weak(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(AzureResourceType.KEY_VAULT_KEY):
            facts = azure_facts(key)
            strength_issues = _key_vault_key_strength_issues(facts)
            if not strength_issues:
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
                    affected_resources=dedupe_addresses([key.address, facts.resolved_key_vault_address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} has deterministic Key Vault key shape evidence below the "
                        f"{_KEY_VAULT_MIN_RSA_KEY_SIZE_BITS}-bit RSA baseline used by tfSTRIDE. This finding "
                        "concerns cryptographic key strength posture; it does not evaluate key operations, "
                        "identity access, or data-plane exposure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _key_vault_lifecycle_target_evidence(key, facts)),
                        evidence_item("key_strength_issues", strength_issues),
                        evidence_item("key_posture", _key_vault_key_posture_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_key_rotation_policy_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(AzureResourceType.KEY_VAULT_KEY):
            facts = azure_facts(key)
            rotation_issues = _key_vault_key_rotation_issues(facts)
            if not rotation_issues:
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
                    affected_resources=dedupe_addresses([key.address, facts.resolved_key_vault_address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} does not show bounded Key Vault key rotation and expiry "
                        "governance. This finding concerns cryptographic key lifecycle posture for dependent "
                        "data; it does not assert access to secrets or data-plane compromise."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _key_vault_lifecycle_target_evidence(key, facts)),
                        evidence_item("rotation_issues", rotation_issues),
                        evidence_item("key_posture", _key_vault_key_posture_evidence(facts)),
                        evidence_item("rotation_policy", _key_vault_key_rotation_policy_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


_KEY_VAULT_LIFECYCLE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.KEY_VAULT_SECRET,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
    }
)
_KEY_VAULT_MAX_LIFETIME_DAYS = 730
_KEY_VAULT_MAX_CERTIFICATE_VALIDITY_MONTHS = 24
_KEY_VAULT_MAX_KEY_ROTATION_INTERVAL_DAYS = 365
_KEY_VAULT_MAX_KEY_EXPIRY_DAYS = 730
_KEY_VAULT_MIN_RSA_KEY_SIZE_BITS = 2048
_ISO_PERIOD_RE = re.compile(r"^P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?$")


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


def _key_vault_key_strength_issues(facts: AzureResourceFacts) -> list[str]:
    if facts.key_vault_key_posture_uncertainties:
        return []

    key_type = str(facts.key_vault_key_type or "").strip().upper()
    key_size = facts.key_vault_key_size
    if key_type in {"RSA", "RSA-HSM"} and key_size is not None and key_size < _KEY_VAULT_MIN_RSA_KEY_SIZE_BITS:
        return [
            f"key_type={facts.key_vault_key_type} uses key_size={key_size}; "
            f"minimum_rsa_key_size_bits={_KEY_VAULT_MIN_RSA_KEY_SIZE_BITS}"
        ]
    return []


def _key_vault_key_rotation_issues(facts: AzureResourceFacts) -> list[str]:
    if facts.key_vault_key_posture_uncertainties:
        return []

    issues: list[str] = []
    if not facts.key_vault_rotation_policy:
        issues.append("key has no rotation_policy")
    else:
        if not facts.key_vault_rotation_policy_expire_after:
            issues.append("rotation_policy.expire_after is not configured")
        if not (
            facts.key_vault_rotation_policy_automatic_time_after_creation
            or facts.key_vault_rotation_policy_automatic_time_before_expiry
        ):
            issues.append("rotation_policy.automatic is not configured")

    expire_after_days = _parse_iso_period_days(facts.key_vault_rotation_policy_expire_after)
    if expire_after_days is not None and expire_after_days > _KEY_VAULT_MAX_KEY_EXPIRY_DAYS:
        issues.append(
            f"rotation_policy.expire_after is {facts.key_vault_rotation_policy_expire_after} "
            f"({expire_after_days} days); maximum is {_KEY_VAULT_MAX_KEY_EXPIRY_DAYS} days"
        )

    rotate_after_days = _parse_iso_period_days(facts.key_vault_rotation_policy_automatic_time_after_creation)
    if rotate_after_days is not None and rotate_after_days > _KEY_VAULT_MAX_KEY_ROTATION_INTERVAL_DAYS:
        issues.append(
            "rotation_policy.automatic.time_after_creation is "
            f"{facts.key_vault_rotation_policy_automatic_time_after_creation} ({rotate_after_days} days); "
            f"maximum is {_KEY_VAULT_MAX_KEY_ROTATION_INTERVAL_DAYS} days"
        )

    lifetime_days = _key_vault_lifetime_days(facts.key_vault_not_before_date, facts.key_vault_expiration_date)
    if lifetime_days is not None and lifetime_days > _KEY_VAULT_MAX_KEY_EXPIRY_DAYS:
        issues.append(
            f"configured key lifetime is {lifetime_days} days; maximum is {_KEY_VAULT_MAX_KEY_EXPIRY_DAYS} days"
        )
    return issues


def _key_vault_lifecycle_issues(resource_type: str, facts: AzureResourceFacts) -> list[str]:
    if facts.key_vault_lifecycle_uncertainties:
        return []

    issues: list[str] = []
    expiration_date = facts.key_vault_expiration_date
    validity_months = facts.key_vault_certificate_validity_months
    if not expiration_date and not (
        resource_type == AzureResourceType.KEY_VAULT_CERTIFICATE and validity_months is not None
    ):
        issues.append(f"{_key_vault_lifecycle_label(resource_type)} has no expiration_date")

    lifetime_days = _key_vault_lifetime_days(facts.key_vault_not_before_date, expiration_date)
    if lifetime_days is not None and lifetime_days > _KEY_VAULT_MAX_LIFETIME_DAYS:
        issues.append(f"configured lifetime is {lifetime_days} days; maximum is {_KEY_VAULT_MAX_LIFETIME_DAYS} days")
    if (
        resource_type == AzureResourceType.KEY_VAULT_CERTIFICATE
        and validity_months is not None
        and validity_months > _KEY_VAULT_MAX_CERTIFICATE_VALIDITY_MONTHS
    ):
        issues.append(
            "certificate_policy.validity_in_months is "
            f"{validity_months}; maximum is {_KEY_VAULT_MAX_CERTIFICATE_VALIDITY_MONTHS}"
        )
    return issues


def _key_vault_lifecycle_target_evidence(resource: NormalizedResource, facts: AzureResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    if facts.key_vault_reference:
        values.append(f"key_vault_reference={facts.key_vault_reference}")
    if facts.resolved_key_vault_address:
        values.append(f"resolved_key_vault_address={facts.resolved_key_vault_address}")
    return values


def _key_vault_key_posture_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [
        f"key_type={facts.key_vault_key_type or 'unset'}",
        f"key_size={facts.key_vault_key_size if facts.key_vault_key_size is not None else 'unset'}",
        f"curve={facts.key_vault_key_curve or 'unset'}",
        f"key_ops={', '.join(facts.key_vault_key_ops) if facts.key_vault_key_ops else 'unset'}",
        f"minimum_rsa_key_size_bits={_KEY_VAULT_MIN_RSA_KEY_SIZE_BITS}",
        f"expiration_date={facts.key_vault_expiration_date or 'unset'}",
        f"not_before_date={facts.key_vault_not_before_date or 'unset'}",
        f"maximum_key_expiry_days={_KEY_VAULT_MAX_KEY_EXPIRY_DAYS}",
        f"maximum_rotation_interval_days={_KEY_VAULT_MAX_KEY_ROTATION_INTERVAL_DAYS}",
    ]
    lifetime_days = _key_vault_lifetime_days(facts.key_vault_not_before_date, facts.key_vault_expiration_date)
    if lifetime_days is not None:
        values.append(f"configured_key_lifetime_days={lifetime_days}")
    return values


def _key_vault_key_rotation_policy_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [
        f"rotation_policy_present={str(bool(facts.key_vault_rotation_policy)).lower()}",
        f"expire_after={facts.key_vault_rotation_policy_expire_after or 'unset'}",
        f"notify_before_expiry={facts.key_vault_rotation_policy_notify_before_expiry or 'unset'}",
        f"automatic.time_after_creation={facts.key_vault_rotation_policy_automatic_time_after_creation or 'unset'}",
        f"automatic.time_before_expiry={facts.key_vault_rotation_policy_automatic_time_before_expiry or 'unset'}",
    ]
    for label, value in (
        ("expire_after_days", facts.key_vault_rotation_policy_expire_after),
        ("automatic_time_after_creation_days", facts.key_vault_rotation_policy_automatic_time_after_creation),
        ("automatic_time_before_expiry_days", facts.key_vault_rotation_policy_automatic_time_before_expiry),
    ):
        parsed_days = _parse_iso_period_days(value)
        if parsed_days is not None:
            values.append(f"{label}={parsed_days}")
    return values


def _key_vault_lifecycle_evidence(facts: AzureResourceFacts) -> list[str]:
    validity_months = facts.key_vault_certificate_validity_months
    values = [
        f"expiration_date={facts.key_vault_expiration_date or 'unset'}",
        f"not_before_date={facts.key_vault_not_before_date or 'unset'}",
        f"certificate_policy.validity_in_months={validity_months if validity_months is not None else 'unset'}",
        f"maximum_lifetime_days={_KEY_VAULT_MAX_LIFETIME_DAYS}",
        f"maximum_certificate_validity_months={_KEY_VAULT_MAX_CERTIFICATE_VALIDITY_MONTHS}",
    ]
    lifetime_days = _key_vault_lifetime_days(facts.key_vault_not_before_date, facts.key_vault_expiration_date)
    if lifetime_days is not None:
        values.append(f"configured_lifetime_days={lifetime_days}")
    return values


def _key_vault_lifetime_days(not_before_date: str | None, expiration_date: str | None) -> int | None:
    start = _parse_iso_datetime(not_before_date)
    end = _parse_iso_datetime(expiration_date)
    if start is None or end is None or end <= start:
        return None
    return (end - start).days


def _parse_iso_period_days(value: str | None) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    match = _ISO_PERIOD_RE.fullmatch(value.strip().upper())
    if match is None or not any(match.groupdict().values()):
        return None
    years = int(match.group("years") or 0)
    months = int(match.group("months") or 0)
    weeks = int(match.group("weeks") or 0)
    days = int(match.group("days") or 0)
    return years * 365 + months * 30 + weeks * 7 + days


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


def _key_vault_lifecycle_label(resource_type: str) -> str:
    if resource_type == AzureResourceType.KEY_VAULT_CERTIFICATE:
        return "certificate"
    return "secret"


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
