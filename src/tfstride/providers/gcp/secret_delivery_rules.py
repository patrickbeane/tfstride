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
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES
from tfstride.providers.secret_settings import (
    SensitiveSettingCategory,
    SensitiveSettingClassification,
    redacted_sensitive_setting_evidence,
)

_MAX_NARROW_SECRET_SET_SIZE = 5
_BROAD_SECRET_ACCESS_SCOPE_TYPES = frozenset({"project", "folder", "organization"})


class GcpCloudRunSecretDeliveryRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_inline_sensitive_environment_value(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            for record in gcp_facts(service).cloud_run_secret_references:
                classification = _literal_sensitive_setting(record)
                if classification is None:
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
                        affected_resources=[service.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{service.display_name} materializes the sensitive-classified setting "
                            f"{classification.normalized_name} as a literal Cloud Run environment value. Literal "
                            "configuration can place credential material in Terraform plan/state and Cloud Run "
                            "revision configuration; use Cloud Run Secret Manager integration instead. The literal "
                            "value is intentionally excluded from this finding."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(service)),
                            evidence_item(
                                "sensitive_setting",
                                [
                                    redacted_sensitive_setting_evidence(
                                        classification,
                                        path=_setting_path(record),
                                    )
                                ],
                            ),
                            evidence_item("delivery_posture", _delivery_posture_evidence(record)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_secret_access_blast_radius(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
            facts = gcp_facts(service)
            consumed_secrets = _exact_consumed_secret_names(facts)
            if consumed_secrets is None or not 1 <= len(consumed_secrets) <= _MAX_NARROW_SECRET_SET_SIZE:
                continue

            for access_paths in _broad_grant_groups(facts.cloud_run_secret_access_paths):
                representative = access_paths[0]
                iam_resource_address = _known_string(representative.get("iam_resource_address"))
                if iam_resource_address is None:
                    continue
                role = _known_string(representative.get("role")) or "unknown role"
                scope_type = _known_string(representative.get("grant_scope_type")) or "unknown"
                scope = _known_string(representative.get("grant_scope")) or "unknown"
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2,
                    data_sensitivity=2,
                    lateral_movement=0,
                    blast_radius=2,
                )
                affected_resources = dedupe_addresses(
                    [
                        service.address,
                        iam_resource_address,
                        *[
                            secret_address
                            for path in access_paths
                            if (secret_address := _known_string(path.get("secret_resource_address")))
                        ],
                    ]
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{service.display_name} consumes {len(consumed_secrets)} exact Secret Manager "
                            f"secret(s), but its Cloud Run service account receives {role} at {scope_type} "
                            f"scope {scope}. That modeled grant can reach Secret Manager resources beyond the "
                            "specific secrets configured on this workload. Grant secret access on only the exact "
                            "secret resources consumed by the service."
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _target_resource_evidence(service)),
                            evidence_item(
                                "runtime_identity",
                                _runtime_identity_evidence(representative),
                            ),
                            evidence_item(
                                "consumed_secrets",
                                _consumed_secret_evidence(consumed_secrets),
                            ),
                            evidence_item(
                                "broad_secret_access_grant",
                                _broad_grant_evidence(representative),
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _literal_sensitive_setting(record: Mapping[str, Any]) -> SensitiveSettingClassification | None:
    if record.get("state") != "literal":
        return None
    normalized_name = record.get("normalized_setting_name")
    category = record.get("sensitive_category")
    if not isinstance(normalized_name, str) or not normalized_name or not isinstance(category, str):
        return None
    try:
        sensitive_category = SensitiveSettingCategory(category)
    except ValueError:
        return None
    return SensitiveSettingClassification(
        normalized_name=normalized_name,
        category=sensitive_category,
    )


def _setting_path(record: Mapping[str, Any]) -> str | None:
    value_path = record.get("value_path")
    if isinstance(value_path, str) and value_path:
        return value_path
    path = record.get("path")
    return path if isinstance(path, str) and path else None


def _target_resource_evidence(resource: NormalizedResource) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    if resource.identifier:
        values.append(f"identifier={resource.identifier}")
    return values


def _delivery_posture_evidence(record: Mapping[str, Any]) -> list[str]:
    return [
        f"source={record.get('source') or 'unknown'}",
        f"container_name={record.get('container_name') or 'unknown'}",
        f"state={record.get('state') or 'unknown'}",
    ]


def _exact_consumed_secret_names(facts: GcpResourceFacts) -> tuple[str, ...] | None:
    if facts.cloud_run_secret_posture_uncertainties or facts.cloud_run_secret_access_path_uncertainties:
        return None

    resolved_by_reference = {
        reference: secret_name
        for path in facts.cloud_run_secret_access_paths
        if (reference := _known_string(path.get("secret_reference")))
        and (secret_name := _known_string(path.get("secret_resource_name")))
    }
    consumed: set[str] = set()
    for reference in facts.cloud_run_secret_references:
        if reference.get("state") != "reference":
            continue
        raw_reference = _known_string(reference.get("secret_reference"))
        if raw_reference is None:
            return None
        secret_name = resolved_by_reference.get(raw_reference) or _canonical_secret_name(raw_reference, facts.project)
        if secret_name is None:
            return None
        consumed.add(secret_name)
    return tuple(sorted(consumed))


def _broad_grant_groups(
    access_paths: list[dict[str, Any]],
) -> list[list[Mapping[str, Any]]]:
    groups: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for path in access_paths:
        if path.get("access_state") != "granted":
            continue
        if path.get("condition_state") != "not_configured" or path.get("condition"):
            continue
        scope_type = _known_string(path.get("grant_scope_type"))
        if scope_type not in _BROAD_SECRET_ACCESS_SCOPE_TYPES:
            continue
        iam_resource_address = _known_string(path.get("iam_resource_address"))
        role = _known_string(path.get("role"))
        scope = _known_string(path.get("grant_scope"))
        if iam_resource_address is None or role is None or scope is None:
            continue
        key = (iam_resource_address, role, scope_type, scope)
        groups.setdefault(key, []).append(path)
    return list(groups.values())


def _canonical_secret_name(value: str, project: str | None) -> str | None:
    text = value.strip()
    if text.startswith("//secretmanager.googleapis.com/"):
        text = text.removeprefix("//secretmanager.googleapis.com/")
    parts = [part for part in text.split("/") if part]
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "secrets":
        if _exact_segment(parts[1]) and _exact_segment(parts[3]):
            return f"projects/{parts[1]}/secrets/{parts[3]}"
        return None
    normalized_project = _normalized_project(project)
    if len(parts) == 1 and normalized_project and _exact_segment(parts[0]):
        return f"projects/{normalized_project}/secrets/{parts[0]}"
    return None


def _normalized_project(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if text.startswith("projects/"):
        text = text.removeprefix("projects/")
    return text if _exact_segment(text) else None


def _exact_segment(value: str) -> bool:
    return bool(value) and ("$" + "{") not in value and not any(character in value for character in "/*?")


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _runtime_identity_evidence(path: Mapping[str, Any]) -> list[str]:
    return [
        f"service_account_email={path.get('service_account_email') or 'unknown'}",
        f"service_account_member={path.get('service_account_member') or 'unknown'}",
        f"identity_kind={path.get('identity_kind') or 'unknown'}",
        f"credential_context={path.get('credential_context') or 'unknown'}",
    ]


def _consumed_secret_evidence(consumed_secrets: tuple[str, ...]) -> list[str]:
    return [
        f"exact_secret_count={len(consumed_secrets)}",
        f"small_secret_set_threshold={_MAX_NARROW_SECRET_SET_SIZE}",
        *(f"secret_resource_name={secret_name}" for secret_name in consumed_secrets),
    ]


def _broad_grant_evidence(path: Mapping[str, Any]) -> list[str]:
    values = [
        f"iam_resource_address={path.get('iam_resource_address') or 'unknown'}",
        f"iam_resource_type={path.get('iam_resource_type') or 'unknown'}",
        f"role={path.get('role') or 'unknown'}",
        f"role_kind={path.get('role_kind') or 'unknown'}",
        f"grant_scope_type={path.get('grant_scope_type') or 'unknown'}",
        f"grant_scope={path.get('grant_scope') or 'unknown'}",
        f"grant_basis={path.get('grant_basis') or 'unknown'}",
        f"access_state={path.get('access_state') or 'unknown'}",
        f"condition_state={path.get('condition_state') or 'unknown'}",
    ]
    permissions = path.get("custom_role_permissions")
    if isinstance(permissions, list):
        values.extend(
            f"custom_role_permission={permission}"
            for permission in permissions
            if isinstance(permission, str) and permission
        )
    return values
