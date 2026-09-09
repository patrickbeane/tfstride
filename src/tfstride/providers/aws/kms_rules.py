from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.key_management import ManagedKeyLifecyclePosture
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.kms_evidence import AwsKmsGrantRelationship, AwsKmsKeyPolicyEvidence
from tfstride.providers.aws.policy_conditions import assess_principal
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED, STATE_UNKNOWN

_AWS_KMS_KEY = "aws_kms_key"
_AWS_KMS_GRANT = "aws_kms_grant"
_AWS_KMS_KEY_POLICY = "aws_kms_key_policy"
_SYMMETRIC_KEY_SPECS = frozenset({"SYMMETRIC_DEFAULT"})
_KMS_MIN_DELETION_WINDOW_DAYS = 14
_KMS_DEFAULT_DELETION_WINDOW_DAYS = 30
_KMS_DEFAULT_ROTATION_PERIOD_DAYS = 365
_KMS_ROTATION_BASELINE_MAX_DAYS = 365
_KMS_AUTOMATIC_ROTATION_ORIGIN = "AWS_KMS"
_KMS_POLICY_CONFIGURED = "configured"
_HIGH_IMPACT_GRANT_OPERATIONS = frozenset(
    {
        "creategrant",
        "decrypt",
        "derivesharedsecret",
        "encrypt",
        "generatedatakey",
        "generatedatakeypair",
        "generatedatakeypairwithoutplaintext",
        "generatedatakeywithoutplaintext",
        "generatemac",
        "reencryptfrom",
        "reencryptto",
        "sign",
    }
)


class AwsKmsRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_key_rotation_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(_AWS_KMS_KEY):
            facts = aws_facts(key)
            lifecycle_posture = _kms_key_lifecycle_posture(facts)
            if not lifecycle_posture.is_applicable:
                continue
            if not lifecycle_posture.requires_attention and lifecycle_posture.assessment != "unknown":
                continue
            issue_state = _kms_rotation_evidence_state(lifecycle_posture)

            unknown = lifecycle_posture.assessment == "unknown"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[key.address],
                    trust_boundary_id=None,
                    rationale=_kms_rotation_rationale(key.display_name, facts, issue_state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item("key_posture", _kms_key_posture_evidence(facts)),
                        evidence_item(
                            "rotation_posture",
                            _kms_rotation_evidence(facts, issue_state),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            list(lifecycle_posture.uncertainties),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_deletion_window_too_short(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(_AWS_KMS_KEY):
            facts = aws_facts(key)
            if _kms_uncertainty_evidence(facts, "deletion_window_in_days"):
                continue
            deletion_window_days = facts.kms_deletion_window_in_days
            if deletion_window_days is None or deletion_window_days >= _KMS_MIN_DELETION_WINDOW_DAYS:
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
                    affected_resources=[key.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} configures a {deletion_window_days}-day KMS deletion window, "
                        f"which is shorter than the {_KMS_MIN_DELETION_WINDOW_DAYS}-day tfSTRIDE baseline. "
                        "A short scheduled-deletion window gives operators less time to detect and cancel "
                        "accidental or malicious key deletion before dependent encrypted data becomes unrecoverable. "
                        "This finding concerns key recovery governance; it does not inspect key policies or grants."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item("key_posture", _kms_key_posture_evidence(facts)),
                        evidence_item("deletion_window_posture", _kms_deletion_window_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_policy_lockout_safety_check_bypassed(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(_AWS_KMS_KEY):
            bypassed_sources = _bypassed_policy_sources(key, context)
            if not bypassed_sources:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            source_addresses = [source for source, _ in bypassed_sources]
            source_count = len(bypassed_sources)
            source_noun = "source" if source_count == 1 else "sources"
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_dedupe_addresses([key.address, *source_addresses]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} has {source_count} resolved KMS key-policy {source_noun} with "
                        "the policy lockout safety check explicitly bypassed. Applying a replacement key "
                        "policy without that guard can leave the key without a principal able to administer "
                        "future policy changes. This finding is based only on the explicit bypass setting; "
                        "policy-document completeness is retained as evidence and is not used to infer actual "
                        "administrator lockout."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item(
                            "policy_sources",
                            _bypassed_policy_source_evidence(bypassed_sources),
                        ),
                        evidence_item(
                            "lockout_safety_posture",
                            [
                                "bypass_policy_lockout_safety_check_state=enabled",
                                "evaluated_policy_sources=resolved sources with an explicitly enabled bypass",
                                "policy_document_completeness=retained as evidence, not used as an absence claim",
                                "does_not_claim=the resulting policy necessarily locks out every administrator",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_broad_grant_authorization(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        primary_account_id = context.inventory.primary_account_id
        for key in context.inventory.by_type(_AWS_KMS_KEY):
            for grant in _deterministic_key_grants(key, context):
                principal = _known_string(grant.get("grantee_principal"))
                operations = _grant_operations(grant)
                if principal is None or not operations:
                    continue

                assessment = assess_principal(principal, primary_account_id)
                reasons = _broad_grant_reasons(
                    assessment_is_foreign=assessment.is_foreign_account,
                    assessment_is_root=assessment.is_root_like,
                    operations=operations,
                    constraints=grant.get("constraints"),
                )
                if not reasons:
                    continue

                source = _known_string(grant.get("source"))
                if source is None:
                    continue
                normalized_operations = {_normalize_grant_operation(operation) for operation in operations}
                has_create_grant = "creategrant" in normalized_operations
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=2 if has_create_grant or assessment.is_root_like else 1,
                    data_sensitivity=2,
                    lateral_movement=2 if has_create_grant or assessment.is_foreign_account else 1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[key.address, source],
                        trust_boundary_id=None,
                        rationale=_kms_grant_rationale(
                            key.display_name,
                            principal,
                            operations,
                            reasons,
                        ),
                        evidence=collect_evidence(
                            evidence_item("target_resource", _kms_target_evidence(key)),
                            evidence_item(
                                "grant_authorization",
                                _kms_grant_evidence(grant, operations),
                            ),
                            evidence_item("authorization_reasons", reasons),
                            evidence_item(
                                "authorization_scope",
                                [
                                    "establishes=an exact modeled KMS grant on this key",
                                    "does_not_establish=all independent IAM and service authorization "
                                    "requirements are satisfied",
                                ],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _kms_key_lifecycle_posture(facts: AwsResourceFacts) -> ManagedKeyLifecyclePosture:
    applicability_uncertainties = tuple(_kms_rotation_applicability_uncertainties(facts))
    if applicability_uncertainties:
        return ManagedKeyLifecyclePosture(
            "unknown",
            "not_evaluated",
            uncertainties=applicability_uncertainties,
        )
    if not _kms_automatic_rotation_supported(facts):
        return ManagedKeyLifecyclePosture("not_applicable", "not_evaluated")

    rotation_uncertainties = tuple(_kms_rotation_uncertainty_evidence(facts))
    state = facts.kms_enable_key_rotation_state or STATE_DISABLED
    if state == STATE_DISABLED:
        return ManagedKeyLifecyclePosture(
            "applicable",
            "action_required",
            issues=("rotation_disabled",),
            uncertainties=rotation_uncertainties,
        )
    if state != STATE_ENABLED or _kms_uncertainty_evidence(facts, "rotation_period_in_days"):
        return ManagedKeyLifecyclePosture(
            "applicable",
            "unknown",
            uncertainties=rotation_uncertainties,
        )

    rotation_period_days = facts.kms_rotation_period_in_days or _KMS_DEFAULT_ROTATION_PERIOD_DAYS
    if rotation_period_days > _KMS_ROTATION_BASELINE_MAX_DAYS:
        return ManagedKeyLifecyclePosture(
            "applicable",
            "action_required",
            issues=("rotation_interval_too_long",),
            uncertainties=rotation_uncertainties,
        )
    return ManagedKeyLifecyclePosture(
        "applicable",
        "compliant",
        uncertainties=rotation_uncertainties,
    )


def _kms_rotation_applicability_uncertainties(facts: AwsResourceFacts) -> list[str]:
    field_paths = (
        "key_usage",
        "key_spec",
        "customer_master_key_spec",
        "origin",
        "custom_key_store_id",
        "xks_key_id",
    )
    return [
        uncertainty
        for uncertainty in facts.kms_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
    ]


def _kms_automatic_rotation_supported(facts: AwsResourceFacts) -> bool:
    key_usage = _normalized_upper(facts.kms_key_usage) or "ENCRYPT_DECRYPT"
    if key_usage != "ENCRYPT_DECRYPT":
        return False

    for spec in (facts.kms_key_spec, facts.kms_customer_master_key_spec):
        normalized = _normalized_upper(spec)
        if normalized is not None and normalized not in _SYMMETRIC_KEY_SPECS:
            return False

    origin = _normalized_upper(facts.kms_key_origin) or _KMS_AUTOMATIC_ROTATION_ORIGIN
    return (
        origin == _KMS_AUTOMATIC_ROTATION_ORIGIN
        and facts.kms_custom_key_store_id is None
        and facts.kms_xks_key_id is None
    )


def _kms_rotation_evidence_state(lifecycle_posture: ManagedKeyLifecyclePosture) -> str:
    if lifecycle_posture.assessment == "unknown":
        return STATE_UNKNOWN
    if lifecycle_posture.issues == ("rotation_disabled",):
        return STATE_DISABLED
    if lifecycle_posture.issues == ("rotation_interval_too_long",):
        return "too_long"
    raise ValueError(f"unsupported AWS managed-key lifecycle posture: {lifecycle_posture!r}")


def _normalized_upper(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().upper()
    return text or None


def _kms_target_evidence(key: NormalizedResource) -> list[str]:
    values = [f"address={key.address}", f"type={key.resource_type}"]
    if key.identifier:
        values.append(f"identifier={key.identifier}")
    if key.arn:
        values.append(f"arn={key.arn}")
    return values


def _kms_key_posture_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"key_usage={facts.kms_key_usage or 'ENCRYPT_DECRYPT'}",
        f"key_spec={facts.kms_key_spec or 'unset'}",
        f"customer_master_key_spec={facts.kms_customer_master_key_spec or 'unset'}",
        f"origin={facts.kms_key_origin or _KMS_AUTOMATIC_ROTATION_ORIGIN}",
        f"custom_key_store_id={facts.kms_custom_key_store_id or 'unset'}",
        f"xks_key_id={facts.kms_xks_key_id or 'unset'}",
        f"multi_region_state={facts.kms_multi_region_state or STATE_DISABLED}",
    ]


def _kms_rotation_evidence(facts: AwsResourceFacts, issue_state: str) -> list[str]:
    state = facts.kms_enable_key_rotation_state or STATE_DISABLED
    values = [
        f"enable_key_rotation_state={state}",
        "rotation_period_in_days="
        + (str(facts.kms_rotation_period_in_days) if facts.kms_rotation_period_in_days is not None else "unset"),
        f"default_rotation_period_days={_KMS_DEFAULT_ROTATION_PERIOD_DAYS}",
        f"tfstride_rotation_baseline_max_days={_KMS_ROTATION_BASELINE_MAX_DAYS}",
        f"rotation_posture_state={issue_state}",
    ]
    if facts.kms_enable_key_rotation is True:
        values.append("enable_key_rotation is true")
    elif facts.kms_enable_key_rotation is False:
        values.append("enable_key_rotation is false")
    else:
        values.append("enable_key_rotation is unknown")
    if state == STATE_ENABLED and not _kms_uncertainty_evidence(
        facts,
        "rotation_period_in_days",
    ):
        values.append(
            "effective_rotation_period_days="
            + str(facts.kms_rotation_period_in_days or _KMS_DEFAULT_ROTATION_PERIOD_DAYS)
        )
    values.append(
        "automatic rotation is evaluated only for symmetric ENCRYPT_DECRYPT keys with AWS_KMS origin "
        "outside custom key stores"
    )
    return values


def _kms_deletion_window_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [
        f"deletion_window_in_days={facts.kms_deletion_window_in_days}",
        f"minimum_deletion_window_days={_KMS_MIN_DELETION_WINDOW_DAYS}",
        f"default_deletion_window_days={_KMS_DEFAULT_DELETION_WINDOW_DAYS}",
    ]
    values.extend(
        "posture_uncertainty=" + uncertainty
        for uncertainty in _kms_uncertainty_evidence(facts, "deletion_window_in_days")
    )
    return values


def _kms_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.kms_posture_uncertainties if field_path in uncertainty]


def _kms_rotation_uncertainty_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.kms_posture_uncertainties
        if "enable_key_rotation" in uncertainty or "rotation_period_in_days" in uncertainty
    ]


def _kms_rotation_rationale(
    display_name: str,
    facts: AwsResourceFacts,
    issue_state: str,
) -> str:
    if issue_state == STATE_UNKNOWN:
        return (
            f"{display_name} does not show deterministic AWS KMS key rotation posture in the Terraform plan. "
            "Review the final plan or deployed key to confirm automatic rotation is enabled with a bounded "
            f"period no longer than the {_KMS_ROTATION_BASELINE_MAX_DAYS}-day tfSTRIDE baseline."
        )
    if issue_state == "too_long":
        return (
            f"{display_name} enables automatic KMS key rotation every "
            f"{facts.kms_rotation_period_in_days} days, which exceeds the "
            f"{_KMS_ROTATION_BASELINE_MAX_DAYS}-day tfSTRIDE baseline. A long cryptographic-material "
            "lifecycle weakens rotation governance for dependent encrypted data."
        )
    return (
        f"{display_name} has automatic KMS key rotation disabled. Customer-managed symmetric KMS keys can "
        "protect secrets, storage, databases, and Kubernetes secrets; disabling rotation weakens key lifecycle "
        "governance for dependent encrypted data."
    )


def _bypassed_policy_sources(
    key: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[tuple[str, AwsKmsKeyPolicyEvidence]]:
    sources: list[tuple[str, AwsKmsKeyPolicyEvidence]] = []
    for raw_policy in aws_facts(key).kms_key_policies:
        source = _known_string(raw_policy.get("source"))
        if source is None or raw_policy.get("resolved_key_address") != key.address:
            continue
        if raw_policy.get("configuration_state") not in {
            _KMS_POLICY_CONFIGURED,
            STATE_UNKNOWN,
        }:
            continue
        if raw_policy.get("bypass_lockout_safety_check_state") != STATE_ENABLED:
            continue
        if source != key.address:
            source_resource = context.inventory.get_by_address(source)
            if source_resource is None or source_resource.resource_type != _AWS_KMS_KEY_POLICY:
                continue
            if aws_facts(source_resource).kms_key_policy_resolved_key_address != key.address:
                continue
        sources.append((source, raw_policy))
    return sorted(sources, key=lambda item: item[0])


def _bypassed_policy_source_evidence(
    sources: list[tuple[str, AwsKmsKeyPolicyEvidence]],
) -> list[str]:
    values: list[str] = []
    for source, policy in sources:
        raw_uncertainties = policy.get("posture_uncertainties")
        uncertainties = (
            [
                uncertainty.strip()
                for uncertainty in raw_uncertainties
                if isinstance(uncertainty, str) and uncertainty.strip()
            ]
            if isinstance(raw_uncertainties, list)
            else []
        )
        values.append(
            f"source={source}; source_type={policy.get('source_type') or 'unknown'}; "
            f"configuration_state={policy.get('configuration_state')}; "
            f"completeness_state={policy.get('completeness_state')}; "
            "bypass_lockout_safety_check_state=enabled; "
            f"posture_uncertainties={'; '.join(uncertainties) if uncertainties else 'none'}"
        )
    return values


def _deterministic_key_grants(
    key: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[AwsKmsGrantRelationship]:
    grants: list[AwsKmsGrantRelationship] = []
    for raw_grant in aws_facts(key).kms_grants:
        source = _known_string(raw_grant.get("source"))
        if source is None or raw_grant.get("resolved_key_address") != key.address:
            continue
        source_resource = context.inventory.get_by_address(source)
        if source_resource is None or source_resource.resource_type != _AWS_KMS_GRANT:
            continue
        source_facts = aws_facts(source_resource)
        if source_facts.kms_grant_resolved_key_address != key.address:
            continue
        if _grant_authorization_uncertainties(source_facts):
            continue
        grants.append(raw_grant)
    return sorted(grants, key=lambda grant: str(grant.get("source") or ""))


def _grant_authorization_uncertainties(facts: AwsResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in facts.kms_grant_posture_uncertainties
        if any(field in uncertainty for field in ("grantee_principal", "operations", "constraints", "key_id"))
    ]


def _grant_operations(grant: AwsKmsGrantRelationship) -> list[str]:
    raw_operations = grant.get("operations")
    if not isinstance(raw_operations, list):
        return []
    operations: list[str] = []
    seen: set[str] = set()
    for raw_operation in raw_operations:
        operation = _known_string(raw_operation)
        if operation is None:
            continue
        normalized = _normalize_grant_operation(operation)
        if normalized in seen:
            continue
        seen.add(normalized)
        operations.append(operation)
    return sorted(operations, key=str.casefold)


def _normalize_grant_operation(value: str) -> str:
    text = value.strip().casefold()
    return text[4:] if text.startswith("kms:") else text


def _broad_grant_reasons(
    *,
    assessment_is_foreign: bool,
    assessment_is_root: bool,
    operations: list[str],
    constraints: object,
) -> list[str]:
    normalized_operations = {_normalize_grant_operation(operation) for operation in operations}
    high_impact_operations = normalized_operations & _HIGH_IMPACT_GRANT_OPERATIONS
    reasons: list[str] = []
    if high_impact_operations and assessment_is_foreign:
        reasons.append("grantee principal belongs to a foreign AWS account")
    if high_impact_operations and assessment_is_root:
        reasons.append("grantee principal is an AWS account principal represented by its root ARN")
    if "creategrant" in normalized_operations and not _has_effective_grant_constraints(
        constraints,
    ):
        reasons.append("CreateGrant is allowed without an encryption-context constraint")
    return reasons


def _has_effective_grant_constraints(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    return any(
        isinstance(constraint_values, Mapping)
        and any(_known_string(item) is not None for item in constraint_values.values())
        for constraint_values in value.values()
    )


def _kms_grant_evidence(
    grant: AwsKmsGrantRelationship,
    operations: list[str],
) -> list[str]:
    constraints = grant.get("constraints")
    return [
        f"source={grant.get('source')}",
        f"grant_id={grant.get('grant_id') or 'unset'}",
        f"grantee_principal={grant.get('grantee_principal')}",
        f"operations={', '.join(operations)}",
        "constraints_configured=" + str(_has_effective_grant_constraints(constraints)).lower(),
        f"constraints={constraints if constraints else 'none'}",
        f"retiring_principal={grant.get('retiring_principal') or 'unset'}",
        f"retire_on_delete_state={grant.get('retire_on_delete_state') or 'unknown'}",
    ]


def _kms_grant_rationale(
    key_display_name: str,
    principal: str,
    operations: list[str],
    reasons: list[str],
) -> str:
    delegation_note = ""
    if any(reason.startswith("CreateGrant is allowed") for reason in reasons):
        delegation_note = (
            " Unconstrained CreateGrant authority can delegate only the operations allowed by its parent grant."
        )
    return (
        f"{key_display_name} has an exact modeled KMS grant for {principal} with "
        f"{', '.join(operations)} authority. The grant is broad because {'; '.join(reasons)}. "
        "KMS grants participate in key authorization independently of key-policy principal statements."
        f"{delegation_note} This finding establishes the key-side grant, not every independent IAM or "
        "service authorization requirement needed to complete an operation."
    )


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _dedupe_addresses(addresses: list[str]) -> list[str]:
    return list(dict.fromkeys(address for address in addresses if address))
