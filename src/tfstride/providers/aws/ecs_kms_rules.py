from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import EvidenceItem, Finding, NormalizedResource, SeverityReasoning
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.kms_evidence import (
    AwsEcsKmsManagementEffect,
    AwsEcsKmsManagementOperationClass,
    AwsEcsKmsManagementPath,
    AwsEcsKmsOperationPath,
)
from tfstride.providers.aws.protected_data_evidence import (
    AwsEcsS3ProtectedDataConvergence,
)
from tfstride.providers.aws.resource_decoration.ecs_s3_access_paths import current_ecs_s3_access_path
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder
from tfstride.providers.aws.s3_bucket_policies import prepare_s3_bucket_policy_sources

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_KMS_KEY = "aws_kms_key"
_DECRYPT_OPERATION = "kms:Decrypt"
_SIGN_OPERATION = "kms:Sign"
_MAC_GENERATION_OPERATION = "kms:GenerateMac"
_SIGNING_OPERATIONS = frozenset({_SIGN_OPERATION, _MAC_GENERATION_OPERATION})
_OPERATION_KEY_USAGE = {
    _DECRYPT_OPERATION: "ENCRYPT_DECRYPT",
    _SIGN_OPERATION: "SIGN_VERIFY",
    _MAC_GENERATION_OPERATION: "GENERATE_VERIFY_MAC",
}
_AUTHORIZATION_BASES = frozenset({"key_policy_direct", "iam_via_key_policy", "grant"})
_MANAGEMENT_OPERATION_DEFINITIONS: dict[
    str,
    tuple[AwsEcsKmsManagementOperationClass, AwsEcsKmsManagementEffect],
] = {
    "kms:CreateGrant": ("authorization_administration", "delegation"),
    "kms:PutKeyPolicy": ("authorization_administration", "delegation"),
    "kms:DisableKey": ("disruptive_administration", "disruption"),
    "kms:ScheduleKeyDeletion": ("destructive_administration", "disruption"),
    "kms:DeleteImportedKeyMaterial": ("destructive_administration", "disruption"),
}
_MANAGEMENT_OPERATION_ORDER = tuple(_MANAGEMENT_OPERATION_DEFINITIONS)


class AwsEcsKmsOperationRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_decrypt_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            frozenset({_DECRYPT_OPERATION}),
            disclosure=True,
        )

    def detect_public_service_signing_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_operation_access(
            context,
            rule_id,
            _SIGNING_OPERATIONS,
            disclosure=False,
        )

    def detect_public_service_kms_key_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "disruption")

    def detect_public_service_kms_authorization_delegation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        return self._detect_public_management_access(context, rule_id, "delegation")

    def _detect_public_operation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        operations: frozenset[str],
        *,
        disclosure: bool,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            paths = [
                path
                for path in aws_facts(service).ecs_kms_operation_paths
                if _is_deterministic_operation_path(
                    path,
                    service.address,
                    context,
                    operations,
                )
            ]
            if not paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            paths = ingress.current_workload_paths(paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not paths:
                continue

            task_definition_addresses = path_string_values(paths, "task_definition_address")
            role_addresses = path_string_values(paths, "role_address")
            key_addresses = path_string_values(paths, "key_address")
            authorization_bases = _authorization_bases(paths)
            matched_operations = _path_operations(paths)
            protected_data_convergences = (
                _resolved_protected_data_convergences(paths, service, context) if disclosure else []
            )
            protected_data_dependent_addresses = _protected_data_dependent_addresses(
                protected_data_convergences,
            )
            severity_reasoning = _operation_severity(
                disclosure=disclosure,
                key_count=len(key_addresses),
                downstream_dependent_count=len(protected_data_dependent_addresses),
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *key_addresses,
                *protected_data_dependent_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=_rationale(
                        service,
                        matched_operations,
                        len(key_addresses),
                        authorization_bases,
                        disclosure=disclosure,
                        downstream_dependent_count=len(protected_data_dependent_addresses),
                        downstream_dependency_count=len(protected_data_convergences),
                    ),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item("task_roles", _task_role_evidence(paths)),
                        evidence_item("kms_operation_paths", _operation_path_evidence(paths)),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(matched_operations),
                        ),
                        *(
                            [
                                evidence_item(
                                    "downstream_dependencies",
                                    _protected_data_dependency_evidence(
                                        protected_data_convergences,
                                    ),
                                ),
                                evidence_item(
                                    "protected_data_uncertainties",
                                    aws_facts(service).ecs_s3_protected_data_convergence_uncertainties,
                                ),
                            ]
                            if disclosure
                            else []
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def _detect_public_management_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
        management_effect: AwsEcsKmsManagementEffect,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            paths = [
                path
                for path in aws_facts(service).ecs_kms_management_paths
                if _is_deterministic_management_path(
                    path,
                    service.address,
                    context,
                    management_effect,
                )
            ]
            if not paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            paths = ingress.current_workload_paths(paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not paths:
                continue

            task_definition_addresses = path_string_values(paths, "task_definition_address")
            role_addresses = path_string_values(paths, "role_address")
            key_addresses = path_string_values(paths, "key_address")
            downstream_dependencies = (
                _resolved_downstream_dependencies(paths, context) if management_effect == "disruption" else []
            )
            downstream_dependent_addresses = _downstream_dependent_addresses(downstream_dependencies)
            recovery_window_evidence = (
                _recovery_window_evidence(paths, context) if management_effect == "disruption" else []
            )
            authorization_bases = _authorization_bases(paths)
            operations = _management_operations(paths)
            severity_reasoning = _management_severity(
                len(key_addresses),
                len(downstream_dependent_addresses),
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *key_addresses,
                *downstream_dependent_addresses,
            ]
            management_evidence: list[EvidenceItem | None] = [
                evidence_item("network_path", ingress.network_path),
                *ingress.evidence,
                evidence_item(
                    "task_definitions",
                    [f"address={address}" for address in task_definition_addresses],
                ),
                evidence_item("task_roles", _task_role_evidence(paths)),
                evidence_item("kms_management_paths", _management_path_evidence(paths)),
                evidence_item(
                    "assessment_scope",
                    _management_assessment_scope(operations, management_effect),
                ),
            ]
            if management_effect == "disruption":
                management_evidence.extend(
                    [
                        evidence_item(
                            "downstream_dependencies",
                            _downstream_dependency_evidence(downstream_dependencies),
                        ),
                        evidence_item(
                            "recovery_window",
                            recovery_window_evidence,
                        ),
                    ]
                )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(load_balancer_addresses, context),
                    rationale=_management_rationale(
                        service,
                        operations,
                        len(key_addresses),
                        authorization_bases,
                        management_effect,
                        downstream_dependent_count=len(downstream_dependent_addresses),
                        downstream_dependency_count=len(downstream_dependencies),
                        recovery_window_evidence=recovery_window_evidence,
                    ),
                    evidence=collect_evidence(*management_evidence),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_operation_path(
    path: AwsEcsKmsOperationPath,
    service_address: str,
    context: RuleEvaluationContext,
    operations: frozenset[str],
) -> bool:
    key_address = path.get("key_address")
    key = context.inventory.get_by_address(key_address) if isinstance(key_address, str) else None
    if key is None or key.resource_type != _AWS_KMS_KEY:
        return False

    operation = path.get("operation")
    if not isinstance(operation, str) or operation not in operations:
        return False

    key_facts = aws_facts(key)
    key_arn = key_facts.kms_key_arn or key.arn
    expected_usage = _OPERATION_KEY_USAGE[operation]
    authorization_bases = path.get("authorization_bases")
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key_name), str) and bool(path.get(key_name))
            for key_name in (
                "task_definition_address",
                "role_address",
                "key_address",
                "key_arn",
                "operation",
            )
        )
        and path.get("operation") == operation
        and path.get("key_arn") == key_arn
        and _is_exact_kms_key_arn(key_arn)
        and path.get("key_usage") == expected_usage
        and key_facts.kms_key_usage == expected_usage
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("authorization_state") == "allowed"
        and path.get("role_policy_complete") is True
        and path.get("explicit_deny") is False
        and path.get("conditional_evaluation_required") is False
        and isinstance(authorization_bases, list)
        and bool(authorization_bases)
        and all(isinstance(value, str) and value in _AUTHORIZATION_BASES for value in authorization_bases)
    )


def _is_deterministic_management_path(
    path: AwsEcsKmsManagementPath,
    service_address: str,
    context: RuleEvaluationContext,
    management_effect: AwsEcsKmsManagementEffect,
) -> bool:
    key_address = path.get("key_address")
    key = context.inventory.get_by_address(key_address) if isinstance(key_address, str) else None
    if key is None or key.resource_type != _AWS_KMS_KEY:
        return False

    key_facts = aws_facts(key)
    key_arn = key_facts.kms_key_arn or key.arn
    operation = path.get("operation")
    operation_class = path.get("operation_class")
    authorization_bases = path.get("authorization_bases")
    origin_compatibility = path.get("key_origin_compatibility_state")
    authorization_record = path.get("authorization_record")
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key_name), str) and bool(path.get(key_name))
            for key_name in (
                "task_definition_address",
                "role_address",
                "key_address",
                "key_arn",
                "operation",
            )
        )
        and path.get("key_arn") == key_arn
        and _is_exact_kms_key_arn(key_arn)
        and isinstance(operation, str)
        and operation in _MANAGEMENT_OPERATION_ORDER
        and _MANAGEMENT_OPERATION_DEFINITIONS.get(operation)
        == (
            operation_class,
            path.get("management_effect"),
        )
        and path.get("management_effect") == management_effect
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("authorization_state") == "allowed"
        and path.get("role_policy_complete") is True
        and path.get("key_policy_complete") is True
        and path.get("same_account") is True
        and path.get("explicit_deny") is False
        and path.get("authorization_requires_condition_evaluation") is False
        and origin_compatibility in {"compatible", "not_applicable"}
        and isinstance(authorization_bases, list)
        and bool(authorization_bases)
        and all(isinstance(value, str) and value in _AUTHORIZATION_BASES for value in authorization_bases)
        and isinstance(authorization_record, Mapping)
        and authorization_record.get("operation") == operation
        and authorization_record.get("key_address") == key_address
        and authorization_record.get("key_arn") == key_arn
        and authorization_record.get("authorization_state") == "allowed"
    )


def _is_exact_kms_key_arn(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("arn:"):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[2] == "kms"
        and parts[3]
        and parts[4].isdigit()
        and len(parts[4]) == 12
        and parts[5].startswith("key/")
        and len(parts[5]) > len("key/")
        and "*" not in value
        and "?" not in value
    )


def _authorization_bases(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted({value for path in paths for value in _string_values(path.get("authorization_bases"))})


def _management_operations(paths: Sequence[AwsEcsKmsManagementPath]) -> list[str]:
    return [
        operation
        for operation in _MANAGEMENT_OPERATION_ORDER
        if any(path.get("operation") == operation for path in paths)
    ]


def _management_severity(
    key_count: int,
    downstream_dependent_count: int = 0,
) -> SeverityReasoning:
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=2,
        data_sensitivity=1,
        lateral_movement=1,
        blast_radius=2 if key_count > 1 or downstream_dependent_count > 1 else 1,
    )


def _management_rationale(
    service: NormalizedResource,
    operations: list[str],
    key_count: int,
    authorization_bases: list[str],
    management_effect: AwsEcsKmsManagementEffect,
    *,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
    recovery_window_evidence: Sequence[str] = (),
) -> str:
    operation_text = _operation_text(operations)
    basis = ", ".join(authorization_bases)
    if management_effect == "disruption":
        consequence = "could disrupt KMS-backed data or cryptographic availability through those operations"
        capability = "deterministic KMS key-disruption authority"
        downstream = (
            f" The modeled keys have {downstream_dependent_count} unique downstream encrypted dependent "
            f"resource(s) across {downstream_dependency_count} unique dependency relationship(s)."
            if downstream_dependent_count
            else " No resolved downstream encrypted dependent resources are modeled for these keys."
        )
        recovery = (
            f" Recovery-window evidence: {', '.join(recovery_window_evidence)}."
            if recovery_window_evidence
            else " Recovery-window evidence is unavailable or unresolved."
        )
    else:
        consequence = "could change KMS authorization or delegate further key authority through those operations"
        capability = "deterministic KMS authorization-delegation authority"
        downstream = ""
        recovery = ""
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"{capability} ({operation_text}) on {key_count} exact modeled KMS key(s) through {basis}. A compromise "
        f"of the public workload {consequence}.{downstream}{recovery} This establishes cryptographic "
        "key-management authority, not proof "
        "that the operation will succeed outside the modeled AWS policy, grant, and key-state evidence. The KMS "
        "key itself is not public."
    )


def _resolved_downstream_dependencies(
    paths: Sequence[AwsEcsKmsManagementPath],
    context: RuleEvaluationContext,
) -> list[Mapping[str, object]]:
    dependencies: list[Mapping[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for key_address in path_string_values(paths, "key_address"):
        key = context.inventory.get_by_address(key_address)
        if key is None or key.resource_type != _AWS_KMS_KEY:
            continue
        for dependency in aws_facts(key).kms_encryption_dependencies:
            if dependency.get("resolution_state") != "resolved":
                continue
            if dependency.get("key_address") != key_address:
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
                or dependent.provider != "aws"
                or source.provider != "aws"
                or dependency.get("dependent_resource_type") != dependent.resource_type
                or dependency.get("dependency_source_type") != source.resource_type
            ):
                continue
            key_facts = aws_facts(key)
            recorded_key_arn = dependency.get("key_arn")
            if recorded_key_arn is not None and recorded_key_arn != key_facts.kms_key_arn:
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
        ),
    )


def _downstream_dependent_addresses(
    dependencies: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            value
            for dependency in dependencies
            if isinstance(value := dependency.get("dependent_address"), str) and value
        }
    )


def _downstream_dependency_evidence(
    dependencies: Sequence[Mapping[str, object]],
) -> list[str]:
    dependent_addresses = _downstream_dependent_addresses(dependencies)
    values = [
        (
            f"unique_dependency_count={len(dependencies)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            f"blast_radius_basis="
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
            )
        )
        for dependency in dependencies
    )
    return values


def _recovery_window_evidence(
    paths: Sequence[AwsEcsKmsManagementPath],
    context: RuleEvaluationContext,
) -> list[str]:
    operations_by_key: dict[str, set[str]] = {}
    for path in paths:
        key_address = path.get("key_address")
        operation = path.get("operation")
        if isinstance(key_address, str) and isinstance(operation, str):
            operations_by_key.setdefault(key_address, set()).add(operation)

    values: list[str] = []
    for key_address in sorted(operations_by_key):
        key = context.inventory.get_by_address(key_address)
        if key is None or key.resource_type != _AWS_KMS_KEY:
            continue
        operations = operations_by_key[key_address]
        if "kms:ScheduleKeyDeletion" in operations:
            deletion_window = aws_facts(key).kms_deletion_window_in_days
            values.append(
                "; ".join(
                    (
                        f"key_address={key_address}",
                        "operation=kms:ScheduleKeyDeletion",
                        f"deletion_window_in_days={deletion_window if deletion_window is not None else 'unknown'}",
                        (
                            "recovery_window_state=cancelable_scheduled_deletion"
                            if deletion_window is not None
                            else "recovery_window_state=unknown_scheduled_deletion_window"
                        ),
                    )
                )
            )
        for operation in _MANAGEMENT_OPERATION_ORDER:
            if operation not in operations or operation == "kms:ScheduleKeyDeletion":
                continue
            values.append(
                "; ".join(
                    (
                        f"key_address={key_address}",
                        f"operation={operation}",
                        "recovery_window_state=not_governed_by_deletion_window",
                    )
                )
            )
    return values


def _management_assessment_scope(
    operations: list[str],
    management_effect: AwsEcsKmsManagementEffect,
) -> list[str]:
    effect_text = "key disruption" if management_effect == "disruption" else "authorization delegation"
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for ECS task roles "
            f"with {effect_text} effect on exact modeled KMS keys"
        ),
        (
            "does_not_establish=successful operation completion, authority over keys outside the modeled plan, "
            "or runtime impact beyond the preserved AWS policy, grant, and key-state evidence"
        ),
    ]


def _management_path_evidence(paths: Sequence[AwsEcsKmsManagementPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path['key_address']}",
                    f"key_arn={path['key_arn']}",
                    f"key_id={path.get('key_id') or 'unknown'}",
                    f"key_usage={path.get('key_usage') or 'unknown'}",
                    f"key_origin={path.get('key_origin') or 'unknown'}",
                    f"operation={path['operation']}",
                    f"operation_class={path['operation_class']}",
                    f"management_effect={path['management_effect']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    f"authorization_state={path['authorization_state']}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases')))}",
                    f"candidate_authorization_bases={','.join(_string_values(path.get('candidate_authorization_bases')))}",
                    f"policy_action_patterns={','.join(_string_values(path.get('policy_action_patterns')))}",
                    f"policy_resources={','.join(_string_values(path.get('policy_resources')))}",
                    f"deny_action_patterns={','.join(_string_values(path.get('deny_action_patterns')) or ['none'])}",
                    f"key_policy_sources={','.join(_string_values(path.get('key_policy_source_addresses')) or ['none'])}",
                    f"identity_policy_sources={','.join(_string_values(path.get('identity_policy_source_addresses')) or ['none'])}",
                    f"grant_sources={','.join(_management_grant_sources(path))}",
                    f"grant_constraints={';'.join(_structured_values(path.get('grant_constraints')) or ['none'])}",
                    f"constraint_state={path.get('constraint_state') or 'not_configured'}",
                    (
                        "conditional_policy_evidence_present="
                        f"{str(path.get('conditional_policy_evidence_present')).lower()}"
                    ),
                    (
                        "authorization_requires_condition_evaluation="
                        f"{str(path.get('authorization_requires_condition_evaluation')).lower()}"
                    ),
                    f"key_origin_compatibility={path.get('key_origin_compatibility_state')}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _management_grant_sources(path: AwsEcsKmsManagementPath) -> list[str]:
    sources: set[str] = set()
    for grant in path["kms_grants"]:
        source = grant.get("source")
        if source:
            sources.add(source)
    return sorted(sources) or ["none"]


def _operation_severity(
    *,
    disclosure: bool,
    key_count: int,
    downstream_dependent_count: int = 0,
) -> SeverityReasoning:
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=1,
        data_sensitivity=2 if disclosure else 1,
        lateral_movement=1,
        blast_radius=2 if key_count > 1 or downstream_dependent_count > 1 else 1,
    )


def _rationale(
    service: NormalizedResource,
    operations: list[str],
    key_count: int,
    authorization_bases: list[str],
    *,
    disclosure: bool,
    downstream_dependent_count: int = 0,
    downstream_dependency_count: int = 0,
) -> str:
    basis = ", ".join(authorization_bases)
    operation_text = _operation_text(operations)
    if disclosure:
        capability = "could attempt KMS decrypt operations, creating information-disclosure potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload possesses useful "
            "ciphertext or can disclose plaintext."
        )
        downstream = (
            f" The exact decrypt evidence converges with {downstream_dependent_count} unique KMS-protected S3 "
            f"resource(s) across {downstream_dependency_count} unique encryption dependency relationship(s)."
            if downstream_dependent_count
            else " No resolved KMS-protected S3 access convergence is modeled for these keys."
        )
    elif operations == [_SIGN_OPERATION]:
        capability = "could generate KMS signatures, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "application-level signature accepted by a relying system."
        )
        downstream = ""
    elif operations == [_MAC_GENERATION_OPERATION]:
        capability = "could generate KMS message authentication codes, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "message authentication code accepted by a relying system."
        )
        downstream = ""
    else:
        capability = "could generate KMS signatures or message authentication codes, creating spoofing potential"
        qualification = (
            "This establishes cryptographic-operation authority, not proof that the workload can produce a valid "
            "signature or message authentication code accepted by a relying system."
        )
        downstream = ""
    return (
        f"{service.display_name} is reachable through an internet-facing load balancer and its ECS task role has "
        f"deterministic {operation_text} authority on {key_count} exact modeled KMS key(s) through {basis}. "
        f"A compromise of the public workload {capability}. {qualification}{downstream} The KMS key itself is not public."
    )


def _resolved_protected_data_convergences(
    paths: Sequence[AwsEcsKmsOperationPath],
    service: NormalizedResource,
    context: RuleEvaluationContext,
) -> list[AwsEcsS3ProtectedDataConvergence]:
    valid_path_keys = {
        (
            path["task_definition_address"],
            path["role_address"],
            path["role_arn"],
            path["key_address"],
            path["key_arn"],
        )
        for path in paths
        if path["operation"] == _DECRYPT_OPERATION
    }
    decoration_context = AwsDecorationContext(AwsResourceIndexBuilder().build(list(context.inventory.resources)))
    bucket_policies = prepare_s3_bucket_policy_sources(list(context.inventory.resources), decoration_context)
    convergences: list[AwsEcsS3ProtectedDataConvergence] = []
    seen: set[tuple[str, str, str]] = set()
    for convergence in aws_facts(service).ecs_s3_protected_data_convergences:
        if not _is_valid_protected_data_convergence(
            convergence,
            service,
            context,
            valid_path_keys,
        ):
            continue
        current_access_path = current_ecs_s3_access_path(
            convergence["access_path"],
            service,
            decoration_context,
            actions=frozenset({"s3:GetObject", "s3:GetObjectVersion"}),
            bucket_policies=bucket_policies,
        )
        if current_access_path is None:
            continue
        convergence = convergence.copy()
        convergence["access_path"] = current_access_path
        dependency = convergence["encryption_dependency"]
        fingerprint = (
            convergence["bucket_address"],
            dependency["dependency_source_address"],
            repr(dependency["configuration_path"]),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        convergences.append(convergence)
    return sorted(
        convergences,
        key=lambda convergence: (
            convergence["bucket_address"],
            convergence["encryption_dependency"]["dependency_source_address"],
            repr(convergence["encryption_dependency"]["configuration_path"]),
        ),
    )


def _is_valid_protected_data_convergence(
    convergence: AwsEcsS3ProtectedDataConvergence,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    valid_path_keys: set[tuple[str, str, str | None, str, str]],
) -> bool:
    if (
        convergence["convergence_state"] != "resolved"
        or convergence["workload_address"] != service.address
        or convergence["workload_type"] != _AWS_ECS_SERVICE
        or convergence["operation"] != _DECRYPT_OPERATION
        or convergence["access_class"] != "read"
        or convergence["runtime_identity_match"] is not True
        or convergence["protected_resource_match"] is not True
        or convergence["key_identity_match"] is not True
    ):
        return False

    if (
        convergence["task_definition_address"],
        convergence["role_address"],
        convergence["role_arn"],
        convergence["key_address"],
        convergence["key_arn"],
    ) not in valid_path_keys:
        return False

    task_definition = context.inventory.get_by_address(
        convergence["task_definition_address"],
    )
    role = context.inventory.get_by_address(convergence["role_address"])
    key = context.inventory.get_by_address(convergence["key_address"])
    bucket = context.inventory.get_by_address(convergence["bucket_address"])
    if (
        task_definition is None
        or task_definition.provider != "aws"
        or task_definition.resource_type != _AWS_ECS_TASK_DEFINITION
        or role is None
        or role.provider != "aws"
        or role.resource_type != _AWS_IAM_ROLE
        or convergence["role_arn"] != role.arn
        or key is None
        or key.provider != "aws"
        or key.resource_type != _AWS_KMS_KEY
        or bucket is None
        or bucket.provider != "aws"
        or bucket.resource_type != "aws_s3_bucket"
        or convergence["key_arn"] != (aws_facts(key).kms_key_arn or key.arn)
        or convergence["bucket_arn"] != bucket.arn
    ):
        return False

    access_path = convergence["access_path"]
    operation_path = convergence["key_operation_path"]
    if (
        access_path["workload_address"] != service.address
        or access_path["workload_type"] != _AWS_ECS_SERVICE
        or access_path.get("task_definition_address") != convergence["task_definition_address"]
        or access_path["role_address"] != convergence["role_address"]
        or access_path["role_arn"] != convergence["role_arn"]
        or access_path["bucket_address"] != convergence["bucket_address"]
        or access_path["bucket_arn"] != convergence["bucket_arn"]
        or access_path["access_state"] != "allowed"
        or access_path["role_kind"] != "ecs_task_role"
        or access_path["credential_context"] != "workload_runtime"
        or operation_path["workload_address"] != service.address
        or operation_path["workload_type"] != _AWS_ECS_SERVICE
        or operation_path["task_definition_address"] != convergence["task_definition_address"]
        or operation_path["role_address"] != convergence["role_address"]
        or operation_path["key_address"] != convergence["key_address"]
        or operation_path["key_arn"] != convergence["key_arn"]
        or operation_path["operation"] != _DECRYPT_OPERATION
        or operation_path["authorization_state"] != "allowed"
    ):
        return False

    dependency = convergence["encryption_dependency"]
    source_address = dependency["dependency_source_address"]
    source = context.inventory.get_by_address(source_address)
    return bool(
        dependency["resolution_state"] == "resolved"
        and dependency["encryption_ownership_state"] == "customer_managed"
        and dependency["dependent_address"] == convergence["bucket_address"]
        and dependency["dependent_resource_type"] == bucket.resource_type
        and dependency["key_address"] == convergence["key_address"]
        and dependency["key_arn"] == convergence["key_arn"]
        and source is not None
        and source.provider == "aws"
        and dependency["dependency_source_type"] == source.resource_type
    )


def _protected_data_dependent_addresses(
    convergences: Sequence[AwsEcsS3ProtectedDataConvergence],
) -> list[str]:
    return sorted({convergence["bucket_address"] for convergence in convergences})


def _protected_data_dependency_evidence(
    convergences: Sequence[AwsEcsS3ProtectedDataConvergence],
) -> list[str]:
    dependent_addresses = _protected_data_dependent_addresses(convergences)
    values = [
        (
            f"unique_dependency_count={len(convergences)}; "
            f"unique_dependent_resource_count={len(dependent_addresses)}; "
            "downstream_dependency_state="
            f"{'resolved_dependents' if dependent_addresses else 'no_resolved_dependents'}"
        )
    ]
    values.extend(
        "; ".join(
            (
                f"key_address={convergence['key_address']}",
                f"dependent_address={convergence['bucket_address']}",
                f"dependency_source={convergence['encryption_dependency']['dependency_source_address']}",
                f"configuration_path={convergence['encryption_dependency']['configuration_path']}",
                f"reference_kind={convergence['encryption_dependency']['reference_kind'] or 'unknown'}",
            )
        )
        for convergence in convergences
    )
    return values


def _assessment_scope(operations: list[str]) -> list[str]:
    return [
        (
            f"establishes=deterministic {_operation_text(operations)} authority for an ECS task role "
            "on exact modeled KMS keys"
        ),
        (
            "does_not_establish=useful ciphertext, plaintext disclosure, accepted application signatures or MACs, "
            "or runtime success outside the modeled AWS policy and grant evidence"
        ),
    ]


def _path_operations(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
    return [
        operation
        for operation in (
            _DECRYPT_OPERATION,
            _SIGN_OPERATION,
            _MAC_GENERATION_OPERATION,
        )
        if any(path.get("operation") == operation for path in paths)
    ]


def _operation_text(operations: list[str]) -> str:
    if len(operations) == 1:
        return operations[0]
    return " and ".join(operations)


def _task_role_evidence(paths: Sequence[Mapping[str, object]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "role_policy_complete=true",
                )
            )
            for path in paths
        }
    )


def _operation_path_evidence(paths: Sequence[AwsEcsKmsOperationPath]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"key_address={path['key_address']}",
                    f"key_arn={path['key_arn']}",
                    f"key_id={path.get('key_id') or 'unknown'}",
                    f"key_usage={path.get('key_usage') or 'unknown'}",
                    f"key_spec={path.get('key_spec') or 'unknown'}",
                    f"operation={path['operation']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    f"authorization_state={path['authorization_state']}",
                    f"authorization_bases={','.join(_string_values(path.get('authorization_bases')))}",
                    f"candidate_authorization_bases={','.join(_string_values(path.get('candidate_authorization_bases')))}",
                    f"policy_action_patterns={','.join(_string_values(path.get('policy_action_patterns')))}",
                    f"policy_resources={','.join(_string_values(path.get('policy_resources')))}",
                    f"deny_action_patterns={','.join(_string_values(path.get('deny_action_patterns')) or ['none'])}",
                    f"key_policy_sources={','.join(_string_values(path.get('key_policy_source_addresses')) or ['none'])}",
                    f"identity_policy_sources={','.join(_string_values(path.get('identity_policy_source_addresses')) or ['none'])}",
                    f"grant_sources={','.join(_grant_sources(path))}",
                    f"grant_constraints={';'.join(_structured_values(path.get('grant_constraints')) or ['none'])}",
                    f"constraint_state={path.get('constraint_state') or 'not_configured'}",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _grant_sources(path: AwsEcsKmsOperationPath) -> list[str]:
    sources: set[str] = set()
    for grant in path["kms_grants"]:
        source = grant["source"]
        if source:
            sources.add(source)
    return sorted(sources) or ["none"]


def _structured_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [json.dumps(item, sort_keys=True) for item in value if isinstance(item, Mapping)]


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]
