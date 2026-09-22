from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal, cast

from tfstride.models import (
    IAMPolicyStatement,
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.aws.audit_telemetry_disruption_evidence import (
    AwsCloudTrailActiveStandardTrailLifecycleEvidence,
    AwsCloudTrailAuditTelemetryDisruptionOperation,
    AwsCloudTrailAuditTelemetryPolicyStatementEvidence,
    AwsCloudTrailAuditTelemetryPolicyStatementEvidenceCommon,
    AwsCloudTrailDeleteTrailPolicyStatementEvidence,
    AwsCloudTrailStopLoggingPolicyStatementEvidence,
    AwsEcsCloudTrailAuditTelemetryDisruptionPath,
    AwsEcsCloudTrailAuditTelemetryDisruptionPathCommon,
    AwsEcsCloudTrailDeleteTrailPath,
    AwsEcsCloudTrailStopLoggingPath,
)
from tfstride.providers.aws.iam_permissions_boundaries import permissions_boundary_uncertainties
from tfstride.providers.aws.reference_resolution import (
    assess_symbolic_reference,
    symbolic_reference_target,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    dedupe,
)
from tfstride.resource_helpers import parse_aws_account_id

_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_ECS_SERVICE = "aws_ecs_service"
_IAM_ROLE = "aws_iam_role"
_CLOUDTRAIL = "aws_cloudtrail"
_CALLER_IDENTITY = "aws_caller_identity"
_STOP_LOGGING = "cloudtrail:StopLogging"
_DELETE_TRAIL = "cloudtrail:DeleteTrail"
_COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class _OperationDefinition:
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation
    operation_class: Literal["trail_logging_stop", "trail_deletion"]
    internal_operation: Literal["stop_trail_logging", "delete_trail"]
    target_granularity: Literal["trail_logging_control", "trail_configuration"]
    configuration_deletion: bool


_OPERATION_DEFINITIONS = (
    _OperationDefinition(
        _STOP_LOGGING,
        "trail_logging_stop",
        "stop_trail_logging",
        "trail_logging_control",
        False,
    ),
    _OperationDefinition(
        _DELETE_TRAIL,
        "trail_deletion",
        "delete_trail",
        "trail_configuration",
        True,
    ),
)


@dataclass(frozen=True, slots=True)
class _StatementMatch:
    statement: IAMPolicyStatement
    source_address: str
    matching_action_patterns: tuple[str, ...]
    matching_resource: str
    effect: Literal["allow", "deny"]

    @property
    def conditional(self) -> bool:
        return bool(self.statement.conditions)


@dataclass(frozen=True, slots=True)
class _PolicyMatches:
    matches: tuple[_StatementMatch, ...]
    unresolved_allow: bool
    unresolved_deny: bool


@dataclass(frozen=True, slots=True)
class _AuthorizationEvaluation:
    allows: tuple[_StatementMatch, ...] | None
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CallerIdentity:
    resource: NormalizedResource
    account_id: str
    partition: str


class ModelEcsCloudTrailAuditTelemetryDisruptionPathsStage:
    """Model effective ECS task-role authority to disrupt exact CloudTrail trails."""

    name = "model_ecs_cloudtrail_audit_telemetry_disruption_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        trails = tuple(resource for resource in resources if resource.resource_type == _CLOUDTRAIL)
        for task_definition in resources:
            if task_definition.resource_type != _ECS_TASK_DEFINITION:
                continue
            paths, uncertainties = _task_definition_paths(
                task_definition,
                trails,
                context,
                resources=resources,
            )
            facts = aws_facts(task_definition)
            facts.set_ecs_cloudtrail_audit_telemetry_disruption_paths(paths)
            facts.extend_ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties(
                uncertainties,
            )


class ProjectEcsCloudTrailAuditTelemetryDisruptionPathsOntoServicesStage:
    """Project task-definition CloudTrail paths onto current ECS services."""

    name = "project_ecs_cloudtrail_audit_telemetry_disruption_paths_onto_services"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AwsDecorationContext,
    ) -> None:
        for service in resources:
            if service.resource_type != _ECS_SERVICE:
                continue
            service_facts = aws_facts(service)
            paths: list[AwsEcsCloudTrailAuditTelemetryDisruptionPath] = []
            uncertainties = [
                f"{service.address}: task definition reference {reference} is "
                "unresolved for CloudTrail disruption path projection"
                for reference in service_facts.unresolved_task_definition_references
            ]
            for task_definition_address in service_facts.resolved_task_definition_addresses:
                task_definition = context.index.ecs_task_definitions.get(
                    task_definition_address,
                    source=service,
                )
                if task_definition is None:
                    uncertainties.append(
                        f"{service.address}: resolved task definition "
                        f"{task_definition_address} is unavailable for "
                        "CloudTrail disruption path projection"
                    )
                    continue
                task_facts = aws_facts(task_definition)
                uncertainties.extend(
                    task_facts.ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties,
                )
                paths.extend(
                    _service_path(service, task_definition, path)
                    for path in (task_facts.ecs_cloudtrail_audit_telemetry_disruption_paths)
                )
            paths.sort(key=_path_sort_key)
            service_facts.set_ecs_cloudtrail_audit_telemetry_disruption_paths(
                paths,
            )
            service_facts.extend_ecs_cloudtrail_audit_telemetry_disruption_path_uncertainties(
                dedupe(uncertainties),
            )


def _task_definition_paths(
    task_definition: NormalizedResource,
    trails: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    resources: Sequence[NormalizedResource],
) -> tuple[list[AwsEcsCloudTrailAuditTelemetryDisruptionPath], list[str]]:
    task_facts = aws_facts(task_definition)
    task_role_reference = task_facts.task_role_arn
    if task_role_reference is None:
        return [], _task_role_resolution_uncertainties(task_definition)

    task_role = context.index.role_index.get(task_role_reference, source=task_definition)
    if task_role is None or task_role.resource_type != _IAM_ROLE:
        if _task_role_configuration_reference_observed(task_definition):
            return (
                [],
                [
                    f"{task_definition.address}: task role relationship is "
                    "ambiguous or unresolved for CloudTrail disruption paths"
                ],
            )
        return (
            [],
            [
                f"{task_definition.address}: ECS task role "
                f"{task_role_reference} is not modeled for CloudTrail "
                "disruption paths"
            ],
        )
    if not _task_role_relationship_is_exact(
        task_definition,
        task_role,
        context,
    ):
        return [], []

    provider_config_key = task_role.provider_config_key
    if provider_config_key is None:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role.address} "
                "has no exact AWS provider-configuration evidence"
            ],
        )

    role_reference = _task_role_evidence_reference(
        task_definition,
        task_role,
    )
    if role_reference is None:
        return [], []

    caller, caller_uncertainties = _caller_identity(
        resources,
        provider_config_key,
    )
    if caller is None:
        return (
            [],
            [f"{task_definition.address}: {uncertainty}" for uncertainty in caller_uncertainties],
        )

    role_account_id = _role_account_id(task_role, caller)
    if role_account_id is None:
        return (
            [],
            [
                f"{task_definition.address}: ECS task role {task_role.address} "
                "account or partition does not match the resolved caller "
                "identity"
            ],
        )

    boundary_uncertainties = permissions_boundary_uncertainties(task_role, authority="CloudTrail disruption")
    if boundary_uncertainties:
        return (
            [],
            [f"{task_definition.address}: {uncertainty}" for uncertainty in boundary_uncertainties],
        )

    identity_policy_complete = _identity_policy_complete(task_role)
    uncertainties: list[str] = []
    if not identity_policy_complete and _role_has_disruption_operation(task_role):
        uncertainties.append(
            f"{task_definition.address}: {task_role.address} CloudTrail "
            "disruption authorization is unresolved because identity-policy "
            "evidence is incomplete"
        )
        uncertainties.extend(
            f"{task_definition.address}: {task_role.address}: {uncertainty}"
            for uncertainty in (aws_facts(task_role).iam_policy_posture_uncertainties)
        )

    paths: list[AwsEcsCloudTrailAuditTelemetryDisruptionPath] = []
    identity_sources = _identity_policy_resources(task_role, context)
    for trail in trails:
        if trail.provider_config_key != provider_config_key:
            if trail.provider_config_key is None and _role_has_disruption_operation(task_role):
                uncertainties.append(
                    f"{task_definition.address}: {trail.address} has no exact AWS provider-configuration evidence"
                )
            continue

        trail_name = _trail_name(trail)
        trail_arn = trail.arn
        if trail_name is None:
            if _role_has_disruption_operation(task_role):
                uncertainties.append(
                    f"{task_definition.address}: {trail.address} has "
                    "unresolved or inconsistent provider-native CloudTrail "
                    "identity"
                )
            continue
        if trail_arn is not None:
            trail_identity = _cloudtrail_arn_parts(trail_arn)
            if trail_identity is None:
                if _role_has_disruption_operation(task_role):
                    uncertainties.append(f"{task_definition.address}: {trail.address} has an unresolved CloudTrail ARN")
                continue
            partition, account_id, _arn_name = trail_identity
            if partition != caller.partition or account_id != caller.account_id:
                continue

        for definition in _OPERATION_DEFINITIONS:
            matches = _identity_policy_matches(
                task_role,
                trail,
                definition.operation,
                identity_sources,
                context,
            )
            if not (matches.matches or matches.unresolved_allow or matches.unresolved_deny):
                continue

            evaluation = _evaluate_authorization(
                trail,
                task_role,
                definition.operation,
                matches,
                identity_policy_complete=identity_policy_complete,
            )
            uncertainties.extend(
                f"{task_definition.address}: {uncertainty}" for uncertainty in evaluation.uncertainties
            )
            if evaluation.allows is None:
                continue

            lifecycle, lifecycle_uncertainties = _active_lifecycle(trail)
            uncertainties.extend(
                f"{task_definition.address}: {trail.address}: {uncertainty}" for uncertainty in lifecycle_uncertainties
            )
            if lifecycle is None:
                continue

            paths.append(
                _path(
                    task_definition,
                    task_role,
                    role_reference,
                    role_account_id,
                    caller,
                    trail,
                    trail_name,
                    trail_arn,
                    definition,
                    evaluation.allows,
                    lifecycle,
                )
            )

    paths.sort(key=_path_sort_key)
    return paths, dedupe(uncertainties)


def _evaluate_authorization(
    trail: NormalizedResource,
    role: NormalizedResource,
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation,
    matches: _PolicyMatches,
    *,
    identity_policy_complete: bool,
) -> _AuthorizationEvaluation:
    denies = [match for match in matches.matches if match.effect == "deny"]
    if any(not match.conditional for match in denies):
        return _AuthorizationEvaluation(None, ())
    if any(match.conditional for match in denies):
        return _AuthorizationEvaluation(
            None,
            (f"{trail.address}: {role.address} {operation} has condition-dependent explicit-deny evidence",),
        )
    if matches.unresolved_deny:
        return _AuthorizationEvaluation(
            None,
            (f"{trail.address}: {role.address} {operation} has ambiguous or unresolved explicit-deny scope",),
        )

    allows = tuple(match for match in matches.matches if match.effect == "allow" and not match.conditional)
    candidate_observed = bool(
        allows or matches.unresolved_allow or any(match.effect == "allow" for match in matches.matches)
    )
    if not candidate_observed:
        return _AuthorizationEvaluation(None, ())

    if not identity_policy_complete:
        return _AuthorizationEvaluation(
            None,
            (
                f"{trail.address}: {role.address} {operation} authorization "
                "is unresolved because identity-policy evidence is incomplete",
            ),
        )
    if allows:
        return _AuthorizationEvaluation(allows, ())
    if matches.unresolved_allow:
        return _AuthorizationEvaluation(
            None,
            (
                f"{trail.address}: {role.address} {operation} allow evidence "
                "does not identify one exact CloudTrail trail",
            ),
        )
    return _AuthorizationEvaluation(
        None,
        (f"{trail.address}: {role.address} {operation} authorization depends on runtime policy conditions",),
    )


def _identity_policy_matches(
    role: NormalizedResource,
    trail: NormalizedResource,
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation,
    sources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
) -> _PolicyMatches:
    matches: list[_StatementMatch] = []
    unresolved_allow = False
    unresolved_deny = False
    for statement in role.policy_statements:
        effect = _normalized_effect(statement)
        if effect is None:
            continue
        action_patterns = _matching_action_patterns(
            statement.actions,
            operation,
        )
        if not action_patterns:
            continue
        for resource in statement.resources:
            applicability = _resource_targets_trail(
                resource,
                trail,
                sources,
                context,
                exact_allow_required=effect == "allow",
            )
            if applicability is True:
                matches.append(
                    _StatementMatch(
                        statement,
                        role.address,
                        action_patterns,
                        resource,
                        effect,
                    )
                )
            elif applicability is None:
                if effect == "allow":
                    unresolved_allow = True
                else:
                    unresolved_deny = True
    return _PolicyMatches(
        tuple(matches),
        unresolved_allow,
        unresolved_deny,
    )


def _resource_targets_trail(
    resource: str,
    trail: NormalizedResource,
    sources: Sequence[NormalizedResource],
    context: AwsDecorationContext,
    *,
    exact_allow_required: bool,
) -> bool | None:
    trail_arn = trail.arn
    normalized = _unwrap_reference(resource)
    if trail_arn is not None and normalized == trail_arn:
        return True
    if normalized.startswith("arn:"):
        if trail_arn is None:
            return None if _cloudtrail_arn_or_pattern(normalized) else False
        if _has_wildcard(normalized):
            if not fnmatchcase(trail_arn, normalized):
                return False
            return None if exact_allow_required else True
        return False

    candidates: set[str] = set()
    uncertain = False
    for source in sources:
        assessment = assess_symbolic_reference(
            source,
            context.index,
            normalized,
            expected_resource_types={_CLOUDTRAIL},
            expected_reference_suffixes={".arn"},
        )
        if assessment.state == "resolved" and assessment.target is not None:
            candidates.add(assessment.target.address)
        elif assessment.state == "uncertain":
            uncertain = True
    if uncertain or len(candidates) > 1:
        return None
    if candidates:
        return candidates == {trail.address}

    if normalized == "*":
        return None if exact_allow_required else True
    if _has_wildcard(normalized):
        return None
    return False


def _active_lifecycle(
    trail: NormalizedResource,
) -> tuple[
    AwsCloudTrailActiveStandardTrailLifecycleEvidence | None,
    list[str],
]:
    facts = aws_facts(trail)
    logging_state = facts.cloudtrail_enable_logging_state
    organization_state = facts.cloudtrail_organization_trail_state

    if organization_state == STATE_ENABLED:
        return (
            None,
            ["organization trails are outside deterministic workload CloudTrail disruption modeling"],
        )
    if organization_state != STATE_DISABLED:
        return (
            None,
            ["organization-trail state is unknown after planning"],
        )
    if logging_state == STATE_DISABLED:
        return None, []
    if logging_state != STATE_ENABLED:
        return (
            None,
            ["trail logging state is unknown after planning"],
        )

    return (
        AwsCloudTrailActiveStandardTrailLifecycleEvidence(
            lifecycle_evidence_scope="plan_local_cloudtrail_logging_state",
            logging_state="enabled",
            enable_logging=True,
            organization_trail_state="disabled",
            is_organization_trail=False,
            lifecycle_compatibility_state="compatible",
            uncertainties=[],
        ),
        [],
    )


def _path(
    task_definition: NormalizedResource,
    role: NormalizedResource,
    role_reference: str,
    role_account_id: str,
    caller: _CallerIdentity,
    trail: NormalizedResource,
    trail_name: str,
    trail_arn: str | None,
    definition: _OperationDefinition,
    allows: Sequence[_StatementMatch],
    lifecycle: AwsCloudTrailActiveStandardTrailLifecycleEvidence,
) -> AwsEcsCloudTrailAuditTelemetryDisruptionPath:
    statement_records = [_statement_record(match, definition.operation) for match in allows]
    matching_resources = sorted(
        {match.matching_resource for match in allows},
        key=str.casefold,
    )
    trail_reference = trail_arn if trail_arn is not None and trail_arn in matching_resources else matching_resources[0]
    common: AwsEcsCloudTrailAuditTelemetryDisruptionPathCommon = {
        "workload_address": task_definition.address,
        "workload_type": task_definition.resource_type,
        "task_definition_address": task_definition.address,
        "task_definition_arn": task_definition.arn,
        "internet_facing_load_balancers": [],
        "role_kind": "ecs_task_role",
        "credential_context": "workload_runtime",
        "role_address": role.address,
        "role_reference": role_reference,
        "role_arn": role.arn,
        "role_account_id": role_account_id,
        "role_provider_config_key": cast(str, role.provider_config_key),
        "caller_identity_address": caller.resource.address,
        "caller_account_id": caller.account_id,
        "caller_provider_config_key": cast(
            str,
            caller.resource.provider_config_key,
        ),
        "trail_address": trail.address,
        "trail_resource_type": trail.resource_type,
        "trail_name": trail_name,
        "trail_reference": trail_reference,
        "trail_arn": trail_arn,
        "trail_account_id": caller.account_id,
        "trail_provider_config_key": cast(
            str,
            trail.provider_config_key,
        ),
        "same_account": True,
        "provider_configuration_match": True,
        "management_effect": "audit_telemetry_disruption",
        "target_scope": "exact_cloudtrail_trail",
        "target_model_evidence_addresses": [trail.address],
        "authorization_source_addresses": (_identity_policy_source_addresses(role)),
        "authorization_state": "allowed",
        "evaluation_basis": "modeled_ecs_task_role_identity_policy",
        "identity_policy_complete": True,
        "identity_policy_source_addresses": (_identity_policy_source_addresses(role)),
        "explicit_deny": False,
        "conditional_evaluation_required": False,
        "lifecycle_compatibility_state": "compatible",
        "lifecycle_evidence": lifecycle,
        "outcome_evidence": {
            "outcome_evidence_scope": ("plan_local_cloudtrail_control_authority"),
            "successful_operation_observed": False,
            "historical_log_object_deletion_authorized_by_operation": False,
            "historical_log_object_deletion_observed": False,
            "logging_destination_deletion_authorized_by_operation": False,
            "logging_destination_deletion_observed": False,
            "all_account_audit_trails_evaluated": False,
            "out_of_plan_trails_evaluated": False,
            "telemetry_recovery_state": ("not_established_by_modeled_aws_cloudtrail_evidence"),
            "restoration_observed": False,
            "uncertainties": [],
        },
        "posture_uncertainties": [],
    }
    if definition.operation == _STOP_LOGGING:
        stop_path: AwsEcsCloudTrailStopLoggingPath = {
            **common,
            "operation": "cloudtrail:StopLogging",
            "operation_class": "trail_logging_stop",
            "internal_operation": "stop_trail_logging",
            "target_granularity": "trail_logging_control",
            "matched_actions": ["cloudtrail:StopLogging"],
            "authorization_statements": cast(
                list[AwsCloudTrailStopLoggingPolicyStatementEvidence],
                statement_records,
            ),
            "trail_configuration_deletion_authorized": False,
        }
        return stop_path

    delete_path: AwsEcsCloudTrailDeleteTrailPath = {
        **common,
        "operation": "cloudtrail:DeleteTrail",
        "operation_class": "trail_deletion",
        "internal_operation": "delete_trail",
        "target_granularity": "trail_configuration",
        "matched_actions": ["cloudtrail:DeleteTrail"],
        "authorization_statements": cast(
            list[AwsCloudTrailDeleteTrailPolicyStatementEvidence],
            statement_records,
        ),
        "trail_configuration_deletion_authorized": True,
    }
    return delete_path


def _statement_record(
    match: _StatementMatch,
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation,
) -> AwsCloudTrailAuditTelemetryPolicyStatementEvidence:
    common: AwsCloudTrailAuditTelemetryPolicyStatementEvidenceCommon = {
        "source_address": match.source_address,
        "source_kind": "identity_policy",
        "effect": "allow",
        "actions": list(match.statement.actions),
        "matching_action_patterns": list(match.matching_action_patterns),
        "resources": list(match.statement.resources),
        "matching_resources": [match.matching_resource],
        "resource_scopes": ["exact_trail"],
        "principals": [],
        "principal_match": None,
        "conditions": [],
        "conditional": False,
    }
    if operation == _STOP_LOGGING:
        stop_record: AwsCloudTrailStopLoggingPolicyStatementEvidence = {
            **common,
            "matched_actions": ["cloudtrail:StopLogging"],
        }
        return stop_record
    delete_record: AwsCloudTrailDeleteTrailPolicyStatementEvidence = {
        **common,
        "matched_actions": ["cloudtrail:DeleteTrail"],
    }
    return delete_record


def current_ecs_cloudtrail_audit_telemetry_disruption_path(
    task_definition: NormalizedResource,
    trail: NormalizedResource,
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation,
    context: AwsDecorationContext,
) -> AwsEcsCloudTrailAuditTelemetryDisruptionPath | None:
    """Recompute the current deterministic path for one task and trail."""

    if trail.resource_type != _CLOUDTRAIL:
        return None

    resources = tuple(context.index.resources_by_address.values())
    paths, _uncertainties = _task_definition_paths(
        task_definition,
        (trail,),
        context,
        resources=resources,
    )
    return next(
        (path for path in paths if path["trail_address"] == trail.address and path["operation"] == operation),
        None,
    )


def _caller_identity(
    resources: Sequence[NormalizedResource],
    provider_config_key: str,
) -> tuple[_CallerIdentity | None, list[str]]:
    candidates = sorted(
        (
            resource
            for resource in resources
            if resource.resource_type == _CALLER_IDENTITY and resource.provider_config_key == provider_config_key
        ),
        key=lambda resource: resource.address,
    )
    if not candidates:
        return (
            None,
            [f"resolved aws_caller_identity evidence is absent for AWS provider configuration {provider_config_key}"],
        )

    account_ids: set[str] = set()
    partitions: set[str] = set()
    for candidate in candidates:
        facts = aws_facts(candidate)
        if facts.caller_identity_account_id_state != "resolved" or facts.caller_identity_account_id is None:
            return (
                None,
                [
                    "caller-account ownership is ambiguous or unresolved for "
                    f"AWS provider configuration {provider_config_key}"
                ],
            )
        partition = _arn_partition(candidate.arn)
        if partition is None:
            return (
                None,
                [f"caller partition is unresolved for AWS provider configuration {provider_config_key}"],
            )
        account_ids.add(facts.caller_identity_account_id)
        partitions.add(partition)

    if len(account_ids) != 1 or len(partitions) != 1:
        return (
            None,
            [f"caller-account ownership is ambiguous for AWS provider configuration {provider_config_key}"],
        )
    return (
        _CallerIdentity(
            candidates[0],
            next(iter(account_ids)),
            next(iter(partitions)),
        ),
        [],
    )


def _role_account_id(
    role: NormalizedResource,
    caller: _CallerIdentity,
) -> str | None:
    if role.provider_config_key != caller.resource.provider_config_key:
        return None
    if role.arn is None:
        return caller.account_id
    if not _is_exact_iam_role_arn(role.arn):
        return None
    if parse_aws_account_id(role.arn) != caller.account_id or _arn_partition(role.arn) != caller.partition:
        return None
    return caller.account_id


def _trail_name(trail: NormalizedResource) -> str | None:
    configured = aws_facts(trail).name
    arn_parts = _cloudtrail_arn_parts(trail.arn) if trail.arn is not None else None
    arn_name = arn_parts[2] if arn_parts is not None else None
    if configured is not None and arn_name is not None and configured != arn_name:
        return None
    return configured or arn_name


def _cloudtrail_arn_parts(
    value: str,
) -> tuple[str, str, str] | None:
    if _has_wildcard(value):
        return None
    parts = value.split(":", 5)
    if not (
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "cloudtrail"
        and parts[3]
        and parse_aws_account_id(value) is not None
        and parts[5].startswith("trail/")
        and len(parts[5]) > len("trail/")
    ):
        return None
    name = parts[5][len("trail/") :]
    if "/" in name:
        return None
    account_id = parse_aws_account_id(value)
    assert account_id is not None
    return parts[1], account_id, name


def _cloudtrail_arn_or_pattern(value: str) -> bool:
    parts = value.split(":", 5)
    return bool(len(parts) == 6 and parts[0] == "arn" and parts[1] and parts[2].casefold() == "cloudtrail" and parts[5])


def _identity_policy_complete(role: NormalizedResource) -> bool:
    facts = aws_facts(role)
    return bool(
        facts.iam_policy_completeness_state == _COMPLETE
        and not facts.unresolved_attached_policy_arns
        and all(
            statement.effect.strip().casefold() in {"allow", "deny"}
            and bool(statement.actions)
            and bool(statement.resources)
            and not statement.principal_entries
            for statement in role.policy_statements
        )
    )


def _identity_policy_resources(
    role: NormalizedResource,
    context: AwsDecorationContext,
) -> list[NormalizedResource]:
    resources = [role]
    facts = aws_facts(role)
    for address in (
        *facts.inline_policy_resource_addresses,
        *facts.attached_policy_addresses,
    ):
        source = context.index.resources_by_address.get(address)
        if source is not None:
            resources.append(source)
    return resources


def _identity_policy_source_addresses(
    role: NormalizedResource,
) -> list[str]:
    facts = aws_facts(role)
    return dedupe(
        [
            role.address,
            *facts.inline_policy_resource_addresses,
            *facts.attached_policy_addresses,
        ]
    )


def _task_role_evidence_reference(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
) -> str | None:
    current = aws_facts(task_definition).task_role_arn
    if task_role.arn is not None and current == task_role.arn:
        return current
    for resolution in task_definition.reference_resolutions:
        if (
            resolution.path != ("task_role_arn",)
            or resolution.state != TerraformReferenceResolutionState.SYMBOLIC
            or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
            or len(resolution.targets) != 1
        ):
            continue
        target = resolution.targets[0]
        if target.address == task_role.address and target.reference.endswith(".arn"):
            return target.reference
    return None


def _task_role_relationship_is_exact(
    task_definition: NormalizedResource,
    task_role: NormalizedResource,
    context: AwsDecorationContext,
) -> bool:
    reference = aws_facts(task_definition).task_role_arn
    if reference is None:
        return False
    if task_role.arn is not None and reference == task_role.arn:
        return True
    symbolic = symbolic_reference_target(
        task_definition,
        context.index,
        "task_role_arn",
        expected_resource_types={_IAM_ROLE},
        expected_reference_suffixes={".arn"},
    )
    return bool(symbolic is not None and symbolic.address == task_role.address and reference == task_role.address)


def _task_role_configuration_reference_observed(
    task_definition: NormalizedResource,
) -> bool:
    return any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        for resolution in task_definition.reference_resolutions
    )


def _task_role_resolution_uncertainties(
    task_definition: NormalizedResource,
) -> list[str]:
    uncertainties = [
        f"{task_definition.address}: task role reference {reference} is unresolved for CloudTrail disruption paths"
        for reference in aws_facts(task_definition).unresolved_task_role_arns
    ]
    if any(
        resolution.path == ("task_role_arn",)
        and resolution.provenance == TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        and resolution.state
        in {
            TerraformReferenceResolutionState.AMBIGUOUS,
            TerraformReferenceResolutionState.UNRESOLVED,
            TerraformReferenceResolutionState.UNSUPPORTED,
        }
        for resolution in task_definition.reference_resolutions
    ):
        uncertainties.append(
            f"{task_definition.address}: task role configuration reference is "
            "ambiguous or unresolved for CloudTrail disruption paths"
        )
    return dedupe(uncertainties)


def _matching_action_patterns(
    patterns: Sequence[str],
    operation: AwsCloudTrailAuditTelemetryDisruptionOperation,
) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if fnmatchcase(operation.casefold(), pattern.casefold()))


def _role_has_disruption_operation(role: NormalizedResource) -> bool:
    return any(
        _matching_action_patterns(statement.actions, definition.operation)
        for statement in role.policy_statements
        for definition in _OPERATION_DEFINITIONS
    )


def _normalized_effect(
    statement: IAMPolicyStatement,
) -> Literal["allow", "deny"] | None:
    effect = statement.effect.strip().casefold()
    if effect == "allow":
        return "allow"
    if effect == "deny":
        return "deny"
    return None


def _is_exact_iam_role_arn(value: str) -> bool:
    if _has_wildcard(value):
        return False
    parts = value.split(":", 5)
    return bool(
        len(parts) == 6
        and parts[0] == "arn"
        and parts[1]
        and parts[2] == "iam"
        and not parts[3]
        and parse_aws_account_id(value) is not None
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
    )


def _unwrap_reference(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        return normalized[2:-1].strip()
    return normalized


def _arn_partition(value: str | None) -> str | None:
    if value is None:
        return None
    parts = value.split(":", 2)
    return parts[1] if len(parts) == 3 and parts[0] == "arn" else None


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _service_path(
    service: NormalizedResource,
    task_definition: NormalizedResource,
    path: AwsEcsCloudTrailAuditTelemetryDisruptionPath,
) -> AwsEcsCloudTrailAuditTelemetryDisruptionPath:
    projected = path.copy()
    projected["workload_address"] = service.address
    projected["workload_type"] = service.resource_type
    projected["task_definition_address"] = task_definition.address
    projected["task_definition_arn"] = task_definition.arn
    projected["internet_facing_load_balancers"] = aws_facts(service).internet_facing_load_balancer_addresses
    return projected


def _path_sort_key(
    path: AwsEcsCloudTrailAuditTelemetryDisruptionPath,
) -> tuple[str, str, str]:
    return (
        path["trail_address"],
        path["operation"],
        path["role_address"],
    )
