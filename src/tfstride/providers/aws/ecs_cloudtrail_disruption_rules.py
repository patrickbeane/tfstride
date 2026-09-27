from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.audit_telemetry_disruption_evidence import (
    AwsCloudTrailAuditTelemetryDisruptionOperation,
    AwsEcsCloudTrailAuditTelemetryDisruptionPath,
)
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.resource_decoration.ecs_cloudtrail_audit_telemetry_disruption_paths import (
    current_ecs_cloudtrail_audit_telemetry_disruption_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_AWS_ECS_SERVICE = "aws_ecs_service"
_AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
_AWS_IAM_ROLE = "aws_iam_role"
_AWS_CLOUDTRAIL = "aws_cloudtrail"
_STOP_LOGGING = "cloudtrail:StopLogging"
_DELETE_TRAIL = "cloudtrail:DeleteTrail"
_OPERATIONS = frozenset({_STOP_LOGGING, _DELETE_TRAIL})

# These fields identify the projected authorization relationship. Native ARNs,
# evidence source addresses, lifecycle records, and load balancers are refreshed
# from the current inventory after this relationship is matched.
_AUTHORIZATION_RELATIONSHIP_FIELDS = (
    "workload_address",
    "workload_type",
    "task_definition_address",
    "role_kind",
    "credential_context",
    "role_address",
    "role_provider_config_key",
    "role_account_id",
    "caller_account_id",
    "caller_provider_config_key",
    "trail_address",
    "trail_resource_type",
    "trail_account_id",
    "trail_provider_config_key",
    "same_account",
    "provider_configuration_match",
    "operation",
    "operation_class",
    "internal_operation",
    "management_effect",
    "target_granularity",
    "target_scope",
    "target_model_evidence_addresses",
)


class AwsEcsCloudTrailDisruptionRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_cloudtrail_disruption(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        decoration_context = AwsDecorationContext(
            AwsResourceIndexBuilder().build(list(context.inventory.resources)),
        )
        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            service_facts = aws_facts(service)
            current_paths: list[AwsEcsCloudTrailAuditTelemetryDisruptionPath] = []
            seen_keys: set[tuple[object, ...]] = set()
            for cached_path in service_facts.ecs_cloudtrail_audit_telemetry_disruption_paths:
                current_path = _current_deterministic_path(
                    cached_path,
                    service,
                    context,
                    decoration_context,
                )
                if current_path is None:
                    continue
                key = _authorization_relationship_key(current_path)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                current_paths.append(current_path)

            if not current_paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            current_paths = ingress.current_workload_paths(current_paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not current_paths:
                continue

            task_definition_addresses = path_string_values(
                current_paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(
                current_paths,
                "role_address",
            )
            trail_addresses = path_string_values(
                current_paths,
                "trail_address",
            )
            operations = cast(
                list[AwsCloudTrailAuditTelemetryDisruptionOperation],
                path_string_values(current_paths, "operation"),
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=(3 if _DELETE_TRAIL in operations else 2),
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=2 if len(trail_addresses) > 1 else 1,
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *trail_addresses,
            ]
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=list(dict.fromkeys(affected_resources)),
                    trust_boundary_id=internet_boundary_id(
                        load_balancer_addresses,
                        context,
                    ),
                    rationale=_rationale(
                        service,
                        operations,
                        len(trail_addresses),
                    ),
                    evidence=collect_evidence(
                        evidence_item("network_path", ingress.network_path),
                        *ingress.evidence,
                        evidence_item(
                            "task_definitions",
                            [f"address={address}" for address in task_definition_addresses],
                        ),
                        evidence_item(
                            "task_roles",
                            _task_role_evidence(current_paths),
                        ),
                        evidence_item(
                            "cloudtrail_audit_telemetry_disruption_paths",
                            _disruption_path_evidence(current_paths),
                        ),
                        evidence_item(
                            "cloudtrail_lifecycle_evidence",
                            _lifecycle_evidence(current_paths),
                        ),
                        evidence_item(
                            "cloudtrail_disruption_outcome_evidence",
                            _outcome_evidence(current_paths),
                        ),
                        evidence_item(
                            "cloudtrail_audit_telemetry_disruption_path_uncertainties",
                            _current_path_uncertainties(current_paths),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _assessment_scope(),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _current_deterministic_path(
    cached_path: AwsEcsCloudTrailAuditTelemetryDisruptionPath,
    service: NormalizedResource,
    context: RuleEvaluationContext,
    decoration_context: AwsDecorationContext,
) -> AwsEcsCloudTrailAuditTelemetryDisruptionPath | None:
    if not _cached_path_is_coherent(cached_path):
        return None

    task_definition = _resource_for_path(
        cached_path,
        "task_definition_address",
        _AWS_ECS_TASK_DEFINITION,
        context,
    )
    role = _resource_for_path(
        cached_path,
        "role_address",
        _AWS_IAM_ROLE,
        context,
    )
    trail = _resource_for_path(
        cached_path,
        "trail_address",
        _AWS_CLOUDTRAIL,
        context,
    )
    if task_definition is None or role is None or trail is None:
        return None

    service_facts = aws_facts(service)
    if (
        cached_path.get("workload_address") != service.address
        or cached_path.get("workload_type") != service.resource_type
        or task_definition.address not in service_facts.resolved_task_definition_addresses
        or cached_path.get("task_definition_address") != task_definition.address
        or cached_path.get("role_address") != role.address
        or cached_path.get("trail_address") != trail.address
    ):
        return None

    operation = cached_path.get("operation")
    if operation not in _OPERATIONS:
        return None
    assert operation in {_STOP_LOGGING, _DELETE_TRAIL}
    current_task_path = current_ecs_cloudtrail_audit_telemetry_disruption_path(
        task_definition,
        trail,
        operation,
        decoration_context,
    )
    if current_task_path is None:
        return None

    current_path = current_task_path.copy()
    current_path["workload_address"] = service.address
    current_path["workload_type"] = service.resource_type
    current_path["task_definition_address"] = task_definition.address
    current_path["task_definition_arn"] = task_definition.arn
    current_path["internet_facing_load_balancers"] = service_facts.internet_facing_load_balancer_addresses
    if _authorization_relationship_key(cached_path) != (_authorization_relationship_key(current_path)):
        return None
    return current_path


def _cached_path_is_coherent(
    path: Mapping[str, object],
) -> bool:
    operation = path.get("operation")
    if operation == _STOP_LOGGING:
        variant_matches = bool(
            path.get("operation_class") == "trail_logging_stop"
            and path.get("internal_operation") == "stop_trail_logging"
            and path.get("target_granularity") == "trail_logging_control"
            and path.get("trail_configuration_deletion_authorized") is False
        )
    elif operation == _DELETE_TRAIL:
        variant_matches = bool(
            path.get("operation_class") == "trail_deletion"
            and path.get("internal_operation") == "delete_trail"
            and path.get("target_granularity") == "trail_configuration"
            and path.get("trail_configuration_deletion_authorized") is True
        )
    else:
        return False

    trail_address = path.get("trail_address")
    role_provider = path.get("role_provider_config_key")
    caller_provider = path.get("caller_provider_config_key")
    trail_provider = path.get("trail_provider_config_key")
    role_account = path.get("role_account_id")
    caller_account = path.get("caller_account_id")
    trail_account = path.get("trail_account_id")
    if not (
        variant_matches
        and isinstance(trail_address, str)
        and trail_address
        and isinstance(role_provider, str)
        and role_provider
        and role_provider == caller_provider == trail_provider
        and isinstance(role_account, str)
        and role_account
        and role_account == caller_account == trail_account
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("trail_resource_type") == _AWS_CLOUDTRAIL
        and path.get("same_account") is True
        and path.get("provider_configuration_match") is True
        and path.get("management_effect") == "audit_telemetry_disruption"
        and path.get("target_scope") == "exact_cloudtrail_trail"
        and path.get("target_model_evidence_addresses") == [trail_address]
        and path.get("authorization_state") == "allowed"
        and path.get("evaluation_basis") == "modeled_ecs_task_role_identity_policy"
        and path.get("matched_actions") == [operation]
        and path.get("identity_policy_complete") is True
        and path.get("explicit_deny") is False
        and path.get("conditional_evaluation_required") is False
        and path.get("lifecycle_compatibility_state") == "compatible"
        and _lifecycle_is_active_standard(path.get("lifecycle_evidence"))
        and _authorization_statements_are_coherent(
            path.get("authorization_statements"),
            operation,
        )
        and _outcome_is_conservative(path.get("outcome_evidence"))
    ):
        return False
    return True


def _lifecycle_is_active_standard(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    lifecycle = cast(Mapping[str, object], value)
    return bool(
        lifecycle.get("lifecycle_evidence_scope") == "plan_local_cloudtrail_logging_state"
        and lifecycle.get("logging_state") == "enabled"
        and lifecycle.get("enable_logging") is True
        and lifecycle.get("organization_trail_state") == "disabled"
        and lifecycle.get("is_organization_trail") is False
        and lifecycle.get("lifecycle_compatibility_state") == "compatible"
        and lifecycle.get("uncertainties") == []
    )


def _authorization_statements_are_coherent(
    value: object,
    operation: object,
) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for raw_statement in cast(list[object], value):
        if not isinstance(raw_statement, Mapping):
            return False
        statement = cast(Mapping[str, object], raw_statement)
        if not (
            statement.get("source_kind") == "identity_policy"
            and statement.get("effect") == "allow"
            and statement.get("matched_actions") == [operation]
            and statement.get("resource_scopes") == ["exact_trail"]
            and statement.get("principals") == []
            and statement.get("principal_match") is None
            and statement.get("conditions") == []
            and statement.get("conditional") is False
            and _string_values(statement.get("matching_action_patterns"))
            and _string_values(statement.get("matching_resources"))
        ):
            return False
    return True


def _outcome_is_conservative(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    outcome = cast(Mapping[str, object], value)
    return bool(
        outcome.get("outcome_evidence_scope") == "plan_local_cloudtrail_control_authority"
        and outcome.get("successful_operation_observed") is False
        and outcome.get("historical_log_object_deletion_authorized_by_operation") is False
        and outcome.get("historical_log_object_deletion_observed") is False
        and outcome.get("logging_destination_deletion_authorized_by_operation") is False
        and outcome.get("logging_destination_deletion_observed") is False
        and outcome.get("all_account_audit_trails_evaluated") is False
        and outcome.get("out_of_plan_trails_evaluated") is False
        and outcome.get("telemetry_recovery_state") == "not_established_by_modeled_aws_cloudtrail_evidence"
        and outcome.get("restoration_observed") is False
    )


def _resource_for_path(
    path: Mapping[str, object],
    key: str,
    expected_type: str,
    context: RuleEvaluationContext,
) -> NormalizedResource | None:
    address = path.get(key)
    resource = context.inventory.get_by_address(address) if isinstance(address, str) else None
    if resource is None or resource.provider != "aws" or resource.resource_type != expected_type:
        return None
    return resource


def _authorization_relationship_key(
    path: Mapping[str, object],
) -> tuple[object, ...]:
    return tuple(_freeze(path.get(field)) for field in _AUTHORIZATION_RELATIONSHIP_FIELDS)


def _freeze(value: object) -> object:
    if isinstance(value, list):
        return tuple(_freeze(item) for item in cast(list[object], value))
    if isinstance(value, Mapping):
        return tuple(
            sorted(
                (
                    str(key),
                    _freeze(item),
                )
                for key, item in value.items()
            )
        )
    return value


def _task_role_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path.get('role_address')}",
                    f"reference={path.get('role_reference')}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    f"account_id={path.get('role_account_id')}",
                    f"provider_config={path.get('role_provider_config_key')}",
                    f"caller_identity={path.get('caller_identity_address')}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "authorization_state=allowed",
                )
            )
            for path in paths
        }
    )


def _disruption_path_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"trail_address={path.get('trail_address')}",
                    f"trail_name={path.get('trail_name')}",
                    f"trail_reference={path.get('trail_reference')}",
                    f"trail_arn={path.get('trail_arn') or 'unknown'}",
                    f"operation={path.get('operation')}",
                    f"operation_class={path.get('operation_class')}",
                    f"internal_operation={path.get('internal_operation')}",
                    f"target_granularity={path.get('target_granularity')}",
                    f"target_scope={path.get('target_scope')}",
                    f"task_definition={path.get('task_definition_address')}",
                    f"task_role={path.get('role_address')}",
                    "same_account=true",
                    "provider_configuration_match=true",
                    (
                        "authorization_sources="
                        f"{','.join(_string_values(path.get('authorization_source_addresses'))) or 'none'}"
                    ),
                    (f"matched_actions={','.join(_string_values(path.get('matched_actions')))}"),
                    (f"matching_action_patterns={','.join(_authorization_patterns(path))}"),
                    "authorization_state=allowed",
                    "operation_evaluation=deterministic_allowed",
                )
            )
            for path in paths
        }
    )


def _authorization_patterns(path: Mapping[str, object]) -> list[str]:
    statements = path.get("authorization_statements")
    if not isinstance(statements, list):
        return []
    return sorted(
        {
            pattern
            for raw_statement in cast(list[object], statements)
            if isinstance(raw_statement, Mapping)
            for pattern in _string_values(cast(Mapping[str, object], raw_statement).get("matching_action_patterns"))
        },
        key=str.casefold,
    )


def _lifecycle_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        raw_lifecycle = path.get("lifecycle_evidence")
        if not isinstance(raw_lifecycle, Mapping):
            continue
        lifecycle = cast(Mapping[str, object], raw_lifecycle)
        values.add(
            "; ".join(
                (
                    f"trail_address={path.get('trail_address')}",
                    (f"logging_state={_display(lifecycle.get('logging_state'))}"),
                    (f"enable_logging={_display(lifecycle.get('enable_logging'))}"),
                    (f"organization_trail_state={_display(lifecycle.get('organization_trail_state'))}"),
                    (f"is_organization_trail={_display(lifecycle.get('is_organization_trail'))}"),
                    (f"lifecycle_compatibility_state={_display(lifecycle.get('lifecycle_compatibility_state'))}"),
                    (f"uncertainties={','.join(_string_values(lifecycle.get('uncertainties'))) or 'none'}"),
                )
            )
        )
    return sorted(values)


def _outcome_evidence(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    values: set[str] = set()
    for path in paths:
        raw_outcome = path.get("outcome_evidence")
        if not isinstance(raw_outcome, Mapping):
            continue
        outcome = cast(Mapping[str, object], raw_outcome)
        values.add(
            "; ".join(
                (
                    f"trail_address={path.get('trail_address')}",
                    (f"successful_operation_observed={_display(outcome.get('successful_operation_observed'))}"),
                    (
                        "historical_log_object_deletion_authorized_by_operation="
                        f"{_display(outcome.get('historical_log_object_deletion_authorized_by_operation'))}"
                    ),
                    (
                        "historical_log_object_deletion_observed="
                        f"{_display(outcome.get('historical_log_object_deletion_observed'))}"
                    ),
                    (
                        "logging_destination_deletion_authorized_by_operation="
                        f"{_display(outcome.get('logging_destination_deletion_authorized_by_operation'))}"
                    ),
                    (
                        "logging_destination_deletion_observed="
                        f"{_display(outcome.get('logging_destination_deletion_observed'))}"
                    ),
                    (
                        "all_account_audit_trails_evaluated="
                        f"{_display(outcome.get('all_account_audit_trails_evaluated'))}"
                    ),
                    (f"out_of_plan_trails_evaluated={_display(outcome.get('out_of_plan_trails_evaluated'))}"),
                    (f"telemetry_recovery_state={_display(outcome.get('telemetry_recovery_state'))}"),
                    (f"restoration_observed={_display(outcome.get('restoration_observed'))}"),
                    (f"uncertainties={','.join(_string_values(outcome.get('uncertainties'))) or 'none'}"),
                )
            )
        )
    return sorted(values)


def _current_path_uncertainties(
    paths: Sequence[Mapping[str, object]],
) -> list[str]:
    return sorted({uncertainty for path in paths for uncertainty in _string_values(path.get("posture_uncertainties"))})


def _assessment_scope() -> list[str]:
    return [
        (
            "establishes=deterministic cloudtrail:StopLogging or "
            "cloudtrail:DeleteTrail authority for an ECS task role over exact "
            "modeled active standard CloudTrail trails; this creates a "
            "Repudiation risk because workload compromise could disrupt future "
            "audit telemetry and weaken auditability"
        ),
        (
            "does_not_establish=successful operation, historical CloudTrail "
            "log-object deletion, logging-destination deletion, disruption of "
            "all account trails, authority over out-of-plan trails, telemetry "
            "recovery, or restoration"
        ),
    ]


def _rationale(
    service: NormalizedResource,
    operations: Sequence[AwsCloudTrailAuditTelemetryDisruptionOperation],
    trail_count: int,
) -> str:
    trail_text = "trail" if trail_count == 1 else "trails"
    return (
        f"{service.display_name} is reachable through an internet-facing load "
        "balancer and its ECS task role has deterministic CloudTrail control "
        f"authority to {_operation_text(operations)} across {trail_count} exact "
        f"modeled active standard CloudTrail {trail_text}. A compromise of the "
        "public workload could disrupt future audit-event collection for those "
        "trails. This authority does not establish a successful operation, "
        "deletion of historical CloudTrail log objects or logging destinations, "
        "impact to every account trail or out-of-plan trails, telemetry recovery, "
        "or restoration."
    )


def _operation_text(
    operations: Sequence[AwsCloudTrailAuditTelemetryDisruptionOperation],
) -> str:
    operation_set = set(operations)
    if operation_set == {_STOP_LOGGING}:
        return "stop logging"
    if operation_set == {_DELETE_TRAIL}:
        return "delete trail configurations"
    return "stop logging or delete trail configurations"


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str) and item]


def _display(value: object) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)
