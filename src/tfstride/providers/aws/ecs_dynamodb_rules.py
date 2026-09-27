from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource, SeverityReasoning
from tfstride.providers.aws.ecs_path_rule_helpers import (
    internet_boundary_id,
    path_string_values,
    verified_public_service_ingress,
)
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_access_paths import (
    DYNAMODB_ACCESS_CLASSES_BY_ACTION,
)
from tfstride.providers.aws.resource_facts import aws_facts

_AWS_DYNAMODB_TABLE = "aws_dynamodb_table"
_AWS_ECS_SERVICE = "aws_ecs_service"
_MUTATION_CLASS_ORDER = (
    "entity_write",
    "destructive_administration",
    "configuration_administration",
)
_MUTATION_ACCESS_CLASSES = frozenset(_MUTATION_CLASS_ORDER)
_DISCLOSURE_CLASS_ORDER = ("read", "return_value_read", "bulk_export")
_DISCLOSURE_ACCESS_CLASSES = frozenset(_DISCLOSURE_CLASS_ORDER)
_TABLE_SCAN_ACTIONS = frozenset({"dynamodb:scan", "dynamodb:partiqlselect"})
_TOPOLOGY_DELETION_ACTIONS = frozenset({"dynamodb:deletetable"})
_CLASS_PRIVILEGE_BREADTH = {
    "entity_write": 1,
    "configuration_administration": 2,
    "destructive_administration": 3,
}
_CLASS_CAPABILITIES = {
    "entity_write": "create or update items in the modeled table",
    "destructive_administration": ("delete complete DynamoDB tables or replicas and their stored data"),
    "configuration_administration": (
        "change DynamoDB table configuration or controls without directly modifying item contents"
    ),
}


class AwsEcsDynamoDbAccessRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_service_mutation_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            mutation_paths = [
                path
                for path in aws_facts(service).ecs_dynamodb_access_paths
                if _is_deterministic_mutation_path(
                    path,
                    service.address,
                    context,
                )
            ]
            if not mutation_paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            mutation_paths = ingress.current_workload_paths(mutation_paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not mutation_paths:
                continue

            task_definition_addresses = path_string_values(
                mutation_paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(mutation_paths, "role_address")
            table_addresses = path_string_values(
                mutation_paths,
                "dynamodb_table_address",
            )
            mutation_classes = _mutation_classes(mutation_paths)
            severity_reasoning = _mutation_severity(
                mutation_classes,
                table_count=len(table_addresses),
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *table_addresses,
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
                    rationale=(
                        f"{service.display_name} is reachable through an "
                        "internet-facing load balancer and its ECS task role has "
                        "an unconditional identity-policy allow for DynamoDB mutation "
                        f"on {len(table_addresses)} exact modeled table(s). A compromise "
                        "of the public workload could attempt to "
                        f"{_capability_summary(mutation_classes)}."
                        f"{_impact_context(mutation_classes)} This establishes a modeled "
                        "identity-policy path, not guaranteed effective authorization "
                        "through every AWS policy layer. The DynamoDB table itself is "
                        "not public."
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
                            _task_role_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "dynamodb_mutation_paths",
                            _mutation_path_evidence(mutation_paths),
                        ),
                        evidence_item(
                            "impact_profile",
                            _impact_profile(mutation_classes),
                        ),
                        evidence_item(
                            "assessment_scope",
                            [
                                ("establishes=unconditional identity-policy allow for exact DynamoDB mutation actions"),
                                (
                                    "does_not_establish=effective authorization after "
                                    "DynamoDB resource policies, permissions boundaries, "
                                    "service control policies, or deletion protection"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_service_read_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(_AWS_ECS_SERVICE):
            read_paths = [
                path
                for path in aws_facts(service).ecs_dynamodb_access_paths
                if _is_deterministic_read_path(
                    path,
                    service.address,
                    context,
                )
            ]
            if not read_paths:
                continue

            ingress = verified_public_service_ingress(service, context)
            read_paths = ingress.current_workload_paths(read_paths)
            load_balancer_addresses = ingress.load_balancer_addresses
            if not load_balancer_addresses or not read_paths:
                continue

            task_definition_addresses = path_string_values(
                read_paths,
                "task_definition_address",
            )
            role_addresses = path_string_values(read_paths, "role_address")
            table_addresses = path_string_values(
                read_paths,
                "dynamodb_table_address",
            )
            target_arns = path_string_values(
                read_paths,
                "dynamodb_target_arn",
            )
            disclosure_classes = _disclosure_classes(read_paths)
            broad_scope_reasons = _broad_read_scope_reasons(
                read_paths,
                target_count=len(target_arns),
            )
            severity_reasoning = _read_severity(
                disclosure_classes,
                broad_scope=bool(broad_scope_reasons),
            )
            affected_resources = [
                *ingress.resource_addresses,
                service.address,
                *task_definition_addresses,
                *role_addresses,
                *table_addresses,
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
                    rationale=(
                        f"{service.display_name} is reachable through an "
                        "internet-facing load balancer and its ECS task role has "
                        "an unconditional identity-policy allow for DynamoDB "
                        f"read-capable actions on {len(target_arns)} exact modeled "
                        "table or index target(s). A compromise of the public "
                        f"workload could attempt to {_disclosure_capability_summary(disclosure_classes)}. "
                        f"{_read_scope_context(read_paths, broad_scope_reasons)} "
                        "This establishes a modeled identity-policy allow, not "
                        "guaranteed effective authorization after DynamoDB resource "
                        "policies, permissions boundaries, service control policies, "
                        "or VPC endpoint policies. The DynamoDB resource itself is "
                        "not public."
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
                            _task_role_evidence(read_paths),
                        ),
                        evidence_item(
                            "dynamodb_read_paths",
                            _read_path_evidence(read_paths),
                        ),
                        evidence_item(
                            "scope_profile",
                            _read_scope_profile(
                                target_count=len(target_arns),
                                table_count=len(table_addresses),
                                broad_scope_reasons=broad_scope_reasons,
                            ),
                        ),
                        evidence_item(
                            "assessment_scope",
                            _read_assessment_scope(disclosure_classes),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _is_deterministic_read_path(
    path: Mapping[str, Any],
    service_address: str,
    context: RuleEvaluationContext,
) -> bool:
    table_address = path.get("dynamodb_table_address")
    table = context.inventory.get_by_address(table_address) if isinstance(table_address, str) else None
    table_arn = aws_facts(table).dynamodb_table_arn or table.arn if table is not None else None
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key), str) and bool(path.get(key))
            for key in (
                "task_definition_address",
                "role_address",
                "dynamodb_table_address",
                "dynamodb_table_arn",
                "dynamodb_target_kind",
                "dynamodb_target_scope",
                "dynamodb_target_arn",
            )
        )
        and table is not None
        and table.resource_type == _AWS_DYNAMODB_TABLE
        and table_arn == path.get("dynamodb_table_arn")
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("access_state") == "allowed"
        and path.get("modeled_access_state") == "allowed"
        and path.get("role_policy_complete") is True
        and _is_exact_modeled_read_target(path, table, table_arn)
        and bool(_disclosure_actions(path))
    )


def _is_exact_modeled_read_target(
    path: Mapping[str, Any],
    table: NormalizedResource,
    table_arn: str | None,
) -> bool:
    if not table_arn:
        return False

    target_kind = path.get("dynamodb_target_kind")
    target_arn = path.get("dynamodb_target_arn")
    resource_scopes = set(_string_values(path.get("resource_scopes")))
    if target_kind == "table":
        return (
            path.get("dynamodb_target_scope") == "exact_table"
            and target_arn == table_arn
            and "exact_table" in resource_scopes
            and path.get("dynamodb_index_name") is None
            and path.get("dynamodb_index_arn") is None
        )

    if target_kind != "index":
        return False
    index_name = path.get("dynamodb_index_name")
    index_arn = path.get("dynamodb_index_arn")
    if not isinstance(index_name, str) or not index_name:
        return False
    expected_index_arn = f"{table_arn}/index/{index_name}"
    table_facts = aws_facts(table)
    return (
        path.get("dynamodb_target_scope") == "exact_index"
        and target_arn == expected_index_arn
        and index_arn == expected_index_arn
        and index_name in table_facts.dynamodb_index_names
        and bool(resource_scopes.intersection({"exact_index", "index_pattern"}))
        and path.get("dynamodb_index_inventory_state") == table_facts.dynamodb_index_inventory_state
    )


def _disclosure_actions(path: Mapping[str, Any]) -> list[str]:
    return _path_disclosure_actions(path, "matched_actions")


def _denied_disclosure_actions(path: Mapping[str, Any]) -> list[str]:
    return _path_disclosure_actions(path, "denied_actions")


def _path_disclosure_actions(
    path: Mapping[str, Any],
    key: str,
) -> list[str]:
    return [
        action
        for action in _string_values(path.get(key))
        if _DISCLOSURE_ACCESS_CLASSES.intersection(DYNAMODB_ACCESS_CLASSES_BY_ACTION.get(action.lower(), ()))
    ]


def _path_disclosure_classes(path: Mapping[str, Any]) -> list[str]:
    classes = {
        access_class
        for action in _disclosure_actions(path)
        for access_class in DYNAMODB_ACCESS_CLASSES_BY_ACTION.get(
            action.lower(),
            (),
        )
        if access_class in _DISCLOSURE_ACCESS_CLASSES
    }
    return [access_class for access_class in _DISCLOSURE_CLASS_ORDER if access_class in classes]


def _disclosure_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_disclosure_classes(path)}
    return [access_class for access_class in _DISCLOSURE_CLASS_ORDER if access_class in classes]


def _broad_read_scope_reasons(
    paths: list[dict[str, Any]],
    *,
    target_count: int,
) -> list[str]:
    reasons: list[str] = []
    if any(
        path.get("dynamodb_target_kind") == "table"
        and _TABLE_SCAN_ACTIONS.intersection(action.lower() for action in _disclosure_actions(path))
        for path in paths
    ):
        reasons.append("table_scan")
    if any("bulk_export" in _path_disclosure_classes(path) for path in paths):
        reasons.append("bulk_export")
    if target_count > 1:
        reasons.append("multiple_targets")
    if any(
        path.get("dynamodb_target_kind") == "index"
        and "index_pattern" in _string_values(path.get("resource_scopes"))
        and path.get("dynamodb_index_inventory_state") != "complete"
        for path in paths
    ):
        reasons.append("incomplete_index_inventory")
    return reasons


def _read_severity(
    disclosure_classes: list[str],
    *,
    broad_scope: bool,
) -> SeverityReasoning:
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=2 if "bulk_export" in disclosure_classes else 1,
        data_sensitivity=2,
        lateral_movement=1,
        blast_radius=2 if broad_scope else 1,
    )


def _disclosure_capability_summary(
    disclosure_classes: list[str],
) -> str:
    capabilities = {
        "read": "read DynamoDB item attributes through non-mutating operations",
        "return_value_read": ("retrieve stored item attributes through mutation return values or condition failures"),
        "bulk_export": "initiate a DynamoDB table export",
    }
    values = [capabilities[access_class] for access_class in disclosure_classes]
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return " and ".join(values)
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def _read_scope_context(
    paths: list[dict[str, Any]],
    broad_scope_reasons: list[str],
) -> str:
    statements: list[str] = []
    reasons = set(broad_scope_reasons)
    if "table_scan" in reasons:
        statements.append("Table-level Scan or PartiQLSelect authority can traverse broad table contents.")
    if "bulk_export" in reasons:
        statements.append(
            "Bulk export authority can cover a complete table, although "
            "successful transfer also depends on destination S3 authorization."
        )
    if "multiple_targets" in reasons:
        statements.append("The modeled authority spans multiple exact DynamoDB targets.")
    if "incomplete_index_inventory" in reasons:
        statements.append(
            "An index-pattern grant may cover additional unresolved indexes "
            "because the modeled index inventory is incomplete."
        )
    if not statements and all(path.get("dynamodb_target_kind") == "index" for path in paths):
        statements.append(
            "Each modeled path is constrained to an exact index ARN; it can "
            "expose projected index attributes but does not establish "
            "table-wide read authority."
        )
    if not statements:
        statements.append("The modeled authority is constrained to one exact DynamoDB target.")
    return " ".join(statements)


def _read_scope_profile(
    *,
    target_count: int,
    table_count: int,
    broad_scope_reasons: list[str],
) -> list[str]:
    return [
        f"target_count={target_count}",
        f"table_count={table_count}",
        f"broad_scope={str(bool(broad_scope_reasons)).lower()}",
        "broad_scope_reasons=" + (",".join(broad_scope_reasons) or "none"),
    ]


def _read_assessment_scope(
    disclosure_classes: list[str],
) -> list[str]:
    scope = [
        ("establishes=unconditional identity-policy allow for exact modeled DynamoDB read-capable actions"),
        (
            "does_not_establish=effective authorization after DynamoDB resource "
            "policies, permissions boundaries, service control policies, or VPC "
            "endpoint policies"
        ),
    ]
    if "return_value_read" in disclosure_classes:
        scope.append("return_value_read=stored attributes may be returned by mutation responses or condition failures")
    if "bulk_export" in disclosure_classes:
        scope.append("bulk_export=export initiation is modeled; destination S3 authorization is independent")
    return scope


def _read_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"target_kind={path['dynamodb_target_kind']}",
                    f"target_scope={path['dynamodb_target_scope']}",
                    f"target_name={path.get('dynamodb_target_name') or 'unknown'}",
                    f"target_arn={path['dynamodb_target_arn']}",
                    f"table_address={path['dynamodb_table_address']}",
                    f"table_arn={path['dynamodb_table_arn']}",
                    f"index_name={path.get('dynamodb_index_name') or 'none'}",
                    (f"index_inventory_state={path.get('dynamodb_index_inventory_state') or 'unknown'}"),
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    ("disclosure_classes=" + ",".join(_path_disclosure_classes(path))),
                    f"actions={','.join(_disclosure_actions(path))}",
                    (f"resource_scopes={','.join(_string_values(path.get('resource_scopes')))}"),
                    (f"policy_resources={','.join(_string_values(path.get('policy_resources')))}"),
                    (f"denied_actions={','.join(_denied_disclosure_actions(path)) or 'none'}"),
                    "access_state=allowed",
                    "read_evaluation=unconditional_identity_policy_allow",
                )
            )
            for path in paths
        }
    )


def _is_deterministic_mutation_path(
    path: Mapping[str, Any],
    service_address: str,
    context: RuleEvaluationContext,
) -> bool:
    target_address = path.get("dynamodb_table_address")
    target = context.inventory.get_by_address(target_address) if isinstance(target_address, str) else None
    target_arn = aws_facts(target).dynamodb_table_arn or target.arn if target is not None else None
    return (
        path.get("workload_type") == _AWS_ECS_SERVICE
        and path.get("workload_address") == service_address
        and all(
            isinstance(path.get(key), str) and bool(path.get(key))
            for key in (
                "task_definition_address",
                "role_address",
                "dynamodb_table_address",
                "dynamodb_table_arn",
            )
        )
        and target is not None
        and target.resource_type == _AWS_DYNAMODB_TABLE
        and target_arn == path.get("dynamodb_table_arn")
        and path.get("role_kind") == "ecs_task_role"
        and path.get("credential_context") == "workload_runtime"
        and path.get("access_state") == "allowed"
        and path.get("modeled_access_state") == "allowed"
        and path.get("role_policy_complete") is True
        and "exact_table" in _string_values(path.get("resource_scopes"))
        and bool(_path_mutation_classes(path))
        and bool(_mutation_actions(path))
    )


def _mutation_classes(paths: list[dict[str, Any]]) -> list[str]:
    classes = {access_class for path in paths for access_class in _path_mutation_classes(path)}
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _path_mutation_classes(path: Mapping[str, Any]) -> list[str]:
    classes = {
        access_class
        for action in _mutation_actions(path)
        for access_class in DYNAMODB_ACCESS_CLASSES_BY_ACTION.get(
            action.casefold(),
            (),
        )
        if access_class in _MUTATION_ACCESS_CLASSES
    }
    return [access_class for access_class in _MUTATION_CLASS_ORDER if access_class in classes]


def _mutation_actions(path: Mapping[str, Any]) -> list[str]:
    return [
        action
        for action in _string_values(path.get("matched_actions"))
        if action.casefold() not in _TOPOLOGY_DELETION_ACTIONS and _action_has_mutation_effect(action)
    ]


def _action_has_mutation_effect(action: str) -> bool:
    return bool(
        _MUTATION_ACCESS_CLASSES
        & set(
            DYNAMODB_ACCESS_CLASSES_BY_ACTION.get(
                action.casefold(),
                (),
            )
        )
    )


def _mutation_severity(
    mutation_classes: list[str],
    *,
    table_count: int,
) -> SeverityReasoning:
    privilege_breadth = max(_CLASS_PRIVILEGE_BREADTH[access_class] for access_class in mutation_classes)
    destructive = "destructive_administration" in mutation_classes
    return build_severity_reasoning(
        internet_exposure=True,
        privilege_breadth=privilege_breadth,
        data_sensitivity=2,
        lateral_movement=1,
        blast_radius=2 if destructive or table_count > 1 else 1,
    )


def _capability_summary(mutation_classes: list[str]) -> str:
    capabilities = [_CLASS_CAPABILITIES[access_class] for access_class in mutation_classes]
    if len(capabilities) == 1:
        return capabilities[0]
    if len(capabilities) == 2:
        return " and ".join(capabilities)
    return ", ".join(capabilities[:-1]) + f", and {capabilities[-1]}"


def _impact_context(mutation_classes: list[str]) -> str:
    if "destructive_administration" in mutation_classes:
        return (
            " Destructive table administration is weighted more heavily than "
            "item-level mutation because it can affect a complete table or replica."
        )
    if "configuration_administration" in mutation_classes:
        return (
            " This is configuration or control mutation rather than a claim that "
            "the action directly modifies item contents."
        )
    return ""


def _impact_profile(mutation_classes: list[str]) -> list[str]:
    return [
        f"class={access_class}; capability={_CLASS_CAPABILITIES[access_class]}; "
        f"privilege_breadth={_CLASS_PRIVILEGE_BREADTH[access_class]}"
        for access_class in mutation_classes
    ]


def _task_role_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"address={path['role_address']}",
                    f"arn={path.get('role_arn') or 'unknown'}",
                    "role_kind=ecs_task_role",
                    "credential_context=workload_runtime",
                    "role_policy_complete=true",
                )
            )
            for path in paths
        }
    )


def _mutation_path_evidence(paths: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            "; ".join(
                (
                    f"table_address={path['dynamodb_table_address']}",
                    f"table_arn={path['dynamodb_table_arn']}",
                    f"task_definition={path['task_definition_address']}",
                    f"task_role={path['role_address']}",
                    (f"mutation_classes={','.join(_path_mutation_classes(path))}"),
                    f"actions={','.join(_mutation_actions(path))}",
                    (f"resource_scopes={','.join(_string_values(path.get('resource_scopes')))}"),
                    (f"policy_resources={','.join(_string_values(path.get('policy_resources')))}"),
                    (f"denied_actions={','.join(_string_values(path.get('denied_actions'))) or 'none'}"),
                    "access_state=allowed",
                    "mutation_evaluation=unconditional_identity_policy_allow",
                )
            )
            for path in paths
        }
    )


def _string_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]
