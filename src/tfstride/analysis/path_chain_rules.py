from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.policy_conditions import (
    describe_trust_narrowing_for_principal,
    trust_statement_principal_assessments,
    trust_statement_has_effective_narrowing_for_principal,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_helpers import attached_security_groups, join_clauses, subnet_posture
from tfstride.models import (
    BoundaryType,
    Finding,
    NormalizedResource,
    ResourceInventory,
    SecurityGroupRule,
    TrustBoundary,
)
from tfstride.resource_helpers import describe_security_group_rule


class PathChainRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_transitive_private_data_exposure(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
        boundary_index = context.boundary_index
        trusted_workload_hops = _trusted_workload_hops(inventory)
        private_data_paths = _private_workload_data_paths(boundary_index, inventory)
        seen: set[tuple[str, ...]] = set()

        internet_boundaries = sorted(
            (
                boundary
                for boundary in boundary_index.values()
                if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE
            ),
            key=lambda boundary: (boundary.target, boundary.identifier),
        )

        for internet_boundary in internet_boundaries:
            entry = inventory.get_by_address(internet_boundary.target)
            if entry is None:
                continue

            for path_workloads, security_group_hops in _iter_transitive_workload_paths(
                entry,
                trusted_workload_hops,
                max_hops=2,
            ):
                terminal_workload = path_workloads[-1]
                for data_store, data_boundary in private_data_paths.get(terminal_workload.address, []):
                    finding_key = (
                        entry.address,
                        *[workload.address for workload in path_workloads],
                        data_store.address,
                    )
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)
                    findings.append(
                        _build_transitive_private_data_finding(
                            rule_id=rule_id,
                            finding_factory=self._finding_factory,
                            inventory=inventory,
                            entry=entry,
                            path_workloads=path_workloads,
                            security_group_hops=security_group_hops,
                            data_store=data_store,
                            data_boundary=data_boundary,
                        )
                    )
        return findings

    def detect_control_plane_sensitive_workload_chain(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        inventory = context.inventory
        boundary_index = context.boundary_index
        primary_account_id = inventory.primary_account_id
        control_boundaries_by_role = _control_workload_boundaries_by_role(boundary_index)
        sensitive_data_paths = _private_sensitive_controlled_data_paths(boundary_index, inventory)
        seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()

        for role in inventory.by_type("aws_iam_role"):
            control_boundaries = control_boundaries_by_role.get(role.address, [])
            if not control_boundaries:
                continue
            for trust_statement in role.trust_statements:
                for assessment in trust_statement_principal_assessments(trust_statement, primary_account_id):
                    if trust_statement_has_effective_narrowing_for_principal(trust_statement, assessment):
                        continue
                    principal = assessment.principal
                    if assessment.is_service:
                        continue
                    if not (assessment.is_foreign_account or assessment.is_wildcard):
                        continue

                    chained_paths: list[
                        tuple[NormalizedResource, TrustBoundary, NormalizedResource, TrustBoundary]
                    ] = []
                    for control_boundary in control_boundaries:
                        workload = inventory.get_by_address(control_boundary.target)
                        if workload is None:
                            continue
                        for data_store, data_boundary in sensitive_data_paths.get(workload.address, []):
                            chained_paths.append((workload, control_boundary, data_store, data_boundary))
                    if not chained_paths:
                        continue

                    workload_addresses = tuple(sorted({workload.address for workload, _, _, _ in chained_paths}))
                    data_store_addresses = tuple(sorted({data_store.address for _, _, data_store, _ in chained_paths}))
                    finding_key = (role.address, principal, workload_addresses, data_store_addresses)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    privilege_breadth = 2 if assessment.is_wildcard else 1
                    blast_radius = 2 if assessment.is_wildcard or len(data_store_addresses) > 1 else 1
                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=False,
                        privilege_breadth=privilege_breadth,
                        data_sensitivity=2,
                        lateral_movement=1,
                        blast_radius=blast_radius,
                    )
                    trust_boundary = boundary_index.get(
                        (BoundaryType.CROSS_ACCOUNT_OR_ROLE, principal, role.address)
                    )
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=[
                                role.address,
                                *workload_addresses,
                                *data_store_addresses,
                            ],
                            trust_boundary_id=trust_boundary.identifier if trust_boundary else None,
                            rationale=(
                                f"{principal} can assume {role.display_name}, and that role governs workload paths into "
                                f"{', '.join(data_store.display_name for data_store in sorted({data_store.address: data_store for _, _, data_store, _ in chained_paths}.values(), key=lambda resource: resource.address))}. "
                                "A broad or foreign control-plane principal can therefore influence a workload that already "
                                "retains sensitive secret or database access."
                            ),
                            evidence=collect_evidence(
                                evidence_item("trust_principals", [principal]),
                                evidence_item(
                                    "trust_scope",
                                    [assessment.scope_description] if assessment.scope_description else [],
                                ),
                                evidence_item(
                                    "control_path",
                                    [
                                        f"{principal} assumes {role.address}",
                                        *[
                                            f"{control_boundary.source} governs {control_boundary.target}"
                                            for _, control_boundary, _, _ in chained_paths
                                        ],
                                        *[
                                            f"{data_boundary.source} reaches {data_boundary.target}"
                                            for _, _, _, data_boundary in chained_paths
                                        ],
                                    ],
                                ),
                                evidence_item(
                                    "boundary_rationale",
                                    [
                                        *[
                                            control_boundary.rationale
                                            for _, control_boundary, _, _ in chained_paths
                                        ],
                                        *[
                                            data_boundary.rationale
                                            for _, _, _, data_boundary in chained_paths
                                        ],
                                    ],
                                ),
                                evidence_item(
                                    "sensitive_data_targets",
                                    list(data_store_addresses),
                                ),
                                evidence_item(
                                    "trust_narrowing",
                                    describe_trust_narrowing_for_principal(trust_statement, assessment),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _trusted_workload_hops(
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]]:
    resources_by_security_group: dict[str, list[NormalizedResource]] = {}
    for resource in inventory.resources:
        for security_group_id in resource.security_group_ids:
            resources_by_security_group.setdefault(security_group_id, []).append(resource)

    trusted_hops: dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]] = {}
    for workload in inventory.by_type("aws_instance", "aws_ecs_service"):
        for security_group in attached_security_groups(workload, inventory):
            for rule in security_group.network_rules:
                if rule.direction != "ingress" or not rule.referenced_security_group_ids:
                    continue
                matched_sources = sorted(
                    {
                        source.address: source
                        for security_group_id in rule.referenced_security_group_ids
                        for source in resources_by_security_group.get(security_group_id, [])
                        if source.address != workload.address
                    }.values(),
                    key=lambda source: source.address,
                )
                for source in matched_sources:
                    trusted_hops.setdefault(source.address, []).append((workload, security_group, rule))
    return trusted_hops


def _iter_transitive_workload_paths(
    entry: NormalizedResource,
    trusted_workload_hops: dict[str, list[tuple[NormalizedResource, NormalizedResource, SecurityGroupRule]]],
    *,
    max_hops: int,
) -> list[tuple[list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]]:
    discovered_paths: list[tuple[list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = []
    frontier: list[tuple[NormalizedResource, list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = [
        (entry, [], [])
    ]

    for _ in range(max_hops):
        next_frontier: list[tuple[NormalizedResource, list[NormalizedResource], list[tuple[NormalizedResource, SecurityGroupRule]]]] = []
        for source, path_workloads, security_group_hops in frontier:
            for downstream, security_group, rule in trusted_workload_hops.get(source.address, []):
                if downstream.address == entry.address:
                    continue
                if any(workload.address == downstream.address for workload in path_workloads):
                    continue
                new_path = [*path_workloads, downstream]
                new_hops = [*security_group_hops, (security_group, rule)]
                discovered_paths.append((new_path, new_hops))
                next_frontier.append((downstream, new_path, new_hops))
        frontier = next_frontier
        if not frontier:
            break
    return discovered_paths


def _private_workload_data_paths(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, TrustBoundary]]]:
    data_paths: dict[str, list[tuple[NormalizedResource, TrustBoundary]]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
            continue
        data_store = inventory.get_by_address(boundary.target)
        if data_store is None or not _is_hidden_data_store(data_store):
            continue
        data_paths.setdefault(boundary.source, []).append((data_store, boundary))
    return data_paths


def _private_sensitive_controlled_data_paths(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
    inventory: ResourceInventory,
) -> dict[str, list[tuple[NormalizedResource, TrustBoundary]]]:
    data_paths: dict[str, list[tuple[NormalizedResource, TrustBoundary]]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.WORKLOAD_TO_DATA_STORE:
            continue
        data_store = inventory.get_by_address(boundary.target)
        if data_store is None or not _is_control_plane_sensitive_data_store(data_store):
            continue
        data_paths.setdefault(boundary.source, []).append((data_store, boundary))
    return data_paths


def _control_workload_boundaries_by_role(
    boundary_index: dict[tuple[BoundaryType, str, str], TrustBoundary],
) -> dict[str, list[TrustBoundary]]:
    boundaries_by_role: dict[str, list[TrustBoundary]] = {}
    for boundary in boundary_index.values():
        if boundary.boundary_type != BoundaryType.CONTROL_TO_WORKLOAD:
            continue
        boundaries_by_role.setdefault(boundary.source, []).append(boundary)
    return boundaries_by_role


def _is_hidden_data_store(resource: NormalizedResource) -> bool:
    return not (
        resource.public_exposure
        or resource.direct_internet_reachable
        or resource.internet_ingress_capable
    )


def _is_control_plane_sensitive_data_store(resource: NormalizedResource) -> bool:
    return resource.resource_type in {"aws_db_instance", "aws_secretsmanager_secret"} and _is_hidden_data_store(resource)


def _build_transitive_private_data_finding(
    *,
    rule_id: str,
    finding_factory: FindingFactory,
    inventory: ResourceInventory,
    entry: NormalizedResource,
    path_workloads: list[NormalizedResource],
    security_group_hops: list[tuple[NormalizedResource, SecurityGroupRule]],
    data_store: NormalizedResource,
    data_boundary: TrustBoundary,
) -> Finding:
    terminal_workload = path_workloads[-1]
    workload_path = [entry, *path_workloads]
    hop_descriptions = [
        f"{source.display_name} can reach {target.display_name}"
        for source, target in zip(workload_path[:-1], workload_path[1:])
    ]
    data_posture = [
        f"{data_store.address} is not directly public",
    ]
    if data_store.resource_type == "aws_db_instance":
        data_posture.append("database has no direct internet ingress path")
    severity_reasoning = build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=2 if data_store.data_sensitivity == "sensitive" else 1,
        lateral_movement=2,
        blast_radius=1,
    )
    affected_resources = [entry.address, *[workload.address for workload in path_workloads], data_store.address]
    affected_resources.extend(security_group.address for security_group, _ in security_group_hops)
    return finding_factory.build(
        rule_id=rule_id,
        severity=severity_reasoning.severity,
        affected_resources=list(dict.fromkeys(affected_resources)),
        trust_boundary_id=data_boundary.identifier,
        rationale=(
            f"{data_store.display_name} is not directly public, but internet traffic can first reach {entry.display_name}, "
            f"move through {join_clauses(hop_descriptions)}, and then cross into the private data tier through "
            f"{terminal_workload.display_name}. That creates a quieter transitive exposure path than a directly public data store."
        ),
        evidence=collect_evidence(
            evidence_item("network_path", [
                f"internet reaches {entry.address}",
                *[
                    f"{source.address} reaches {target.address}"
                    for source, target in zip(workload_path[:-1], workload_path[1:])
                ],
                f"{terminal_workload.address} reaches {data_store.address}",
            ]),
            evidence_item(
                "security_group_rules",
                [describe_security_group_rule(security_group, rule) for security_group, rule in security_group_hops],
            ),
            evidence_item("subnet_posture", [posture for workload in workload_path for posture in subnet_posture(workload, inventory)]),
            evidence_item("data_tier_posture", data_posture),
            evidence_item("boundary_rationale", [data_boundary.rationale]),
        ),
        severity_reasoning=severity_reasoning,
    )
