from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.resource_concepts import DATABASE_RESOURCE_TYPES
from tfstride.analysis.rule_definitions import BoundaryIndex, RuleEvaluationContext
from tfstride.analysis.rule_helpers import join_clauses, subnet_posture
from tfstride.models import BoundaryType, Finding, NormalizedResource, SecurityGroupRule, TrustBoundary
from tfstride.providers.aws.analysis_indexes import (
    AwsSecurityGroupRelationships,
    aws_analysis_indexes,
)
from tfstride.resource_helpers import describe_security_group_rule


class AwsNetworkDataRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_database_exposure(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        boundary_index = context.boundary_index
        indexes = context.analysis_indexes
        assert indexes is not None
        security_group_relationships = aws_analysis_indexes(indexes, inventory).security_group_relationships
        for database in inventory.by_type(*DATABASE_RESOURCE_TYPES):
            attached_groups = security_group_relationships.attached_security_groups(database)
            internet_rules = [
                (security_group, rule)
                for security_group in attached_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress" and rule.allows_internet()
            ]
            public_tier_rules: list[tuple[NormalizedResource, SecurityGroupRule, list[NormalizedResource]]] = []
            for security_group in attached_groups:
                for rule in security_group.network_rules:
                    if rule.direction != "ingress":
                        continue
                    matched_workloads = _public_resources_allowed_by_rule(
                        security_group_relationships,
                        security_group,
                        rule,
                    )
                    if matched_workloads:
                        public_tier_rules.append((security_group, rule, matched_workloads))

            direct_internet_reachable = database.direct_internet_reachable and (internet_rules or not attached_groups)
            if not internet_rules and not public_tier_rules and not direct_internet_reachable:
                continue
            boundary = None
            if direct_internet_reachable:
                boundary = boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
            elif public_tier_rules:
                first_public_workload = sorted(
                    {workload.address for _, _, workloads in public_tier_rules for workload in workloads}
                )[0]
                boundary = boundary_index.get(
                    (BoundaryType.WORKLOAD_TO_DATA_STORE, first_public_workload, database.address)
                )
            if boundary is None and database.vpc_id:
                public_private_boundary = next(
                    (item for item in boundary_index.values() if item.boundary_type == BoundaryType.PUBLIC_TO_PRIVATE),
                    None,
                )
                boundary = public_private_boundary
            severity_reasoning = build_severity_reasoning(
                internet_exposure=bool(internet_rules or public_tier_rules or direct_internet_reachable),
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            path_signals: list[str] = []
            if direct_internet_reachable:
                path_signals.append("database is directly internet reachable")
            elif internet_rules:
                path_signals.append(
                    "database is not marked directly internet reachable, but its security groups allow internet-origin ingress"
                )
            if public_tier_rules:
                path_signals.append("database trusts security groups attached to internet-exposed workloads")
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address, *[sg.address for sg in attached_groups]],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{database.display_name} is a sensitive data store, but "
                        f"{join_clauses(path_signals)}. "
                        "That weakens the expected separation between the workload tier and the data tier."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "security_group_rules",
                            [
                                describe_security_group_rule(security_group, rule)
                                for security_group, rule in internet_rules
                            ]
                            + [
                                describe_security_group_rule(security_group, rule)
                                for security_group, rule, _ in public_tier_rules
                            ],
                        ),
                        evidence_item(
                            "network_path",
                            path_signals
                            + [
                                f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(workload.address for workload in workloads)}"
                                for security_group, rule, workloads in public_tier_rules
                            ],
                        ),
                        evidence_item("public_exposure_reasons", database.public_exposure_reasons),
                        evidence_item(
                            "subnet_posture",
                            [
                                posture
                                for _, _, workloads in public_tier_rules
                                for workload in workloads
                                for posture in subnet_posture(
                                    workload, security_group_relationships.resource_index.resolve_subnet
                                )
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_missing_segmentation(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        boundary_index = context.boundary_index
        indexes = context.analysis_indexes
        assert indexes is not None
        security_group_relationships = aws_analysis_indexes(indexes, inventory).security_group_relationships
        for database in inventory.by_type(*DATABASE_RESOURCE_TYPES):
            for security_group in security_group_relationships.attached_security_groups(database):
                risky_rules_with_workloads = [
                    (rule, matched_workloads)
                    for rule in security_group.network_rules
                    if rule.direction == "ingress"
                    and (
                        matched_workloads := _public_resources_allowed_by_rule(
                            security_group_relationships,
                            security_group,
                            rule,
                        )
                    )
                ]
                if not risky_rules_with_workloads:
                    continue
                risky_rules = [rule for rule, _ in risky_rules_with_workloads]
                exposed_workloads = sorted(
                    {
                        workload.address
                        for _, matched_workloads in risky_rules_with_workloads
                        for workload in matched_workloads
                    }
                )
                boundary = _select_workload_to_database_boundary(
                    boundary_index,
                    database.address,
                    exposed_workloads,
                )
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=0,
                    data_sensitivity=2,
                    lateral_movement=2,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[database.address, *exposed_workloads, security_group.address],
                        trust_boundary_id=boundary.identifier if boundary else None,
                        rationale=(
                            f"{database.display_name} accepts traffic from security groups attached to internet-facing "
                            "workloads. A compromise of the public tier can therefore move laterally into the private data tier."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "security_group_rules",
                                [describe_security_group_rule(security_group, rule) for rule in risky_rules],
                            ),
                            evidence_item(
                                "network_path",
                                [
                                    f"{security_group.address} allows {', '.join(rule.referenced_security_group_ids)} attached to {', '.join(workload.address for workload in matched_workloads)}"
                                    for rule, matched_workloads in risky_rules_with_workloads
                                ],
                            ),
                            evidence_item(
                                "subnet_posture",
                                [
                                    posture
                                    for workload_address in exposed_workloads
                                    for posture in subnet_posture(
                                        inventory.get_by_address(workload_address),
                                        security_group_relationships.resource_index.resolve_subnet,
                                    )
                                ],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings


def _select_workload_to_database_boundary(
    boundary_index: BoundaryIndex,
    database_address: str,
    workload_addresses: Iterable[str],
) -> TrustBoundary | None:
    """Select an existing data-store edge for already-matched workload addresses.

    The lexicographically first workload with an exact edge to the database
    supplies the representative boundary.
    """
    for workload_address in sorted(set(workload_addresses)):
        boundary = boundary_index.get((BoundaryType.WORKLOAD_TO_DATA_STORE, workload_address, database_address))
        if boundary is not None:
            return boundary
    return None


def _public_resources_allowed_by_rule(
    relationships: AwsSecurityGroupRelationships,
    security_group: NormalizedResource,
    rule: SecurityGroupRule,
) -> list[NormalizedResource]:
    return sorted(
        {
            resource.address: resource
            for reference in rule.referenced_security_group_ids
            for resource in relationships.resources_attached_to(
                reference,
                source=security_group,
                public_only=True,
            )
        }.values(),
        key=lambda resource: resource.address,
    )
