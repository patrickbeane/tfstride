from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.resource_concepts import (
    DATABASE_RESOURCE_TYPES,
    OBJECT_STORAGE_RESOURCE_TYPES,
    PUBLIC_COMPUTE_RESOURCE_TYPES,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_helpers import subnet_posture
from tfstride.models import BoundaryType, Finding
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.resource_helpers import describe_security_group_rule


class AwsPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_compute_exposure(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        indexes = context.analysis_indexes
        assert indexes is not None
        for resource in inventory.by_type(*PUBLIC_COMPUTE_RESOURCE_TYPES):
            if not resource.public_exposure:
                continue
            attached_groups = indexes.attached_security_groups(resource)
            risky_rules = [
                (security_group, rule)
                for security_group in attached_groups
                for rule in security_group.network_rules
                if rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ]
            if not risky_rules:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", resource.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[
                        resource.address,
                        *[sg.address for sg in attached_groups],
                    ],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{resource.display_name} is reachable from the internet and at least one attached "
                        "security group allows administrative access or all ports from 0.0.0.0/0. "
                        "That broad ingress raises the chance of unauthenticated probing and credential attacks."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "security_group_rules",
                            [
                                describe_security_group_rule(security_group, rule)
                                for security_group, rule in risky_rules
                            ],
                        ),
                        evidence_item("public_exposure_reasons", resource.public_exposure_reasons),
                        evidence_item("subnet_posture", subnet_posture(resource, inventory)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_unencrypted_databases(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for database in inventory.by_type(*DATABASE_RESOURCE_TYPES):
            if database.storage_encrypted:
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
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} stores sensitive data, but `storage_encrypted` is disabled. "
                        "That weakens data-at-rest protections for underlying storage, snapshots, and backup handling."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "encryption_posture",
                            [
                                "storage_encrypted is false",
                                f"engine is {aws_facts(database).engine or 'unknown'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_public_object_storage(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for bucket in inventory.by_type(*OBJECT_STORAGE_RESOURCE_TYPES):
            if not bucket.public_exposure:
                continue
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address))
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
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{bucket.display_name} appears to be public through ACLs or bucket policy. "
                        "Public object access is a common source of unintended data disclosure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings
