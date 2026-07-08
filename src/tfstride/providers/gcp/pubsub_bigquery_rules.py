from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.gcp.iam_access import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    broad_resource_iam_bindings,
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
)

_PUBSUB_RESOURCE_TYPES = frozenset({"google_pubsub_topic", "google_pubsub_subscription"})
_BIGQUERY_RESOURCE_TYPES = frozenset({"google_bigquery_dataset", "google_bigquery_table"})


class GcpPubSubBigQueryRuleDetectors:
    def detect_pubsub_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PUBSUB_RESOURCE_TYPES):
            for source, role, member, assessment, condition in broad_resource_iam_bindings(
                resource, GCP_PUBSUB_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(
                        2 if assessment.is_public else 1, condition, floor=1
                    ),
                    data_sensitivity=1,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([resource.address, source]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{resource.display_name} grants `{role}` to `{member}` through Pub/Sub "
                            "IAM. Public or broad principals can publish, consume, or administer event "
                            "streams outside the expected service boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={source}" if source else "source=unknown",
                                    f"role={role}",
                                    f"member={member}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).iam.resource_policy_source_addresses,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_bigquery_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_BIGQUERY_RESOURCE_TYPES):
            for source, role, member, assessment, condition in broad_resource_iam_bindings(
                resource, GCP_BIGQUERY_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(
                        2 if assessment.is_public else 1, condition, floor=1
                    ),
                    data_sensitivity=2,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(2 if assessment.is_public else 1, condition, floor=0),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([resource.address, source]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{resource.display_name} grants `{role}` to `{member}` through BigQuery "
                            "IAM. Public or broad principals can read or modify analytical data outside "
                            "the expected project trust boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={source}" if source else "source=unknown",
                                    f"role={role}",
                                    f"member={member}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).iam.resource_policy_source_addresses,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings
