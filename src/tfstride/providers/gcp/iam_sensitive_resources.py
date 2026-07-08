from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.gcp.iam_access import (
    GCP_KMS_ACCESS_ROLES,
    GCP_SECRET_ACCESS_ROLES,
    assess_gcp_sensitive_iam_member,
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
)
from tfstride.providers.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.providers.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.providers.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
)
from tfstride.providers.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.providers.gcp.resource_utils import binding_members

_SENSITIVE_GCP_RESOURCE_TYPES = frozenset({"google_kms_crypto_key", "google_secret_manager_secret"})


class GcpSensitiveResourceIamDetectors:
    def detect_sensitive_iam_external_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for resource in context.inventory.by_type(*_SENSITIVE_GCP_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource).iam
            for binding in resource_facts.bindings:
                role = str(binding.get("role") or "unknown role")
                if not _is_sensitive_gcp_resource_role(resource, role):
                    continue
                source = str(binding.get("source") or "").strip()
                for member in binding_members(binding):
                    assessment = assess_gcp_sensitive_iam_member(member, resource_facts.project)
                    if assessment is None:
                        continue
                    finding_key = (resource.address, role, assessment.member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    condition = binding.get("condition")
                    severity_reasoning = guardrail_adjusted_severity_reasoning(
                        gcp_org_policy_guardrail_index(context.analysis_indexes),
                        resource,
                        constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                        internet_exposure=assessment.is_public,
                        privilege_breadth=gcp_iam_condition_limited_score(
                            2 if assessment.is_public or assessment.is_broad else 1, condition, floor=1
                        ),
                        data_sensitivity=2,
                        lateral_movement=1,
                        blast_radius=gcp_iam_condition_limited_score(
                            2 if assessment.is_public or assessment.is_broad else 1, condition, floor=0
                        ),
                    )
                    affected_resources = dedupe_addresses([resource.address, source])
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=affected_resources,
                            trust_boundary_id=None,
                            rationale=(
                                f"{resource.display_name} grants `{role}` to `{assessment.member}` through "
                                "GCP IAM. Public, broad-domain, or foreign-project principals can access "
                                "sensitive secrets or cryptographic key operations outside the expected "
                                "project trust boundary."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={source}" if source else "source=unknown",
                                        f"role={role}",
                                        f"member={assessment.member}",
                                    ],
                                ),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                                evidence_item(
                                    "resource_policy_sources",
                                    resource_facts.resource_policy_source_addresses,
                                ),
                                organization_guardrail_evidence(
                                    gcp_org_policy_guardrail_index(context.analysis_indexes),
                                    resource,
                                    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings


def _is_sensitive_gcp_resource_role(resource: NormalizedResource, role: str) -> bool:
    normalized_role = str(role).strip()
    if resource.resource_type == "google_secret_manager_secret":
        return normalized_role in GCP_SECRET_ACCESS_ROLES
    if resource.resource_type == "google_kms_crypto_key":
        return normalized_role in GCP_KMS_ACCESS_ROLES
    return False
