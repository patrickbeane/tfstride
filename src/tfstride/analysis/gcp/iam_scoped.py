from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.gcp.custom_roles import build_gcp_custom_role_index, custom_role_permissions
from tfstride.analysis.gcp.iam_access import (
    assess_gcp_broad_iam_member,
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
    iam_binding_condition,
    iam_resource_binding_members,
    org_folder_scope_description,
)
from tfstride.analysis.gcp.iam_role_risk import (
    privileged_org_folder_role_risk,
    privileged_project_role_risk,
)
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.gcp.constants import (
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)


class GcpScopedIamDetectors:
    def detect_project_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in iam_resource_binding_members(binding):
                if member not in PUBLIC_GCP_IAM_MEMBERS:
                    continue
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = guardrail_adjusted_severity_reasoning(
                    context.analysis_indexes.gcp_org_policy_guardrails,
                    binding,
                    constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                    internet_exposure=True,
                    privilege_breadth=1,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at project scope. Public "
                            "or broadly authenticated principals can cross into the control plane without an "
                            "organization-owned identity boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            organization_guardrail_evidence(
                                context.analysis_indexes.gcp_org_policy_guardrails,
                                binding,
                                ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_project_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in iam_resource_binding_members(binding):
                role_risk = privileged_project_role_risk(role, custom_roles)
                if role_risk is None:
                    continue
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=gcp_iam_condition_limited_score(2, condition, floor=1),
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=gcp_iam_condition_limited_score(2, condition, floor=1),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at project scope. That role enables {role_risk} and can materially expand "
                            "control-plane blast radius if the principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_org_folder_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = org_folder_scope_description(binding)
            for role, member in iam_resource_binding_members(binding):
                assessment = assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = guardrail_adjusted_severity_reasoning(
                    context.analysis_indexes.gcp_org_policy_guardrails,
                    binding,
                    constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS,),
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(2, condition, floor=1),
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=gcp_iam_condition_limited_score(2, condition, floor=1),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at {scope}. Public or "
                            "broad-domain principals at organization or folder scope can expand access across "
                            "many descendant projects and workloads."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            organization_guardrail_evidence(
                                context.analysis_indexes.gcp_org_policy_guardrails,
                                binding,
                                ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_org_folder_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = org_folder_scope_description(binding)
            for role, member in iam_resource_binding_members(binding):
                role_risk = privileged_org_folder_role_risk(role, custom_roles)
                if role_risk is None:
                    continue
                condition = iam_binding_condition(binding, role, member)
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=False,
                    privilege_breadth=gcp_iam_condition_limited_score(2, condition, floor=1),
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=gcp_iam_condition_limited_score(2, condition, floor=1),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at {scope}. That role enables {role_risk} across a high-level resource "
                            "boundary and can materially expand blast radius if the principal is compromised."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings