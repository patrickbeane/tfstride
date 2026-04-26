from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.policy_trust_rules import PolicyTrustRuleDetectors
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import (
    BoundaryType,
    Finding,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    Severity,
    TrustBoundary,
)


class PolicyTrustRuleDetectorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detectors = PolicyTrustRuleDetectors(FindingFactory())

    def test_detect_resource_policy_exposure_uses_policy_sources_and_boundary(self) -> None:
        principal = "arn:aws:iam::444455556666:root"
        secret = NormalizedResource(
            address="aws_secretsmanager_secret.app",
            provider="aws",
            resource_type="aws_secretsmanager_secret",
            name="app",
            category=ResourceCategory.DATA,
            metadata={
                "resource_policy_source_addresses": ["aws_secretsmanager_secret_policy.app"],
            },
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["*"],
                    principals=[principal],
                )
            ],
        )
        boundary = TrustBoundary(
            identifier="external-secret-policy",
            boundary_type=BoundaryType.CROSS_ACCOUNT_OR_ROLE,
            source=principal,
            target=secret.address,
            description="foreign account can access the secret",
            rationale="secret policy grants the foreign account root",
        )
        context = _context([secret], [boundary])

        findings = self.detectors.detect_sensitive_resource_policy_exposure(
	        context,
	        "aws-sensitive-resource-policy-external-access",
	    )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence_by_key(finding)
        self.assertEqual(finding.rule_id, "aws-sensitive-resource-policy-external-access")
        self.assertEqual(
            finding.title,
            "Sensitive resource policy allows broad or cross-account access",
        )
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(
            finding.affected_resources,
            ["aws_secretsmanager_secret.app", "aws_secretsmanager_secret_policy.app"],
        )
        self.assertEqual(finding.trust_boundary_id, "external-secret-policy")
        self.assertEqual(evidence["trust_principals"], [principal])
        self.assertEqual(
            evidence["trust_scope"],
            ["principal is foreign account root 444455556666"],
        )
        self.assertEqual(evidence["policy_actions"], ["secretsmanager:GetSecretValue"])
        self.assertEqual(
            evidence["resource_policy_sources"],
            ["aws_secretsmanager_secret_policy.app"],
        )

    def test_detect_trust_rules_use_boundary_and_trust_evidence(self) -> None:
        principal = "arn:aws:iam::444455556666:role/deployer"
        role = NormalizedResource(
            address="aws_iam_role.deployer",
            provider="aws",
            resource_type="aws_iam_role",
            name="deployer",
            category=ResourceCategory.IAM,
            metadata={
                "trust_statements": [
                    {
                        "principals": [principal],
                        "narrowing_condition_keys": [],
                        "narrowing_conditions": [],
                        "has_narrowing_conditions": False,
                    }
                ]
            },
        )
        boundary = TrustBoundary(
            identifier="external-role-trust",
            boundary_type=BoundaryType.CROSS_ACCOUNT_OR_ROLE,
            source=principal,
            target=role.address,
            description="foreign deployer can assume the role",
            rationale="trust policy includes the foreign deployer role",
        )
        context = _context([role], [boundary])

        expansion_findings = self.detectors.detect_trust_expansion(
	        context,
	        "aws-role-trust-expansion",
	    )
        narrowing_findings = self.detectors.detect_unconstrained_trust(
	        context,
	        "aws-role-trust-missing-narrowing",
	    )

        self.assertEqual(len(expansion_findings), 1)
        expansion = expansion_findings[0]
        expansion_evidence = _evidence_by_key(expansion)
        self.assertEqual(expansion.rule_id, "aws-role-trust-expansion")
        self.assertEqual(expansion.title, "Role trust relationship expands blast radius")
        self.assertEqual(expansion.severity, Severity.MEDIUM)
        self.assertEqual(expansion.affected_resources, ["aws_iam_role.deployer"])
        self.assertEqual(expansion.trust_boundary_id, "external-role-trust")
        self.assertEqual(expansion_evidence["trust_principals"], [principal])
        self.assertEqual(
            expansion_evidence["trust_path"],
            ["trust principal belongs to foreign account 444455556666"],
        )

        self.assertEqual(len(narrowing_findings), 1)
        narrowing = narrowing_findings[0]
        narrowing_evidence = _evidence_by_key(narrowing)
        self.assertEqual(narrowing.rule_id, "aws-role-trust-missing-narrowing")
        self.assertEqual(
            narrowing.title,
            "Cross-account or broad role trust lacks narrowing conditions",
        )
        self.assertEqual(narrowing.severity, Severity.MEDIUM)
        self.assertEqual(narrowing.affected_resources, ["aws_iam_role.deployer"])
        self.assertEqual(narrowing.trust_boundary_id, "external-role-trust")
        self.assertEqual(narrowing_evidence["trust_principals"], [principal])
        self.assertEqual(
            narrowing_evidence["trust_scope"],
            ["principal belongs to foreign account 444455556666"],
        )
        self.assertEqual(
            narrowing_evidence["trust_narrowing"],
            [
                "supported narrowing conditions present: false",
                "supported narrowing condition keys: none",
            ],
        )


def _context(
    resources: list[NormalizedResource],
    boundaries: list[TrustBoundary],
) -> RuleEvaluationContext:
    return RuleEvaluationContext(
        inventory=ResourceInventory(
            provider="aws",
            resources=resources,
            metadata={"primary_account_id": "111122223333"},
        ),
        boundary_index={
            (boundary.boundary_type, boundary.source, boundary.target): boundary
            for boundary in boundaries
        },
    )


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


if __name__ == "__main__":
    unittest.main()