from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_registry import RuleRegistry
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
from tfstride.providers.aws.iam_rules import AwsIamRuleDetectors


class AwsIamRuleDetectorsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detectors = AwsIamRuleDetectors(FindingFactory())

    def test_detect_wildcard_permissions_builds_finding_from_policy_statements(self) -> None:
        policy = NormalizedResource(
            address="aws_iam_policy.admin",
            provider="aws",
            resource_type="aws_iam_policy",
            name="admin",
            category=ResourceCategory.IAM,
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["s3:*", "ec2:DescribeInstances"],
                    resources=["*"],
                )
            ],
        )
        context = RuleEvaluationContext(
            inventory=ResourceInventory(provider="aws", resources=[policy]),
            boundary_index={},
            rule_registry=RuleRegistry([]),
        )

        findings = self.detectors.detect_wildcard_permissions(
            context,
            "aws-iam-wildcard-permissions",
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence_by_key(finding)
        self.assertEqual(finding.rule_id, "aws-iam-wildcard-permissions")
        self.assertEqual(finding.title, "IAM policy grants wildcard privileges")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.affected_resources, ["aws_iam_policy.admin"])
        self.assertEqual(evidence["iam_actions"], ["s3:*"])
        self.assertEqual(evidence["iam_resources"], ["*"])
        self.assertEqual(
            evidence["policy_statements"],
            ["Allow actions=[s3:*, ec2:DescribeInstances] resources=[*]"],
        )

    def test_detect_workload_role_sensitive_permissions_uses_boundary_and_evidence(self) -> None:
        role = NormalizedResource(
            address="aws_iam_role.worker",
            provider="aws",
            resource_type="aws_iam_role",
            name="worker",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/worker",
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=[
                        "arn:aws:secretsmanager:us-east-1:111122223333:secret:customer",
                    ],
                )
            ],
        )
        workload = NormalizedResource(
            address="aws_lambda_function.worker",
            provider="aws",
            resource_type="aws_lambda_function",
            name="worker",
            category=ResourceCategory.COMPUTE,
            attached_role_arns=["arn:aws:iam::111122223333:role/worker"],
            public_exposure=True,
            metadata={"public_exposure_reasons": ["lambda function URL is public"]},
        )
        boundary = TrustBoundary(
            identifier="control-to-worker",
            boundary_type=BoundaryType.CONTROL_TO_WORKLOAD,
            source=role.address,
            target=workload.address,
            description="role credentials are projected into the workload",
            rationale="lambda execution role attachment",
        )
        context = RuleEvaluationContext(
            inventory=ResourceInventory(provider="aws", resources=[role, workload]),
            boundary_index={(boundary.boundary_type, boundary.source, boundary.target): boundary},
            rule_registry=RuleRegistry([]),
        )

        findings = self.detectors.detect_workload_role_sensitive_permissions(
            context,
            "aws-workload-role-sensitive-permissions",
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = _evidence_by_key(finding)
        self.assertEqual(finding.rule_id, "aws-workload-role-sensitive-permissions")
        self.assertEqual(finding.title, "Workload role carries sensitive permissions")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(
            finding.affected_resources,
            ["aws_lambda_function.worker", "aws_iam_role.worker"],
        )
        self.assertEqual(finding.trust_boundary_id, "control-to-worker")
        self.assertEqual(evidence["iam_actions"], ["secretsmanager:GetSecretValue"])
        self.assertEqual(
            evidence["policy_statements"],
            [
                "Allow actions=[secretsmanager:GetSecretValue] "
                "resources=[arn:aws:secretsmanager:us-east-1:111122223333:secret:customer]"
            ],
        )
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["lambda function URL is public"],
        )


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


if __name__ == "__main__":
    unittest.main()
