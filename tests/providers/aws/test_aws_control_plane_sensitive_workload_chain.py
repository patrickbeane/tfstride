from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import (
    BoundaryType,
    IAMPolicyCondition,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
)

_ACCOUNT = "111122223333"
_FOREIGN_PRINCIPAL = "arn:aws:iam::444455556666:role/deployer"
_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT}:role/runtime"
_WORKLOAD_ARN = f"arn:aws:lambda:us-east-1:{_ACCOUNT}:function:worker"
_SECRET_ARN = f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT}:secret:data"
_CHAIN_RULE = "aws-control-plane-sensitive-workload-chain"


def _role(
    *,
    assumed: bool = True,
    data_authority: bool = True,
    control_resource: str | None = None,
    control_condition: bool = False,
    deny_control: bool = False,
    policy_complete: bool = True,
    permissions_boundary_state: str = "not_configured",
) -> NormalizedResource:
    statements: list[IAMPolicyStatement] = []
    if data_authority:
        statements.append(
            IAMPolicyStatement(
                effect="Allow",
                actions=["secretsmanager:GetSecretValue"],
                resources=[_SECRET_ARN],
            )
        )
    if control_resource is not None:
        statements.append(
            IAMPolicyStatement(
                effect="Allow",
                actions=["lambda:UpdateFunctionCode"],
                resources=[control_resource],
                conditions=(
                    [IAMPolicyCondition(operator="StringEquals", key="aws:RequestedRegion", values=["us-east-1"])]
                    if control_condition
                    else []
                ),
            )
        )
    if deny_control:
        statements.append(
            IAMPolicyStatement(
                effect="Deny",
                actions=["lambda:UpdateFunctionCode"],
                resources=[_WORKLOAD_ARN],
            )
        )
    return NormalizedResource(
        address="aws_iam_role.runtime",
        provider="aws",
        resource_type="aws_iam_role",
        name="runtime",
        category=ResourceCategory.IAM,
        arn=_ROLE_ARN,
        policy_statements=tuple(statements),
        metadata={
            "trust_statements": (
                [
                    {
                        "principals": [_FOREIGN_PRINCIPAL],
                        "principal_entries": [{"kind": "AWS", "value": _FOREIGN_PRINCIPAL}],
                        "narrowing_condition_keys": [],
                        "narrowing_conditions": [],
                        "has_narrowing_conditions": False,
                    }
                ]
                if assumed
                else []
            ),
            "iam_policy_completeness_state": "complete" if policy_complete else "unknown",
            "iam_permissions_boundary_state": permissions_boundary_state,
        },
    )


def _workload(*, attached: bool = True) -> NormalizedResource:
    return NormalizedResource(
        address="aws_lambda_function.worker",
        provider="aws",
        resource_type="aws_lambda_function",
        name="worker",
        category=ResourceCategory.COMPUTE,
        arn=_WORKLOAD_ARN,
        attached_role_arns=(_ROLE_ARN,) if attached else (),
    )


def _secret() -> NormalizedResource:
    return NormalizedResource(
        address="aws_secretsmanager_secret.data",
        provider="aws",
        resource_type="aws_secretsmanager_secret",
        name="data",
        category=ResourceCategory.DATA,
        arn=_SECRET_ARN,
        data_sensitivity="sensitive",
    )


def _evaluate(
    role: NormalizedResource,
    workload: NormalizedResource,
    *,
    rule_ids: frozenset[str] = frozenset({_CHAIN_RULE}),
):
    inventory = ResourceInventory(provider="aws", resources=[role, workload, _secret()])
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )
    return findings, boundaries


class AwsControlPlaneSensitiveWorkloadChainTests(unittest.TestCase):
    def test_role_attachment_describes_inherited_identity_without_claiming_control(self) -> None:
        _, boundaries = _evaluate(_role(), _workload())

        boundary = next(
            boundary for boundary in boundaries if boundary.boundary_type == BoundaryType.CONTROL_TO_WORKLOAD
        )

        self.assertEqual(
            boundary.identifier,
            "admin-to-workload-plane:aws_iam_role.runtime->aws_lambda_function.worker",
        )
        self.assertEqual(
            boundary.description,
            "aws_lambda_function.worker uses aws_iam_role.runtime as its runtime identity.",
        )
        self.assertIn("inherits permissions", boundary.rationale)
        self.assertIn("does not establish authority", boundary.rationale)

    def test_attachment_and_assumption_without_workload_authority_preserve_separate_findings(self) -> None:
        findings, _ = _evaluate(
            _role(),
            _workload(),
            rule_ids=frozenset(
                {
                    _CHAIN_RULE,
                    "aws-role-trust-expansion",
                    "aws-workload-role-sensitive-permissions",
                }
            ),
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertNotIn(_CHAIN_RULE, findings_by_rule)
        self.assertIn("aws-role-trust-expansion", findings_by_rule)
        self.assertIn("aws-workload-role-sensitive-permissions", findings_by_rule)

    def test_chain_requires_attachment_assumption_modification_and_data_authority(self) -> None:
        cases = (
            ("complete chain", _role(control_resource=_WORKLOAD_ARN), _workload(), True),
            ("no attachment", _role(control_resource=_WORKLOAD_ARN), _workload(attached=False), False),
            ("no assumption", _role(assumed=False, control_resource=_WORKLOAD_ARN), _workload(), False),
            ("no workload modification", _role(), _workload(), False),
            (
                "no resource authorization",
                _role(data_authority=False, control_resource=_WORKLOAD_ARN),
                _workload(),
                False,
            ),
        )

        for name, role, workload, expected in cases:
            with self.subTest(case=name):
                findings, _ = _evaluate(role, workload)

                self.assertEqual(any(finding.rule_id == _CHAIN_RULE for finding in findings), expected)

    def test_control_authority_requires_applicable_unconditional_effective_policy(self) -> None:
        cases = (
            ("wildcard resource", _role(control_resource="*"), True),
            ("different workload", _role(control_resource=f"{_WORKLOAD_ARN}-other"), False),
            ("conditional allow", _role(control_resource=_WORKLOAD_ARN, control_condition=True), False),
            ("explicit deny", _role(control_resource=_WORKLOAD_ARN, deny_control=True), False),
            ("incomplete policy", _role(control_resource=_WORKLOAD_ARN, policy_complete=False), False),
            (
                "unresolved permissions boundary",
                _role(control_resource=_WORKLOAD_ARN, permissions_boundary_state="configured"),
                False,
            ),
        )

        for name, role, expected in cases:
            with self.subTest(case=name):
                findings, _ = _evaluate(role, _workload())

                self.assertEqual(any(finding.rule_id == _CHAIN_RULE for finding in findings), expected)

    def test_positive_chain_explains_workload_control_authority(self) -> None:
        findings, _ = _evaluate(_role(control_resource=_WORKLOAD_ARN), _workload())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["workload_control_authority"],
            [
                "workload=aws_lambda_function.worker; operation=lambda:UpdateFunctionCode; "
                "statements=Allow actions=[lambda:UpdateFunctionCode] "
                f"resources=[{_WORKLOAD_ARN}]"
            ],
        )
        self.assertIn(
            "aws_iam_role.runtime can operate aws_lambda_function.worker with lambda:UpdateFunctionCode",
            evidence["control_path"],
        )


if __name__ == "__main__":
    unittest.main()
