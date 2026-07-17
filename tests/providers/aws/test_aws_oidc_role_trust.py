from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.analysis.rule_registry import RuleRegistry
from tfstride.models import Finding, ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.observations import observe_aws_controls
from tfstride.providers.aws.policy_trust_rules import AwsPolicyTrustRuleDetectors
from tfstride.providers.aws.resource_facts import aws_facts

_PROVIDER_ADDRESS = "aws_iam_openid_connect_provider.github"
_PROVIDER_ARN = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
_PROVIDER_URL = "https://token.actions.githubusercontent.com"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _provider(*, arn: str | None = _PROVIDER_ARN, name: str = "github") -> TerraformResource:
    values: dict[str, Any] = {
        "url": _PROVIDER_URL,
        "client_id_list": ["sts.amazonaws.com"],
    }
    if arn is not None:
        values["arn"] = arn
    return _resource("aws_iam_openid_connect_provider", name, values)


def _role(
    principal: str,
    *,
    conditions: dict[str, Any] | None = None,
    action: str = "sts:AssumeRoleWithWebIdentity",
    name: str = "deploy",
) -> TerraformResource:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Action": action,
        "Principal": {"Federated": principal},
    }
    if conditions is not None:
        statement["Condition"] = conditions
    return _resource(
        "aws_iam_role",
        name,
        {
            "name": name,
            "arn": f"arn:aws:iam::111122223333:role/{name}",
            "assume_role_policy": {"Version": "2012-10-17", "Statement": [statement]},
        },
    )


def _context(inventory: ResourceInventory) -> RuleEvaluationContext:
    return RuleEvaluationContext(
        inventory=inventory,
        boundary_index={},
        rule_registry=RuleRegistry([]),
    )


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AwsOidcRoleTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detectors = AwsPolicyTrustRuleDetectors(FindingFactory())

    def test_resolves_terraform_provider_reference_and_reuses_aud_sub_narrowing(self) -> None:
        reference = f"{_PROVIDER_ADDRESS}.arn"
        inventory = AwsNormalizer().normalize(
            [
                _provider(),
                _role(
                    reference,
                    conditions={
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:sub": "repo:example/app:ref:refs/heads/main",
                        }
                    },
                ),
            ]
        )
        role = inventory.get_by_address("aws_iam_role.deploy")
        self.assertIsNotNone(role)
        statement = aws_facts(role).trust_statements[0]

        self.assertEqual(statement["actions"], ["sts:AssumeRoleWithWebIdentity"])
        self.assertEqual(statement["principals"], [_PROVIDER_ARN])
        self.assertEqual(
            statement["principal_entries"],
            [{"kind": "Federated", "value": _PROVIDER_ARN}],
        )
        self.assertEqual(
            statement["resolved_oidc_providers"],
            [
                {
                    "address": _PROVIDER_ADDRESS,
                    "arn": _PROVIDER_ARN,
                    "principal": _PROVIDER_ARN,
                    "reference": reference,
                    "url": _PROVIDER_URL,
                }
            ],
        )
        context = _context(inventory)
        self.assertEqual(
            self.detectors.detect_trust_expansion(context, "aws-role-trust-expansion"),
            [],
        )
        self.assertEqual(
            self.detectors.detect_unconstrained_trust(context, "aws-role-trust-missing-narrowing"),
            [],
        )

        observations = [
            observation
            for observation in observe_aws_controls(inventory)
            if observation.observation_id == "aws-role-trust-narrowed"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(
            observations[0].affected_resources,
            ["aws_iam_role.deploy", _PROVIDER_ADDRESS],
        )

    def test_exact_provider_arn_connection_keeps_existing_trust_rule_ids(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _provider(),
                _role(
                    _PROVIDER_ARN,
                    conditions={
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        }
                    },
                ),
            ]
        )
        context = _context(inventory)

        expansion_findings = self.detectors.detect_trust_expansion(
            context,
            "aws-role-trust-expansion",
        )
        narrowing_findings = self.detectors.detect_unconstrained_trust(
            context,
            "aws-role-trust-missing-narrowing",
        )

        self.assertEqual(len(expansion_findings), 1)
        self.assertEqual(expansion_findings[0].rule_id, "aws-role-trust-expansion")
        self.assertEqual(
            expansion_findings[0].affected_resources,
            ["aws_iam_role.deploy", _PROVIDER_ADDRESS],
        )
        self.assertEqual(
            _evidence_by_key(expansion_findings[0])["trust_provider_resources"],
            [_PROVIDER_ADDRESS],
        )
        self.assertEqual(narrowing_findings, [])

    def test_unresolved_or_non_web_identity_references_do_not_create_connections(self) -> None:
        missing_reference = "aws_iam_openid_connect_provider.missing.arn"
        inventory = AwsNormalizer().normalize(
            [
                _provider(name="github"),
                _role(missing_reference, name="missing"),
                _role(
                    f"{_PROVIDER_ADDRESS}.arn",
                    action="sts:AssumeRoleWithSAML",
                    name="wrong_action",
                ),
            ]
        )

        missing_role = inventory.get_by_address("aws_iam_role.missing")
        wrong_action_role = inventory.get_by_address("aws_iam_role.wrong_action")
        self.assertIsNotNone(missing_role)
        self.assertIsNotNone(wrong_action_role)

        missing_statement = aws_facts(missing_role).trust_statements[0]
        self.assertEqual(
            missing_statement["unresolved_oidc_provider_references"],
            [missing_reference],
        )
        self.assertNotIn("resolved_oidc_providers", missing_statement)

        wrong_action_statement = aws_facts(wrong_action_role).trust_statements[0]
        self.assertEqual(wrong_action_statement["principals"], [f"{_PROVIDER_ADDRESS}.arn"])
        self.assertNotIn("resolved_oidc_providers", wrong_action_statement)

    def test_known_provider_url_preserves_narrowing_when_provider_arn_is_unresolved(self) -> None:
        reference = f"{_PROVIDER_ADDRESS}.arn"
        inventory = AwsNormalizer().normalize(
            [
                _provider(arn=None),
                _role(
                    reference,
                    conditions={
                        "StringEquals": {
                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                            "token.actions.githubusercontent.com:sub": "repo:example/app:*",
                        }
                    },
                ),
            ]
        )
        role = inventory.get_by_address("aws_iam_role.deploy")
        self.assertIsNotNone(role)
        statement = aws_facts(role).trust_statements[0]

        self.assertEqual(statement["principals"], [reference])
        self.assertEqual(statement["unresolved_oidc_provider_references"], [reference])
        self.assertEqual(statement["resolved_oidc_providers"][0]["address"], _PROVIDER_ADDRESS)
        context = _context(inventory)
        self.assertEqual(
            self.detectors.detect_trust_expansion(context, "aws-role-trust-expansion"),
            [],
        )
        self.assertEqual(
            self.detectors.detect_unconstrained_trust(context, "aws-role-trust-missing-narrowing"),
            [],
        )

    def test_resolves_exact_interpolation_wrapper(self) -> None:
        reference = "$" + "{" + f"{_PROVIDER_ADDRESS}.arn" + "}"
        inventory = AwsNormalizer().normalize([_provider(), _role(reference)])
        role = inventory.get_by_address("aws_iam_role.deploy")
        self.assertIsNotNone(role)

        statement = aws_facts(role).trust_statements[0]
        self.assertEqual(statement["principals"], [_PROVIDER_ARN])
        self.assertEqual(statement["resolved_oidc_providers"][0]["reference"], reference)


if __name__ == "__main__":
    unittest.main()
