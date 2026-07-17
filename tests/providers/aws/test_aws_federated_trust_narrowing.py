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
_FOREIGN_PROVIDER_ADDRESS = "aws_iam_openid_connect_provider.foreign"
_FOREIGN_PROVIDER_ARN = "arn:aws:iam::444455556666:oidc-provider/token.actions.githubusercontent.com"


def _resource(resource_type: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _provider(
    *,
    arn: str,
    name: str = "github",
    url: str = _PROVIDER_URL,
) -> TerraformResource:
    return _resource(
        "aws_iam_openid_connect_provider",
        name,
        {
            "url": url,
            "arn": arn,
            "client_id_list": ["sts.amazonaws.com"],
        },
    )


def _role(
    principal: str,
    *,
    conditions: dict[str, Any] | None = None,
    name: str = "deploy",
) -> TerraformResource:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Action": "sts:AssumeRoleWithWebIdentity",
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
            "assume_role_policy": {
                "Version": "2012-10-17",
                "Statement": [statement],
            },
        },
    )


def _conditions(issuer: str, *, include_subject: bool = True) -> dict[str, Any]:
    values: dict[str, Any] = {
        f"{issuer}:aud": "sts.amazonaws.com",
    }
    if include_subject:
        values[f"{issuer}:sub"] = "repo:example/app:*"
    return {"StringEquals": values}


def _inventory(*resources: TerraformResource) -> ResourceInventory:
    return AwsNormalizer().normalize(list(resources))


def _context(inventory: ResourceInventory) -> RuleEvaluationContext:
    return RuleEvaluationContext(
        inventory=inventory,
        boundary_index={},
        rule_registry=RuleRegistry([]),
    )


def _findings(inventory: ResourceInventory) -> tuple[list[Finding], list[Finding]]:
    detectors = AwsPolicyTrustRuleDetectors(FindingFactory())
    context = _context(inventory)
    return (
        detectors.detect_trust_expansion(context, "aws-role-trust-expansion"),
        detectors.detect_unconstrained_trust(context, "aws-role-trust-missing-narrowing"),
    )


def _evidence_by_key(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


class AwsFederatedTrustNarrowingTests(unittest.TestCase):
    def test_narrowed_oidc_trust_is_quiet_and_observed(self) -> None:
        inventory = _inventory(
            _provider(arn=_PROVIDER_ARN),
            _role(_PROVIDER_ARN, conditions=_conditions("token.actions.githubusercontent.com")),
        )

        expansion_findings, unconstrained_findings = _findings(inventory)

        self.assertEqual(expansion_findings, [])
        self.assertEqual(unconstrained_findings, [])
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
        evidence = _evidence_by_key(observations[0])
        self.assertEqual(evidence["trust_provider_resources"], [_PROVIDER_ADDRESS])
        self.assertEqual(
            evidence["trust_narrowing"],
            [
                "supported narrowing conditions present: true",
                "supported narrowing condition keys: "
                "token.actions.githubusercontent.com:aud, "
                "token.actions.githubusercontent.com:sub",
            ],
        )

    def test_broad_oidc_trust_emits_the_existing_expansion_and_narrowing_rules(self) -> None:
        inventory = _inventory(
            _provider(arn=_PROVIDER_ARN),
            _role(_PROVIDER_ARN),
        )

        expansion_findings, unconstrained_findings = _findings(inventory)

        self.assertEqual([finding.rule_id for finding in expansion_findings], ["aws-role-trust-expansion"])
        self.assertEqual(
            [finding.rule_id for finding in unconstrained_findings],
            ["aws-role-trust-missing-narrowing"],
        )
        for finding in (*expansion_findings, *unconstrained_findings):
            self.assertEqual(
                finding.affected_resources,
                ["aws_iam_role.deploy", _PROVIDER_ADDRESS],
            )
            self.assertEqual(
                _evidence_by_key(finding)["trust_provider_resources"],
                [_PROVIDER_ADDRESS],
            )

    def test_foreign_account_oidc_trust_preserves_foreign_scope_evidence(self) -> None:
        inventory = _inventory(
            _role(_FOREIGN_PROVIDER_ARN, name="foreign_deploy"),
            _provider(arn=_FOREIGN_PROVIDER_ARN, name="foreign"),
        )

        expansion_findings, unconstrained_findings = _findings(inventory)

        self.assertEqual(len(expansion_findings), 1)
        self.assertEqual(len(unconstrained_findings), 1)
        self.assertEqual(
            _evidence_by_key(expansion_findings[0])["trust_path"],
            ["trust principal is OIDC identity provider in foreign account 444455556666"],
        )
        self.assertEqual(
            _evidence_by_key(unconstrained_findings[0])["trust_scope"],
            ["OIDC identity provider belongs to foreign account 444455556666"],
        )
        self.assertEqual(
            expansion_findings[0].affected_resources,
            ["aws_iam_role.foreign_deploy", _FOREIGN_PROVIDER_ADDRESS],
        )

    def test_unresolved_provider_reference_preserves_existing_uncertain_trust_findings(self) -> None:
        missing_reference = "aws_iam_openid_connect_provider.missing.arn"
        inventory = _inventory(
            _provider(arn=_PROVIDER_ARN),
            _role(missing_reference, name="unresolved"),
        )

        expansion_findings, unconstrained_findings = _findings(inventory)
        role = inventory.get_by_address("aws_iam_role.unresolved")

        self.assertIsNotNone(role)
        self.assertEqual(len(expansion_findings), 1)
        self.assertEqual(len(unconstrained_findings), 1)
        self.assertEqual(expansion_findings[0].affected_resources, ["aws_iam_role.unresolved"])
        self.assertEqual(unconstrained_findings[0].affected_resources, ["aws_iam_role.unresolved"])
        self.assertNotIn("trust_provider_resources", _evidence_by_key(expansion_findings[0]))
        self.assertEqual(
            aws_facts(role).trust_statements[0]["unresolved_oidc_provider_references"],
            [missing_reference],
        )

    def test_mismatched_issuer_conditions_do_not_suppress_existing_trust_findings(self) -> None:
        inventory = _inventory(
            _provider(arn=_PROVIDER_ARN),
            _role(
                f"{_PROVIDER_ADDRESS}.arn",
                conditions=_conditions("other-issuer.example.com"),
                name="mismatched",
            ),
        )

        expansion_findings, unconstrained_findings = _findings(inventory)

        self.assertEqual([finding.rule_id for finding in expansion_findings], ["aws-role-trust-expansion"])
        self.assertEqual(
            [finding.rule_id for finding in unconstrained_findings],
            ["aws-role-trust-missing-narrowing"],
        )
        self.assertEqual(
            _evidence_by_key(unconstrained_findings[0])["trust_narrowing"],
            [
                "supported narrowing conditions present: false",
                "supported narrowing condition keys: none",
            ],
        )
        self.assertEqual(
            unconstrained_findings[0].affected_resources,
            ["aws_iam_role.mismatched", _PROVIDER_ADDRESS],
        )


if __name__ == "__main__":
    unittest.main()
