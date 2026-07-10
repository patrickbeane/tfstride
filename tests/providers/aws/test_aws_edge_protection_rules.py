from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_RULE_ID = "aws-public-alb-waf-missing"
_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
_OTHER_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/api/def"
_WEB_ACL_ARN = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/app-edge/abc"
_MISSING = object()


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _load_balancer(
    *,
    arn: str = _LOAD_BALANCER_ARN,
    internal: bool = False,
    load_balancer_type: object = "application",
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "app/web/abc",
        "arn": arn,
        "internal": internal,
    }
    if load_balancer_type is not _MISSING:
        values["load_balancer_type"] = load_balancer_type
    return _resource("aws_lb.web", "aws_lb", values)


def _web_acl_association(
    *,
    resource_arn: object = _LOAD_BALANCER_ARN,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"{_WEB_ACL_ARN},{_LOAD_BALANCER_ARN}",
        "web_acl_arn": _WEB_ACL_ARN,
    }
    if resource_arn is not _MISSING:
        values["resource_arn"] = resource_arn
    return _resource(
        "aws_wafv2_web_acl_association.alb",
        "aws_wafv2_web_acl_association",
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsEdgeProtectionRuleTests(unittest.TestCase):
    def test_public_application_load_balancer_without_waf_association_is_detected(self) -> None:
        findings = _findings([_load_balancer()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_lb.web"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["waf_association_coverage"],
            [
                f"target_resource_arn={_LOAD_BALANCER_ARN}",
                "resolved_web_acl_association_count=0",
                "modeled_web_acl_association_count=0",
            ],
        )
        self.assertIn("load_balancer_type=application", evidence["target_load_balancer"])
        self.assertIn("public_exposure=true", evidence["target_load_balancer"])

    def test_public_application_load_balancer_with_resolved_waf_association_is_quiet(self) -> None:
        self.assertEqual(_findings([_load_balancer(), _web_acl_association()]), [])

    def test_waf_association_for_another_load_balancer_does_not_cover_target(self) -> None:
        findings = _findings([_load_balancer(), _web_acl_association(resource_arn=_OTHER_LOAD_BALANCER_ARN)])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["waf_association_coverage"],
            [
                f"target_resource_arn={_LOAD_BALANCER_ARN}",
                "resolved_web_acl_association_count=0",
                "modeled_web_acl_association_count=1",
                f"nonmatching_association_target={_OTHER_LOAD_BALANCER_ARN}",
            ],
        )

    def test_internal_or_non_application_load_balancer_is_quiet(self) -> None:
        self.assertEqual(_findings([_load_balancer(internal=True)]), [])
        self.assertEqual(_findings([_load_balancer(load_balancer_type="network")]), [])
        self.assertEqual(_findings([_load_balancer(load_balancer_type=_MISSING)]), [])

    def test_unknown_waf_association_target_does_not_create_missing_waf_finding(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _load_balancer(),
                    _web_acl_association(
                        resource_arn=_MISSING,
                        unknown_values={"resource_arn": True},
                    ),
                ]
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
