from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_MISSING_VPC_FLOW_LOG_RULE = "aws-vpc-flow-logs-not-configured"
_INCOMPLETE_TRAFFIC_RULE = "aws-vpc-flow-log-traffic-type-incomplete"
_MISSING_DESTINATION_RULE = "aws-vpc-flow-log-destination-missing"
_ALL_RULE_IDS = (_MISSING_VPC_FLOW_LOG_RULE, _INCOMPLETE_TRAFFIC_RULE, _MISSING_DESTINATION_RULE)
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


def _vpc(*, name: str = "app", vpc_id: str = "vpc-app") -> TerraformResource:
    return _resource(
        f"aws_vpc.{name}",
        "aws_vpc",
        {
            "id": vpc_id,
            "cidr_block": "10.0.0.0/16",
        },
    )


def _flow_log(
    *,
    name: str = "app",
    flow_log_id: str = "fl-app",
    vpc_id: object = "vpc-app",
    subnet_id: object = _MISSING,
    traffic_type: object = "ALL",
    destination_type: object = "cloud-watch-logs",
    destination: object = _MISSING,
    log_group_name: object = "/aws/vpc-flow-logs/app",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": flow_log_id,
        "iam_role_arn": "arn:aws:iam::111122223333:role/vpc-flow-logs",
    }
    if vpc_id is not _MISSING:
        values["vpc_id"] = vpc_id
    if subnet_id is not _MISSING:
        values["subnet_id"] = subnet_id
    if traffic_type is not _MISSING:
        values["traffic_type"] = traffic_type
    if destination_type is not _MISSING:
        values["log_destination_type"] = destination_type
    if destination is not _MISSING:
        values["log_destination"] = destination
    if log_group_name is not _MISSING:
        values["log_group_name"] = log_group_name
    return _resource(
        f"aws_flow_log.{name}",
        "aws_flow_log",
        values,
        unknown_values=unknown_values,
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsNetworkTelemetryRuleTests(unittest.TestCase):
    def test_vpc_without_resolved_flow_logs_is_detected(self) -> None:
        findings = _findings([_vpc()], _MISSING_VPC_FLOW_LOG_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_VPC_FLOW_LOG_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(findings[0].affected_resources, ["aws_vpc.app"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["flow_log_coverage"],
            [
                "target_vpc_id=vpc-app",
                "resolved_vpc_flow_log_count=0",
                "aws_flow_log resources are not modeled",
            ],
        )

    def test_vpc_flow_log_with_all_traffic_and_destination_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_vpc(), _flow_log()], *_ALL_RULE_IDS),
            [],
        )

    def test_subnet_flow_log_does_not_count_as_vpc_level_coverage(self) -> None:
        findings = _findings(
            [_vpc(), _flow_log(vpc_id=_MISSING, subnet_id="subnet-private")],
            _MISSING_VPC_FLOW_LOG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_VPC_FLOW_LOG_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn(
            "flow_log=aws_flow_log.app; target_type=subnet; target_id=subnet-private",
            evidence["flow_log_coverage"],
        )

    def test_unresolved_flow_log_target_does_not_create_false_missing_vpc_finding(self) -> None:
        findings = _findings(
            [
                _vpc(),
                _flow_log(vpc_id=_MISSING, unknown_values={"vpc_id": True}),
            ],
            _MISSING_VPC_FLOW_LOG_RULE,
        )

        self.assertEqual(findings, [])

    def test_flow_log_with_reject_only_traffic_is_detected(self) -> None:
        findings = _findings([_vpc(), _flow_log(traffic_type="REJECT")], _INCOMPLETE_TRAFFIC_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_INCOMPLETE_TRAFFIC_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["traffic_capture"],
            ["traffic_type=REJECT", "Flow Log does not capture both ACCEPT and REJECT traffic"],
        )

    def test_flow_log_with_unknown_traffic_type_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _vpc(),
                _flow_log(traffic_type=_MISSING, unknown_values={"traffic_type": True}),
            ],
            _INCOMPLETE_TRAFFIC_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_INCOMPLETE_TRAFFIC_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["traffic_capture"], ["traffic_type=unknown", "Flow Log traffic_type is unknown"])
        self.assertEqual(evidence["posture_uncertainty"], ["uncertainty=traffic_type is unknown after planning"])

    def test_flow_log_without_destination_is_detected(self) -> None:
        findings = _findings(
            [_vpc(), _flow_log(destination_type="s3", destination=_MISSING, log_group_name=_MISSING)],
            _MISSING_DESTINATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_DESTINATION_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["log_destination"],
            [
                "destination_type=s3",
                "log_destination is unset",
                "log_group_name is unset",
                "iam_role_arn=arn:aws:iam::111122223333:role/vpc-flow-logs",
            ],
        )

    def test_flow_log_with_unknown_destination_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _vpc(),
                _flow_log(
                    destination_type=_MISSING,
                    destination=_MISSING,
                    log_group_name=_MISSING,
                    unknown_values={"log_destination_type": True, "log_destination": True},
                ),
            ],
            _MISSING_DESTINATION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MISSING_DESTINATION_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["posture_uncertainty"],
            [
                "uncertainty=log_destination_type is unknown after planning",
                "uncertainty=log_destination is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
