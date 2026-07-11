from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_CORS_RULE = "aws-api-gateway-cors-permissive"
_WAF_RULE = "aws-public-api-gateway-waf-missing"
_ALL_RULE_IDS = (_CORS_RULE, _WAF_RULE)
_REST_EXECUTION_ARN = "arn:aws:execute-api:us-east-1:111122223333:rest123"
_V2_EXECUTION_ARN = "arn:aws:execute-api:us-east-1:111122223333:v2abc"
_V2_ENDPOINT = "https://v2abc.execute-api.us-east-1.amazonaws.com"
_REST_STAGE_ARN = "arn:aws:apigateway:us-east-1:111122223333::/restapis/rest123/stages/prod"
_V2_STAGE_ARN = "arn:aws:apigateway:us-east-1:111122223333::/apis/v2abc/stages/prod"
_WEB_ACL_ARN = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/edge/abc"
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


def _rest_api(
    *,
    api_id: str = "rest123",
    name: str = "orders",
    endpoint_types: tuple[str, ...] | object = ("REGIONAL",),
    vpc_endpoint_ids: tuple[str, ...] | object = (),
    disable_execute_api_endpoint: bool = False,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": api_id,
        "name": name,
        "execution_arn": _REST_EXECUTION_ARN,
        "disable_execute_api_endpoint": disable_execute_api_endpoint,
    }
    if endpoint_types is not _MISSING:
        values["endpoint_configuration"] = [
            {
                "types": list(endpoint_types),  # type: ignore[arg-type]
                "vpc_endpoint_ids": list(vpc_endpoint_ids),  # type: ignore[arg-type]
            }
        ]
    return _resource("aws_api_gateway_rest_api.orders", "aws_api_gateway_rest_api", values)


def _v2_api(
    *,
    api_id: str = "v2abc",
    name: str = "orders-http",
    protocol_type: str = "HTTP",
    api_endpoint: str | object = _V2_ENDPOINT,
    disable_execute_api_endpoint: bool = False,
    cors_configuration: dict[str, Any] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": api_id,
        "name": name,
        "protocol_type": protocol_type,
        "execution_arn": _V2_EXECUTION_ARN,
        "disable_execute_api_endpoint": disable_execute_api_endpoint,
    }
    if api_endpoint is not _MISSING:
        values["api_endpoint"] = api_endpoint
    if cors_configuration is not None:
        values["cors_configuration"] = [cors_configuration]
    return _resource(
        "aws_apigatewayv2_api.orders",
        "aws_apigatewayv2_api",
        values,
        unknown_values=unknown_values,
    )


def _wafv2_web_acl_association(
    *,
    resource_arn: object = _V2_STAGE_ARN,
    address: str = "aws_wafv2_web_acl_association.edge",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"web_acl_arn": _WEB_ACL_ARN}
    if resource_arn is not _MISSING:
        values["resource_arn"] = resource_arn
    return _resource(address, "aws_wafv2_web_acl_association", values, unknown_values=unknown_values)


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsApiGatewayRuleTests(unittest.TestCase):
    def test_public_http_api_with_wildcard_cors_is_detected(self) -> None:
        findings = _findings(
            [
                _v2_api(
                    cors_configuration={
                        "allow_origins": ["*"],
                        "allow_methods": ["GET", "POST"],
                        "allow_credentials": False,
                    }
                )
            ],
            _CORS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_CORS_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_apigatewayv2_api.orders"])
        evidence = _evidence_by_key(finding)
        self.assertIn("allow_origins=*", evidence["cors_configuration"])
        self.assertIn("allow_methods=GET, POST", evidence["cors_configuration"])
        self.assertIn("api_id=v2abc", evidence["target_endpoint"])
        self.assertIn("protocol_type=HTTP", evidence["target_endpoint"])
        self.assertIn("public_endpoint_state=enabled", evidence["target_endpoint"])
        self.assertIn("public_exposure=true", evidence["target_endpoint"])

    def test_public_http_api_with_reviewed_origins_is_quiet_for_cors(self) -> None:
        self.assertEqual(
            _findings(
                [_v2_api(cors_configuration={"allow_origins": ["https://example.com"]})],
                _CORS_RULE,
            ),
            [],
        )

    def test_public_http_api_without_cors_configuration_is_quiet_for_cors(self) -> None:
        self.assertEqual(
            _findings([_v2_api()], _CORS_RULE),
            [],
        )

    def test_websocket_v2_api_is_quiet_for_cors(self) -> None:
        self.assertEqual(
            _findings(
                [_v2_api(protocol_type="WEBSOCKET", api_endpoint=None, cors_configuration={"allow_origins": ["*"]})],
                _CORS_RULE,
            ),
            [],
        )

    def test_private_v2_api_is_quiet_for_cors(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _v2_api(
                        api_endpoint=None,
                        disable_execute_api_endpoint=True,
                        cors_configuration={"allow_origins": ["*"]},
                    )
                ],
                _CORS_RULE,
            ),
            [],
        )

    def test_rest_api_is_quiet_for_cors(self) -> None:
        self.assertEqual(
            _findings([_rest_api()], _CORS_RULE),
            [],
        )

    def test_public_rest_api_without_waf_is_detected(self) -> None:
        findings = _findings([_rest_api()], _WAF_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_WAF_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_api_gateway_rest_api.orders"])
        evidence = _evidence_by_key(finding)
        self.assertIn("api_id=rest123", evidence["target_endpoint"])
        self.assertIn(f"arn={_REST_EXECUTION_ARN}", evidence["target_endpoint"])
        self.assertIn("endpoint_types=REGIONAL", evidence["target_endpoint"])
        self.assertEqual(
            evidence["waf_association_coverage"],
            ["target_api_id=rest123", "resolved_web_acl_association_count=0", "modeled_web_acl_association_count=0"],
        )

    def test_public_v2_api_without_waf_is_detected(self) -> None:
        findings = _findings([_v2_api()], _WAF_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_WAF_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["waf_association_coverage"][0], "target_api_id=v2abc")

    def test_public_v2_api_with_matching_stage_arn_waf_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_v2_api(), _wafv2_web_acl_association(resource_arn=_V2_STAGE_ARN)], *_ALL_RULE_IDS),
            [],
        )

    def test_public_rest_api_with_matching_execute_api_arn_waf_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [_rest_api(), _wafv2_web_acl_association(resource_arn=_REST_EXECUTION_ARN)],
                _WAF_RULE,
            ),
            [],
        )

    def test_public_api_with_nonmatching_waf_association_is_detected(self) -> None:
        findings = _findings(
            [_v2_api(), _wafv2_web_acl_association(resource_arn=_REST_STAGE_ARN)],
            _WAF_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_WAF_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("modeled_web_acl_association_count=1", evidence["waf_association_coverage"])
        self.assertIn(f"nonmatching_association_target={_REST_STAGE_ARN}", evidence["waf_association_coverage"])

    def test_public_v2_api_with_reviewed_cors_and_waf_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _v2_api(cors_configuration={"allow_origins": ["https://example.com"]}),
                    _wafv2_web_acl_association(resource_arn=_V2_STAGE_ARN),
                ],
                *_ALL_RULE_IDS,
            ),
            [],
        )

    def test_private_rest_api_is_quiet_for_waf(self) -> None:
        self.assertEqual(
            _findings(
                [_rest_api(endpoint_types=("PRIVATE",), vpc_endpoint_ids=("vpce-1",))],
                _WAF_RULE,
            ),
            [],
        )

    def test_unknown_public_endpoint_state_is_not_reported_for_waf(self) -> None:
        self.assertEqual(
            _findings(
                [_v2_api(api_endpoint=_MISSING, unknown_values={"disable_execute_api_endpoint": True})],
                _WAF_RULE,
            ),
            [],
        )

    def test_unresolved_waf_association_target_suppresses_waf_findings(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _v2_api(),
                    _wafv2_web_acl_association(
                        resource_arn=_MISSING,
                        unknown_values={"resource_arn": True},
                    ),
                ],
                _WAF_RULE,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
