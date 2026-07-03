from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_HTTP_RULE = "aws-load-balancer-http-public-listener"
_CERTIFICATE_RULE = "aws-load-balancer-listener-tls-certificate-missing"
_SSL_POLICY_RULE = "aws-load-balancer-listener-ssl-policy-weak-or-unknown"
_ALL_RULE_IDS = (_HTTP_RULE, _CERTIFICATE_RULE, _SSL_POLICY_RULE)
_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
_LISTENER_ARN = f"{_LOAD_BALANCER_ARN}/listener/443"
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


def _load_balancer(*, internal: bool = False) -> TerraformResource:
    return _resource(
        "aws_lb.web",
        "aws_lb",
        {
            "id": "app/web/abc",
            "arn": _LOAD_BALANCER_ARN,
            "internal": internal,
            "load_balancer_type": "application",
        },
    )


def _listener(
    *,
    protocol: object = "HTTPS",
    certificate_arn: object = "arn:aws:acm:us-east-1:111122223333:certificate/listener",
    ssl_policy: object = "ELBSecurityPolicy-TLS13-1-2-2021-06",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": _LISTENER_ARN,
        "arn": _LISTENER_ARN,
        "load_balancer_arn": _LOAD_BALANCER_ARN,
        "port": 443,
    }
    if protocol is not _MISSING:
        values["protocol"] = protocol
    if certificate_arn is not _MISSING:
        values["certificate_arn"] = certificate_arn
    if ssl_policy is not _MISSING:
        values["ssl_policy"] = ssl_policy
    return _resource(
        "aws_lb_listener.https",
        "aws_lb_listener",
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


class AwsLoadBalancerListenerTlsRuleTests(unittest.TestCase):
    def test_public_http_listener_is_detected(self) -> None:
        findings = _findings(
            [_load_balancer(), _listener(protocol="HTTP", certificate_arn=_MISSING, ssl_policy=_MISSING)],
            _HTTP_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_HTTP_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_lb_listener.https", "aws_lb.web"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["listener_transport"],
            ["protocol=HTTP", "HTTP listener does not terminate TLS"],
        )
        self.assertIn("public_exposure=true", evidence["load_balancer_exposure"])

    def test_internal_http_listener_is_not_flagged(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _load_balancer(internal=True),
                    _listener(protocol="HTTP", certificate_arn=_MISSING, ssl_policy=_MISSING),
                ],
                *_ALL_RULE_IDS,
            ),
            [],
        )

    def test_public_tls_listener_without_certificate_is_detected(self) -> None:
        findings = _findings(
            [_load_balancer(), _listener(protocol="HTTPS", certificate_arn=_MISSING)],
            _CERTIFICATE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_CERTIFICATE_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["certificate_posture"], ["certificate_arn is unset"])

    def test_public_tls_listener_with_unknown_certificate_is_reported_as_uncertain(self) -> None:
        findings = _findings(
            [
                _load_balancer(),
                _listener(
                    protocol="HTTPS",
                    certificate_arn=_MISSING,
                    unknown_values={"certificate_arn": True},
                ),
            ],
            _CERTIFICATE_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_CERTIFICATE_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["certificate_posture"],
            ["certificate_arn is unset", "certificate_arn is unknown after planning"],
        )
        self.assertEqual(evidence["posture_uncertainty"], ["certificate_arn is unknown after planning"])

    def test_public_tls_listener_with_weak_ssl_policy_is_detected(self) -> None:
        findings = _findings(
            [_load_balancer(), _listener(ssl_policy="ELBSecurityPolicy-2016-08")],
            _SSL_POLICY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SSL_POLICY_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["ssl_policy_posture"],
            ["ssl_policy_state=weak", "ssl_policy=ELBSecurityPolicy-2016-08"],
        )

    def test_public_tls_listener_with_unknown_ssl_policy_is_detected(self) -> None:
        findings = _findings(
            [
                _load_balancer(),
                _listener(
                    ssl_policy=_MISSING,
                    unknown_values={"ssl_policy": True},
                ),
            ],
            _SSL_POLICY_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SSL_POLICY_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["ssl_policy_posture"],
            ["ssl_policy_state=unknown", "ssl_policy is unset or unknown", "ssl_policy is unknown after planning"],
        )
        self.assertEqual(evidence["posture_uncertainty"], ["ssl_policy is unknown after planning"])

    def test_public_tls_listener_with_modern_policy_and_certificate_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_load_balancer(), _listener()], *_ALL_RULE_IDS),
            [],
        )


if __name__ == "__main__":
    unittest.main()
