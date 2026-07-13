from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_HTTP_RULE = "aws-cloudfront-viewer-http-allowed"
_TLS_RULE = "aws-cloudfront-viewer-tls-policy-weak-or-unknown"
_WAF_RULE = "aws-public-cloudfront-waf-missing"
_LOGGING_RULE = "aws-cloudfront-access-logging-not-configured"
_ALL_RULE_IDS = (_HTTP_RULE, _TLS_RULE, _LOGGING_RULE, _WAF_RULE)
_DISTRIBUTION_ARN = "arn:aws:cloudfront::111122223333:distribution/E123"
_WEB_ACL_ARN = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/cdn/abc"
_CERTIFICATE_ARN = "arn:aws:acm:us-east-1:111122223333:certificate/cdn"
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


def _distribution(
    *,
    enabled: bool = True,
    default_viewer_protocol_policy: str = "redirect-to-https",
    ordered_cache_behaviors: list[dict[str, Any]] | None = None,
    minimum_protocol_version: object = "TLSv1.2_2021",
    web_acl_id: object = _WEB_ACL_ARN,
    logging_config: object = ({"bucket": "logs.s3.amazonaws.com", "prefix": "cloudfront/", "include_cookies": False},),
    aliases: tuple[str, ...] = ("www.example.com",),
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "E123",
        "arn": _DISTRIBUTION_ARN,
        "comment": "production CDN",
        "domain_name": "d111111abcdef8.cloudfront.net",
        "enabled": enabled,
        "aliases": list(aliases),
        "default_cache_behavior": [
            {
                "target_origin_id": "app",
                "viewer_protocol_policy": default_viewer_protocol_policy,
                "allowed_methods": ["GET", "HEAD"],
                "cached_methods": ["GET", "HEAD"],
            }
        ],
        "viewer_certificate": [
            {
                "cloudfront_default_certificate": False,
                "acm_certificate_arn": _CERTIFICATE_ARN,
                "ssl_support_method": "sni-only",
            }
        ],
    }
    if ordered_cache_behaviors is not None:
        values["ordered_cache_behavior"] = ordered_cache_behaviors
    if minimum_protocol_version is not _MISSING:
        values["viewer_certificate"][0]["minimum_protocol_version"] = minimum_protocol_version
    if web_acl_id is not _MISSING:
        values["web_acl_id"] = web_acl_id
    if logging_config is not _MISSING:
        values["logging_config"] = list(logging_config)
    return _resource(
        "aws_cloudfront_distribution.cdn",
        "aws_cloudfront_distribution",
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


class AwsCloudFrontRuleTests(unittest.TestCase):
    def test_cloudfront_distribution_allow_all_viewer_http_is_detected(self) -> None:
        findings = _findings(
            [_distribution(default_viewer_protocol_policy="allow-all")],
            _HTTP_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_HTTP_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_cloudfront_distribution.cdn"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["viewer_protocol_policy"],
            ["default_cache_behavior viewer_protocol_policy=allow-all"],
        )
        self.assertIn("public_exposure=true", evidence["target_distribution"])
        self.assertIn("CloudFront distribution is enabled", evidence["target_distribution"])

    def test_ordered_cache_behavior_allow_all_viewer_http_is_detected(self) -> None:
        findings = _findings(
            [
                _distribution(
                    ordered_cache_behaviors=[
                        {
                            "path_pattern": "/api/*",
                            "target_origin_id": "api",
                            "viewer_protocol_policy": "allow-all",
                        }
                    ]
                )
            ],
            _HTTP_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_HTTP_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["viewer_protocol_policy"],
            ["ordered_cache_behavior path_pattern=/api/* viewer_protocol_policy=allow-all"],
        )

    def test_https_only_or_redirect_policies_are_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _distribution(
                        ordered_cache_behaviors=[
                            {
                                "path_pattern": "/api/*",
                                "target_origin_id": "api",
                                "viewer_protocol_policy": "https-only",
                            }
                        ]
                    )
                ],
                *_ALL_RULE_IDS,
            ),
            [],
        )

    def test_disabled_cloudfront_distribution_is_quiet(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _distribution(
                        enabled=False,
                        default_viewer_protocol_policy="allow-all",
                        minimum_protocol_version="TLSv1.1_2016",
                        web_acl_id=_MISSING,
                        logging_config=_MISSING,
                    )
                ],
                *_ALL_RULE_IDS,
            ),
            [],
        )

    def test_weak_viewer_tls_policy_is_detected(self) -> None:
        findings = _findings(
            [_distribution(minimum_protocol_version="TLSv1.1_2016")],
            _TLS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TLS_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["viewer_tls_policy"],
            [
                "minimum_protocol_version_state=weak",
                "minimum_protocol_version=TLSv1.1_2016",
                "certificate_source=acm",
                "cloudfront_default_certificate_state=disabled",
                f"acm_certificate_arn={_CERTIFICATE_ARN}",
                "aliases=www.example.com",
            ],
        )

    def test_unknown_viewer_tls_policy_for_alias_is_detected(self) -> None:
        findings = _findings(
            [_distribution(minimum_protocol_version=_MISSING)],
            _TLS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TLS_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["viewer_tls_policy"],
            [
                "minimum_protocol_version_state=unknown",
                "minimum_protocol_version is unset or unknown",
                "certificate_source=acm",
                "cloudfront_default_certificate_state=disabled",
                f"acm_certificate_arn={_CERTIFICATE_ARN}",
                "aliases=www.example.com",
            ],
        )

    def test_unknown_computed_viewer_tls_policy_preserves_uncertainty(self) -> None:
        findings = _findings(
            [
                _distribution(
                    minimum_protocol_version=_MISSING,
                    unknown_values={"viewer_certificate": [{"minimum_protocol_version": True}]},
                )
            ],
            _TLS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TLS_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["posture_uncertainty"],
            ["viewer_certificate.minimum_protocol_version is unknown after planning"],
        )

    def test_public_cloudfront_distribution_without_access_logging_is_detected(self) -> None:
        findings = _findings(
            [_distribution(logging_config=_MISSING)],
            _LOGGING_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_LOGGING_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn("does not configure a standard access-log destination", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["access_logging"],
            ["cloudfront_logging_state=not_configured", "logging_config.bucket is not configured"],
        )

    def test_cloudfront_with_access_logging_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_distribution()], _LOGGING_RULE),
            [],
        )

    def test_unknown_cloudfront_access_logging_does_not_claim_missing_logs(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _distribution(
                        logging_config=_MISSING,
                        unknown_values={"logging_config": [{"bucket": True}]},
                    )
                ],
                _LOGGING_RULE,
            ),
            [],
        )

    def test_public_cloudfront_distribution_without_web_acl_is_detected(self) -> None:
        findings = _findings(
            [_distribution(web_acl_id=_MISSING)],
            _WAF_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_WAF_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["edge_protection_policy"],
            ["edge_protection_state=missing", "web_acl_id is unset"],
        )
        self.assertIn(f"arn={_DISTRIBUTION_ARN}", evidence["target_distribution"])

    def test_cloudfront_with_web_acl_is_quiet(self) -> None:
        self.assertEqual(
            _findings([_distribution()], *_ALL_RULE_IDS),
            [],
        )

    def test_unknown_web_acl_id_does_not_create_missing_waf_finding(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _distribution(
                        web_acl_id=_MISSING,
                        unknown_values={"web_acl_id": True},
                    )
                ],
                _WAF_RULE,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
