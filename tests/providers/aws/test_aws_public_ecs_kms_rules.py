from __future__ import annotations

import json
import unittest
from typing import cast

from tests.providers.aws.test_aws_ecs_kms_operation_paths import (
    _EXECUTION_ROLE_ARN,
    _KEY_ARNS,
    _ROOT_ARN,
    _TASK_ROLE_ARN,
    _key,
    _policy,
    _role,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_protected_data_convergence import (
    _aws_resources as _aws_protected_data_resources,
)
from tests.providers.aws.test_aws_kms_encryption_dependencies import (
    _resource as _aws_resource,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _service as _public_service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_DECRYPT_RULE_ID = "aws-public-ecs-kms-decrypt-access"
_SIGNING_RULE_ID = "aws-public-ecs-kms-signing-access"
_RULE_IDS = frozenset({_DECRYPT_RULE_ID, _SIGNING_RULE_ID})


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return _evaluate_inventory(inventory)


def _evaluate_inventory(inventory):
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return inventory, boundaries, findings


def _public_kms_resources(
    *,
    internal: bool = False,
    two_decrypt_keys: bool = False,
) -> list[TerraformResource]:
    return [
        *_public_edge(internal=internal),
        _key(
            "data",
            "ENCRYPT_DECRYPT",
            _policy(
                _statement(
                    "Allow",
                    "kms:Decrypt",
                    "*",
                    principal=_TASK_ROLE_ARN,
                )
            ),
        ),
        _key(
            "signing",
            "ENCRYPT_DECRYPT" if two_decrypt_keys else "SIGN_VERIFY",
            _policy(
                _statement(
                    "Allow",
                    "kms:Decrypt" if two_decrypt_keys else "kms:*",
                    "*",
                    principal=_TASK_ROLE_ARN if two_decrypt_keys else _ROOT_ARN,
                )
            ),
        ),
        _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "kms:Decrypt",
                    _KEY_ARNS["data"],
                    principal=_TASK_ROLE_ARN,
                ),
                _statement(
                    "Allow",
                    "kms:Decrypt" if two_decrypt_keys else "kms:Sign",
                    _KEY_ARNS["signing"],
                    principal=_TASK_ROLE_ARN,
                ),
            ],
        ),
        _task_definition(),
        _public_service(),
    ]


class AwsPublicEcsKmsRuleTests(unittest.TestCase):
    def test_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertTrue(_RULE_IDS <= registered)

    def test_public_service_emits_distinct_decrypt_and_signing_findings(self) -> None:
        _, _, findings = _evaluate(_public_kms_resources())

        self.assertEqual(
            {finding.rule_id for finding in findings},
            _RULE_IDS,
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        decrypt_finding = findings_by_rule[_DECRYPT_RULE_ID]
        signing_finding = findings_by_rule[_SIGNING_RULE_ID]

        self.assertEqual(decrypt_finding.severity.value, "high")
        self.assertEqual(signing_finding.severity.value, "high")
        self.assertEqual(
            decrypt_finding.affected_resources,
            [
                "aws_lb.public",
                "aws_lb_listener.https",
                "aws_lb_target_group.orders",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_kms_key.data",
            ],
        )
        self.assertEqual(
            signing_finding.affected_resources,
            [
                "aws_lb.public",
                "aws_lb_listener.https",
                "aws_lb_target_group.orders",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_kms_key.signing",
            ],
        )
        for finding in (decrypt_finding, signing_finding):
            self.assertEqual(
                finding.trust_boundary_id,
                "internet-to-service:internet->aws_lb.public",
            )
            evidence = {item.key: item.values for item in finding.evidence}
            self.assertEqual(
                evidence["network_path"],
                [
                    "internet reaches aws_lb.public through aws_lb_listener.https (HTTPS TCP 443)",
                    "aws_lb_listener.https forwards through aws_lb_target_group.orders to "
                    "aws_ecs_service.orders container=orders (HTTP TCP 8080)",
                ],
            )
            self.assertEqual(
                evidence["task_definitions"],
                ["address=aws_ecs_task_definition.orders"],
            )
            self.assertIn("address=aws_iam_role.orders_task", evidence["task_roles"][0])
            self.assertIn("role_kind=ecs_task_role", evidence["task_roles"][0])
            self.assertIn("key_address=aws_kms_key.", evidence["kms_operation_paths"][0])
            self.assertIn("authorization_state=allowed", evidence["kms_operation_paths"][0])
            self.assertIn("operation_evaluation=deterministic_allowed", evidence["kms_operation_paths"][0])
            self.assertIn("The KMS key itself is not public", finding.rationale)

        decrypt_evidence = {item.key: item.values for item in decrypt_finding.evidence}
        self.assertIn("operation=kms:Decrypt", decrypt_evidence["kms_operation_paths"][0])
        self.assertIn("authorization_bases=key_policy_direct", decrypt_evidence["kms_operation_paths"][0])
        self.assertIn("information-disclosure potential", decrypt_finding.rationale)
        self.assertIn("useful ciphertext or can disclose plaintext", decrypt_finding.rationale)

        signing_evidence = {item.key: item.values for item in signing_finding.evidence}
        self.assertIn("operation=kms:Sign", signing_evidence["kms_operation_paths"][0])
        self.assertIn("authorization_bases=iam_via_key_policy", signing_evidence["kms_operation_paths"][0])
        self.assertIn("spoofing potential", signing_finding.rationale)
        self.assertIn("valid application-level signature", signing_finding.rationale)

    def test_decrypt_finding_enriches_exact_protected_data_dependency(self) -> None:
        _, _, findings = _evaluate(_aws_protected_data_resources())

        self.assertEqual([finding.rule_id for finding in findings], [_DECRYPT_RULE_ID])
        finding = findings[0]
        self.assertIn("aws_s3_bucket.orders", finding.affected_resources)
        severity_reasoning = finding.severity_reasoning
        assert severity_reasoning is not None
        self.assertEqual(severity_reasoning.blast_radius, 1)
        self.assertIn(
            "The exact decrypt evidence converges with 1 unique KMS-protected S3 resource(s) across "
            "1 unique encryption dependency relationship(s).",
            finding.rationale,
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=1; unique_dependent_resource_count=1; "
            "downstream_dependency_state=resolved_dependents",
        )
        self.assertTrue(
            any("dependent_address=aws_s3_bucket.orders" in value for value in evidence["downstream_dependencies"])
        )

    def test_multiple_protected_data_dependents_raise_decrypt_blast_radius(
        self,
    ) -> None:
        archive_arn = "arn:aws:s3:::archive"
        archive_alias_arn = "arn:aws:kms:us-east-1:111122223333:alias/data"
        resources = _aws_protected_data_resources()
        role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
        inline_policies = cast(
            list[dict[str, object]],
            role.values["inline_policy"],
        )
        policy = inline_policies[0]["policy"]
        assert isinstance(policy, str)
        policy_document = cast(dict[str, object], json.loads(policy))
        statements = cast(list[dict[str, object]], policy_document["Statement"])
        statements.append(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"{archive_arn}/*",
            }
        )
        inline_policies[0]["policy"] = json.dumps(policy_document)
        resources.extend(
            [
                _aws_resource(
                    "aws_s3_bucket",
                    "archive",
                    {
                        "id": "archive",
                        "bucket": "archive",
                        "arn": archive_arn,
                    },
                ),
                _aws_resource(
                    "aws_s3_bucket_server_side_encryption_configuration",
                    "archive",
                    {
                        "id": "archive",
                        "bucket": "archive",
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "sse_algorithm": "aws:kms",
                                        "kms_master_key_id": archive_alias_arn,
                                    }
                                ]
                            }
                        ],
                    },
                ),
            ]
        )

        for resource in resources:
            resource.provider_config_key = "aws"
        _, _, findings = _evaluate(resources)

        finding = findings[0]
        self.assertIn("aws_s3_bucket.orders", finding.affected_resources)
        self.assertIn("aws_s3_bucket.archive", finding.affected_resources)
        severity_reasoning = finding.severity_reasoning
        assert severity_reasoning is not None
        self.assertEqual(severity_reasoning.blast_radius, 2)
        self.assertIn(
            "The exact decrypt evidence converges with 2 unique KMS-protected S3 resource(s) across "
            "2 unique encryption dependency relationship(s).",
            finding.rationale,
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=2; unique_dependent_resource_count=2; "
            "downstream_dependency_state=resolved_dependents",
        )

    def test_stale_protected_data_convergence_does_not_enrich_decrypt_finding(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(_aws_protected_data_resources())
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        convergence = aws_facts(service).ecs_s3_protected_data_convergences[0]
        aws_facts(service).set_ecs_s3_protected_data_convergences(
            [
                {
                    **convergence,
                    "bucket_address": "aws_s3_bucket.missing",
                }
            ]
        )

        _, _, findings = _evaluate_inventory(inventory)
        finding = findings[0]
        self.assertNotIn("aws_s3_bucket.missing", finding.affected_resources)
        severity_reasoning = finding.severity_reasoning
        assert severity_reasoning is not None
        self.assertEqual(severity_reasoning.blast_radius, 1)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "downstream_dependency_state=no_resolved_dependents",
        )

    def test_multiple_decryptable_keys_without_convergence_keep_key_blast_radius(
        self,
    ) -> None:
        _, _, findings = _evaluate(_public_kms_resources(two_decrypt_keys=True))

        finding = next(finding for finding in findings if finding.rule_id == _DECRYPT_RULE_ID)
        severity_reasoning = finding.severity_reasoning
        assert severity_reasoning is not None
        self.assertEqual(severity_reasoning.blast_radius, 2)
        self.assertNotIn("aws_s3_bucket.orders", finding.affected_resources)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["downstream_dependencies"][0],
            "unique_dependency_count=0; unique_dependent_resource_count=0; "
            "downstream_dependency_state=no_resolved_dependents",
        )

    def test_public_mac_generation_emits_spoofing_finding(self) -> None:
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                _key(
                    "mac",
                    "GENERATE_VERIFY_MAC",
                    _policy(
                        _statement(
                            "Allow",
                            "kms:GenerateMac",
                            "*",
                            principal=_TASK_ROLE_ARN,
                        )
                    ),
                ),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "kms:GenerateMac",
                            _KEY_ARNS["mac"],
                            principal=_TASK_ROLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
                _public_service(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SIGNING_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.SPOOFING)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn("operation=kms:GenerateMac", evidence["kms_operation_paths"][0])
        self.assertIn("key_usage=GENERATE_VERIFY_MAC", evidence["kms_operation_paths"][0])
        self.assertIn("message authentication codes", finding.rationale)
        self.assertIn("spoofing potential", finding.rationale)

    def test_private_service_remains_quiet(self) -> None:
        _, _, findings = _evaluate(_public_kms_resources(internal=True))

        self.assertEqual(findings, [])

    def test_denied_conditional_and_execution_role_operations_remain_quiet(self) -> None:
        conditional_allow = _statement(
            "Allow",
            "kms:Decrypt",
            "*",
            principal=_TASK_ROLE_ARN,
        )
        conditional_allow["Condition"] = {
            "StringEquals": {
                "kms:EncryptionContext:service": "orders",
            }
        }
        resources = [
            *_public_edge(),
            _key(
                "data",
                "ENCRYPT_DECRYPT",
                _policy(
                    conditional_allow,
                    _statement(
                        "Deny",
                        "kms:Sign",
                        "*",
                        principal=_TASK_ROLE_ARN,
                    ),
                ),
            ),
            _key(
                "signing",
                "SIGN_VERIFY",
                _policy(
                    _statement(
                        "Allow",
                        "kms:Sign",
                        "*",
                        principal=_EXECUTION_ROLE_ARN,
                    )
                ),
            ),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Decrypt",
                        _KEY_ARNS["data"],
                        principal=_TASK_ROLE_ARN,
                    ),
                    _statement(
                        "Allow",
                        "kms:Sign",
                        _KEY_ARNS["signing"],
                        principal=_TASK_ROLE_ARN,
                    ),
                ],
            ),
            _role(
                "orders_execution",
                _EXECUTION_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "kms:Sign",
                        _KEY_ARNS["signing"],
                        principal=_EXECUTION_ROLE_ARN,
                    )
                ],
            ),
            _task_definition(),
            _public_service(),
        ]

        _, _, findings = _evaluate(resources)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
