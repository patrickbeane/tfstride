from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_secret_management_paths import (
    _task_definition,
)
from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _SECRET_ARN,
    _resource,
    _role,
    _secret,
    _statement,
    _unresolved_attachment,
)
from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _aws_ecs_service,
    _aws_public_edge,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_TAMPERING_RULE_ID = "aws-public-ecs-secret-tampering"
_DISRUPTION_RULE_ID = "aws-public-ecs-secret-disruption"
_RULE_IDS = frozenset({_TAMPERING_RULE_ID, _DISRUPTION_RULE_ID})
_TAMPERING_OPERATIONS = (
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
)


def _evaluate_inventory(inventory):
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=_RULE_IDS),
    )
    return boundaries, findings


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries, findings = _evaluate_inventory(inventory)
    return inventory, boundaries, findings


def _public_resources(
    statements: list[dict[str, object]],
    *,
    internal: bool = False,
    recovery_window_in_days: int = 21,
    extra_resources: list[TerraformResource] | None = None,
) -> list[TerraformResource]:
    return [
        *_aws_public_edge(internal=internal),
        _secret(recovery_window_in_days=recovery_window_in_days),
        _role(*statements),
        _task_definition(),
        _aws_ecs_service(),
        *(extra_resources or []),
    ]


class AwsPublicEcsSecretManagementRuleTests(unittest.TestCase):
    def test_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertTrue(_RULE_IDS <= registered)

    def test_public_mutation_authority_emits_tampering_only(self) -> None:
        _, _, findings = _evaluate(
            _public_resources(
                [
                    _statement("Allow", list(_TAMPERING_OPERATIONS)),
                ]
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TAMPERING_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.TAMPERING)
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_lb_listener.https",
                "aws_lb_target_group.orders",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_secretsmanager_secret.orders",
            ],
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
        self.assertIn("role_kind=ecs_task_role", evidence["task_roles"][0])
        self.assertEqual(len(evidence["secret_management_paths"]), 3)
        self.assertTrue(all("management_effect=tampering" in value for value in evidence["secret_management_paths"]))
        self.assertTrue(all("authorization_state=allowed" in value for value in evidence["secret_management_paths"]))
        self.assertFalse("recovery_window" in evidence)
        self.assertIn("Secrets Manager tampering authority", finding.rationale)
        self.assertIn("exact modeled secret(s)", finding.rationale)
        self.assertIn("secret is public", finding.rationale)

    def test_public_delete_authority_emits_disruption_with_terraform_recovery_evidence(
        self,
    ) -> None:
        _, _, findings = _evaluate(
            _public_resources(
                [_statement("Allow", "secretsmanager:DeleteSecret")],
                recovery_window_in_days=30,
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(finding.severity.value, "high")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(len(evidence["secret_management_paths"]), 1)
        self.assertIn(
            "operation=secretsmanager:DeleteSecret",
            evidence["secret_management_paths"][0],
        )
        self.assertIn(
            "recovery_window_state=terraform_resource_deletion_only",
            evidence["recovery_window"][0],
        )
        self.assertIn(
            "terraform_recovery_window_is_not_runtime_recovery=true",
            evidence["recovery_window"][0],
        )
        self.assertIn("Secrets Manager disruption authority", finding.rationale)
        self.assertIn("does not establish runtime recovery", finding.rationale)

    def test_broad_task_role_authority_emits_both_findings_without_cross_effects(
        self,
    ) -> None:
        _, _, findings = _evaluate(
            _public_resources(
                [
                    _statement(
                        "Allow",
                        [*_TAMPERING_OPERATIONS, "secretsmanager:DeleteSecret"],
                    )
                ]
            )
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            _RULE_IDS,
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        tampering_evidence = {item.key: item.values for item in findings_by_rule[_TAMPERING_RULE_ID].evidence}
        disruption_evidence = {item.key: item.values for item in findings_by_rule[_DISRUPTION_RULE_ID].evidence}
        self.assertTrue(
            all("management_effect=tampering" in value for value in tampering_evidence["secret_management_paths"])
        )
        self.assertTrue(
            all("management_effect=disruption" in value for value in disruption_evidence["secret_management_paths"])
        )
        self.assertTrue(
            all("secretsmanager:DeleteSecret" not in value for value in tampering_evidence["secret_management_paths"])
        )
        self.assertEqual(
            findings_by_rule[_TAMPERING_RULE_ID].affected_resources,
            findings_by_rule[_DISRUPTION_RULE_ID].affected_resources,
        )

    def test_multiple_exact_secrets_raise_tampering_blast_radius(self) -> None:
        second_arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:payments-XyZ123"
        second_secret = _resource(
            "aws_secretsmanager_secret",
            "payments",
            {
                "id": second_arn,
                "arn": second_arn,
                "name": "payments",
                "recovery_window_in_days": 21,
            },
        )
        _, _, findings = _evaluate(
            _public_resources(
                [
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        resources=[_SECRET_ARN, second_arn],
                    )
                ],
                extra_resources=[second_secret],
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TAMPERING_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("aws_secretsmanager_secret.orders", finding.affected_resources)
        self.assertIn("aws_secretsmanager_secret.payments", finding.affected_resources)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(len(evidence["secret_management_paths"]), 2)

    def test_private_or_nondeterministic_secret_management_paths_stay_quiet(self) -> None:
        cases = {
            "internal load balancer": _public_resources(
                [_statement("Allow", "secretsmanager:PutSecretValue")],
                internal=True,
            ),
            "conditional allow": _public_resources(
                [
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                    )
                ]
            ),
            "explicit deny": _public_resources([_statement("Deny", "secretsmanager:PutSecretValue")]),
            "incomplete identity evidence": [
                *_public_resources([]),
                _unresolved_attachment(),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(resources)
                self.assertEqual(findings, [])

    def test_stale_service_management_path_does_not_create_a_finding(self) -> None:
        inventory = AwsNormalizer().normalize(_public_resources([_statement("Allow", "secretsmanager:PutSecretValue")]))
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        paths = aws_facts(service).ecs_secret_management_paths
        stale_path = dict(paths[0])
        stale_path["secret_arn"] = "arn:aws:secretsmanager:us-east-1:111122223333:secret:stale-AbCdEf"
        aws_facts(service).set_ecs_secret_management_paths([stale_path])

        _, findings = _evaluate_inventory(inventory)

        self.assertEqual(findings, [])

    def test_current_service_task_role_and_authorization_joins_are_required(self) -> None:
        cases = (
            "service no longer selects task definition",
            "task definition task role changed",
            "current secret authorization removed",
        )

        for case in cases:
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(
                    _public_resources([_statement("Allow", "secretsmanager:PutSecretValue")])
                )
                service = inventory.get_by_address("aws_ecs_service.orders")
                task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
                secret = inventory.get_by_address("aws_secretsmanager_secret.orders")
                assert service is not None
                assert task_definition is not None
                assert secret is not None

                if case == "service no longer selects task definition":
                    aws_facts(service).set(
                        AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES,
                        [],
                    )
                elif case == "task definition task role changed":
                    aws_facts(task_definition).set_task_role_arn("arn:aws:iam::111122223333:role/other_task")
                else:
                    aws_facts(secret).set_secrets_manager_operation_authorization_posture(
                        authorizations=[],
                        uncertainties=[],
                    )

                _, findings = _evaluate_inventory(inventory)

                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
