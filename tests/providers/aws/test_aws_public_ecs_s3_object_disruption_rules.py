from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _EXECUTION_ROLE_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _role,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _caller_identity,
    _object_lock,
    _versioning,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _load_balancer,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_DISRUPTION_RULE_ID = "aws-public-ecs-s3-object-disruption"
_MUTATION_RULE_ID = "aws-public-ecs-s3-mutation-access"


def _evaluate(resources: list[TerraformResource], rule_ids: set[str]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, findings


def _runtime_resources(
    actions: str | list[str],
    *,
    versioning: str | None = None,
    object_lock: bool = False,
) -> list[TerraformResource]:
    resources: list[TerraformResource] = [
        _caller_identity(),
        _load_balancer(),
        _bucket(),
        _role("orders_task", _TASK_ROLE_ARN, [_statement("Allow", actions, f"{_BUCKET_ARN}/*")]),
        _task_definition(execution_role_arn=None),
        _service(),
    ]
    if versioning is not None:
        resources.insert(2, _versioning(versioning))
    if object_lock:
        resources.insert(2, _object_lock())
    return resources


class AwsPublicEcsS3ObjectDisruptionRuleTests(unittest.TestCase):
    def test_delete_object_only_emits_dos_and_not_mutation(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:DeleteObject", versioning="disabled"),
            {_DISRUPTION_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("operation=s3:DeleteObject", evidence["s3_object_deletion_paths"][0])
        self.assertIn("recovery_state=unversioned_current_object_deletion", evidence["recovery_evidence"][0])
        self.assertIn("permanent_deletion_not_established=true", evidence["recovery_evidence"][0])
        self.assertNotIn("permanent deletion authority", findings[0].rationale.lower())

    def test_delete_object_version_only_emits_dos_with_version_scope_evidence(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:DeleteObjectVersion", object_lock=True),
            {_DISRUPTION_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("operation=s3:DeleteObjectVersion", evidence["s3_object_deletion_paths"][0])
        self.assertIn("object_lock_target_compatibility=unknown", evidence["recovery_evidence"][0])
        self.assertIn("target_retention_or_legal_hold_is_not_established=true", evidence["recovery_evidence"][0])
        self.assertIn("permanent_deletion_not_established=true", evidence["recovery_evidence"][0])

    def test_put_and_delete_emit_tampering_and_dos(self) -> None:
        _, findings = _evaluate(
            _runtime_resources(["s3:PutObject", "s3:DeleteObject"], versioning="Enabled"),
            {_DISRUPTION_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_DISRUPTION_RULE_ID, _MUTATION_RULE_ID},
        )

    def test_multiple_scopes_in_one_bucket_do_not_inflate_rationale_bucket_count(self) -> None:
        resources = [
            _caller_identity(),
            _load_balancer(),
            _bucket(),
            _versioning("disabled"),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/export.json"),
                    _statement("Allow", "s3:DeleteObject", f"{_BUCKET_ARN}/private/*"),
                ],
            ),
            _task_definition(execution_role_arn=None),
            _service(),
        ]

        _, findings = _evaluate(resources, {_DISRUPTION_RULE_ID})

        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(len(evidence["s3_object_deletion_paths"]), 2)
        self.assertIn("across 1 exact modeled S3 bucket.", findings[0].rationale)
        self.assertNotIn("1 exact modeled bucket/object scope", findings[0].rationale)

    def test_delete_object_tagging_remains_tampering_only(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:DeleteObjectTagging"),
            {_DISRUPTION_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTATION_RULE_ID])

    def test_private_service_stays_quiet(self) -> None:
        resources = _runtime_resources("s3:DeleteObject", versioning="disabled")
        resources = [resource for resource in resources if resource.resource_type != "aws_lb"]
        _, findings = _evaluate(resources, {_DISRUPTION_RULE_ID})

        self.assertEqual(findings, [])

    def test_current_service_task_role_and_bucket_path_are_revalidated(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources("s3:DeleteObject", versioning="disabled"),
            {_DISRUPTION_RULE_ID},
        )
        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])

        service = inventory.get_by_address("aws_ecs_service.orders")
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert service is not None
        assert task_definition is not None
        service_facts = aws_facts(service)
        path = service_facts.ecs_s3_object_deletion_paths[0]

        original_task_definition_address = path["task_definition_address"]
        path["task_definition_address"] = "aws_ecs_task_definition.stale"
        service_facts.set_ecs_s3_object_deletion_paths([path])
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE_ID})),
            ),
            [],
        )
        path["task_definition_address"] = original_task_definition_address
        service_facts.set_ecs_s3_object_deletion_paths([path])

        task_facts = aws_facts(task_definition)
        task_facts.set_task_role_arn(_EXECUTION_ROLE_ARN)
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE_ID})),
            ),
            [],
        )

        task_facts.set_task_role_arn(_TASK_ROLE_ARN)
        path["matched_actions"] = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        service_facts.set_ecs_s3_object_deletion_paths([path])
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE_ID})),
            ),
            [],
        )

    def test_current_recovery_posture_is_revalidated(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources("s3:DeleteObject", versioning="Enabled"),
            {_DISRUPTION_RULE_ID},
        )
        self.assertEqual([finding.rule_id for finding in findings], [_DISRUPTION_RULE_ID])
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        assert bucket is not None
        aws_facts(bucket).set_s3_versioning_posture(
            status="disabled",
            configuration={},
            source_address=None,
        )
        self.assertEqual(
            StrideRuleEngine().evaluate(
                inventory,
                detect_trust_boundaries(inventory),
                rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE_ID})),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
