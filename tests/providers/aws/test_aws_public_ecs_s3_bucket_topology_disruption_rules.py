from __future__ import annotations

import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ARCHIVE_BUCKET_ARN,
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _resource,
    _role,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_bucket_topology_destruction_paths import (
    _bucket_policy,
    _bucket_statement,
    _caller_identity,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import _versioning
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _load_balancer_path,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_facts import aws_facts

_TOPOLOGY_RULE_ID = "aws-public-ecs-s3-bucket-topology-disruption"
_MUTATION_RULE_ID = "aws-public-ecs-s3-mutation-access"


def _runtime_resources(
    actions: str | list[str] | None = None,
    *,
    role_statements: list[dict[str, Any]] | None = None,
    include_load_balancer: bool = True,
    extra: list[TerraformResource] | None = None,
) -> list[TerraformResource]:
    statements = role_statements
    if statements is None:
        assert actions is not None
        statements = [_statement("Allow", actions, _BUCKET_ARN)]
    resources: list[TerraformResource] = [
        _caller_identity(),
        _bucket(),
        _role("orders_task", _TASK_ROLE_ARN, statements),
        _task_definition(execution_role_arn=None),
        _service(),
    ]
    if include_load_balancer:
        resources[1:1] = _load_balancer_path()
    resources.extend(extra or [])
    return resources


def _evaluate(
    resources: list[TerraformResource],
    rule_ids: set[str] | frozenset[str] = frozenset({_TOPOLOGY_RULE_ID}),
):
    inventory = AwsNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, findings


def _reevaluate(
    inventory,
    rule_ids: set[str] | frozenset[str] = frozenset({_TOPOLOGY_RULE_ID}),
):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsPublicEcsS3BucketTopologyDisruptionRuleTests(unittest.TestCase):
    def test_delete_bucket_is_topology_dos_only(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:DeleteBucket"),
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

    def test_delete_bucket_policy_remains_tampering_only(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:DeleteBucketPolicy"),
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTATION_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        mutation_actions = evidence["s3_mutation_paths"][0].split("actions=", 1)[1].split(";", 1)[0].split(",")
        self.assertEqual(mutation_actions, ["s3:DeleteBucketPolicy"])

    def test_delete_bucket_and_policy_preserve_separate_taxonomy(self) -> None:
        _, findings = _evaluate(
            _runtime_resources(["s3:DeleteBucket", "s3:DeleteBucketPolicy"]),
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )
        mutation = next(finding for finding in findings if finding.rule_id == _MUTATION_RULE_ID)
        evidence = {item.key: item.values for item in mutation.evidence}
        mutation_actions = evidence["s3_mutation_paths"][0].split("actions=", 1)[1].split(";", 1)[0].split(",")
        self.assertEqual(mutation_actions, ["s3:DeleteBucketPolicy"])
        self.assertNotIn("s3:DeleteBucket", mutation_actions)

    def test_wildcard_s3_action_retains_non_topology_administrative_mutation_evidence(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("s3:*"),
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )
        mutation = next(finding for finding in findings if finding.rule_id == _MUTATION_RULE_ID)
        evidence = {item.key: item.values for item in mutation.evidence}
        mutation_actions = evidence["s3_mutation_paths"][0].split("actions=", 1)[1].split(";", 1)[0].split(",")
        self.assertIn("s3:DeleteBucketPolicy", mutation_actions)
        self.assertIn("s3:PutBucketPolicy", mutation_actions)
        self.assertNotIn("s3:DeleteBucket", mutation_actions)

    def test_positive_finding_preserves_exact_bucket_and_recovery_boundary(self) -> None:
        _, findings = _evaluate(_runtime_resources("s3:DeleteBucket"))

        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_s3_bucket.orders",
            ],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_path"],
            [
                "internet reaches aws_lb.public",
                "aws_lb.public fronts aws_ecs_service.orders",
            ],
        )
        self.assertIn(
            "bucket_address=aws_s3_bucket.orders",
            evidence["s3_bucket_topology_destruction_paths"][0],
        )
        self.assertIn(
            "operation=s3:DeleteBucket",
            evidence["s3_bucket_topology_destruction_paths"][0],
        )
        self.assertIn(
            "authorization_state=allowed",
            evidence["s3_bucket_topology_destruction_paths"][0],
        )
        recovery = evidence["bucket_deletion_recovery_evidence"][0]
        self.assertIn("bucket_emptiness_state=not_established", recovery)
        self.assertIn("attached_access_point_state=not_established", recovery)
        self.assertIn("successful_deletion_observed=false", recovery)
        self.assertIn("recovery_observed=false", recovery)
        self.assertIn("bucket emptiness", finding.rationale)
        self.assertIn("successful deletion", finding.rationale)
        self.assertNotIn("permanent deletion", finding.rationale.lower())

    def test_put_and_delete_bucket_emit_tampering_and_topology_dos(self) -> None:
        _, findings = _evaluate(
            _runtime_resources(
                role_statements=[
                    _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                    _statement("Allow", "s3:DeleteBucket", _BUCKET_ARN),
                ],
            ),
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_TOPOLOGY_RULE_ID, _MUTATION_RULE_ID},
        )
        mutation = next(finding for finding in findings if finding.rule_id == _MUTATION_RULE_ID)
        mutation_evidence = {item.key: item.values for item in mutation.evidence}
        self.assertNotIn("s3:DeleteBucket", mutation_evidence["s3_mutation_paths"][0])
        self.assertIn("s3:PutObject", mutation_evidence["s3_mutation_paths"][0])

    def test_private_service_retains_path_but_stays_quiet(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources("s3:DeleteBucket", include_load_balancer=False),
        )

        self.assertEqual(findings, [])
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        self.assertEqual(len(aws_facts(service).ecs_s3_bucket_topology_destruction_paths), 1)

    def test_multiple_buckets_deduplicate_targets_and_raise_blast_radius(self) -> None:
        _, findings = _evaluate(
            _runtime_resources(
                role_statements=[
                    _statement("Allow", "s3:DeleteBucket", _BUCKET_ARN),
                    _statement("Allow", "s3:DeleteBucket", _ARCHIVE_BUCKET_ARN),
                ],
                extra=[_bucket("archive", arn=_ARCHIVE_BUCKET_ARN)],
            ),
        )

        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(len(evidence["s3_bucket_topology_destruction_paths"]), 2)
        self.assertEqual(len(evidence["bucket_deletion_recovery_evidence"]), 2)
        self.assertEqual(finding.affected_resources.count("aws_s3_bucket.orders"), 1)
        self.assertEqual(finding.affected_resources.count("aws_s3_bucket.archive"), 1)
        self.assertIn("across 2 exact modeled S3 buckets", finding.rationale)

    def test_recovery_posture_drift_refreshes_current_finding_evidence(
        self,
    ) -> None:
        inventory, findings = _evaluate(
            _runtime_resources(
                "s3:DeleteBucket",
                extra=[_versioning(None, unknown=True)],
            )
        )
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])
        initial_evidence = _evidence(findings[0])
        self.assertIn(
            "versioning_status=unknown",
            initial_evidence["bucket_deletion_recovery_evidence"][0],
        )
        self.assertTrue(
            any(
                "versioning_configuration" in uncertainty
                for uncertainty in initial_evidence["s3_bucket_topology_destruction_path_uncertainties"]
            )
        )

        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        assert bucket is not None
        bucket_facts = aws_facts(bucket)
        bucket_facts.set_s3_versioning_posture(
            status="Enabled",
            configuration={"status": "Enabled"},
            source_address="aws_s3_bucket_versioning.orders",
        )
        bucket_facts.set(AwsResourceMetadata.S3_POSTURE_UNCERTAINTIES, [])

        current_findings = _reevaluate(inventory)
        self.assertEqual(
            [finding.rule_id for finding in current_findings],
            [_TOPOLOGY_RULE_ID],
        )
        current_evidence = _evidence(current_findings[0])
        self.assertIn(
            "versioning_status=Enabled",
            current_evidence["bucket_deletion_recovery_evidence"][0],
        )
        self.assertFalse(
            any(
                "versioning_configuration" in uncertainty
                for uncertainty in current_evidence["s3_bucket_topology_destruction_path_uncertainties"]
            )
        )

    def test_unrelated_permission_expansion_preserves_current_finding(self) -> None:
        inventory, findings = _evaluate(_runtime_resources("s3:DeleteBucket"))
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        role.policy_statements = (
            parse_policy_statement(
                _statement(
                    "Allow",
                    ["s3:DeleteBucket", "s3:DeleteBucketPolicy"],
                    _BUCKET_ARN,
                )
            ),
        )

        current_findings = _reevaluate(inventory)
        self.assertEqual(
            [finding.rule_id for finding in current_findings],
            [_TOPOLOGY_RULE_ID],
        )

    def test_public_load_balancer_replacement_refreshes_network_evidence(
        self,
    ) -> None:
        replacement = _resource(
            "aws_lb",
            "replacement",
            {
                "name": "replacement",
                "arn": ("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/replacement/def"),
                "internal": False,
                "load_balancer_type": "application",
            },
        )
        inventory, findings = _evaluate(
            _runtime_resources(
                "s3:DeleteBucket",
                extra=[replacement],
            )
        )
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        aws_facts(service).set_internet_facing_load_balancer_addresses(["aws_lb.replacement"])

        current_findings = _reevaluate(inventory)
        self.assertEqual(
            [finding.rule_id for finding in current_findings],
            [_TOPOLOGY_RULE_ID],
        )
        current_finding = current_findings[0]
        self.assertIn("aws_lb.replacement", current_finding.affected_resources)
        self.assertNotIn("aws_lb.public", current_finding.affected_resources)
        self.assertEqual(
            _evidence(current_finding)["network_path"],
            [
                "internet reaches aws_lb.replacement",
                "aws_lb.replacement fronts aws_ecs_service.orders",
            ],
        )

    def test_current_identity_allow_removal_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_runtime_resources("s3:DeleteBucket"))
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        role.policy_statements = ()
        self.assertEqual(_reevaluate(inventory), [])

    def test_current_identity_explicit_deny_suppresses_cached_finding(self) -> None:
        inventory, findings = _evaluate(_runtime_resources("s3:DeleteBucket"))
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        deny = _statement("Deny", "s3:DeleteBucket", _BUCKET_ARN)
        role.policy_statements = (*role.policy_statements, parse_policy_statement(deny))
        self.assertEqual(_reevaluate(inventory), [])

    def test_current_bucket_policy_deny_suppresses_cached_finding(self) -> None:
        allow = _bucket_policy(
            [_bucket_statement("Allow", "s3:DeleteBucket", _BUCKET_ARN)],
        )
        inventory, findings = _evaluate(
            _runtime_resources(
                "s3:DeleteBucket",
                extra=[allow],
            ),
        )
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        policy = inventory.get_by_address("aws_s3_bucket_policy.orders")
        assert policy is not None
        deny = _bucket_statement("Deny", "s3:DeleteBucket", _BUCKET_ARN)
        policy.policy_statements = (parse_policy_statement(deny),)
        aws_facts(policy).set_policy_document(
            {
                "Version": "2012-10-17",
                "Statement": [deny],
            }
        )
        self.assertEqual(_reevaluate(inventory), [])

    def test_current_service_task_role_and_bucket_relationships_are_revalidated(self) -> None:
        inventory, findings = _evaluate(_runtime_resources("s3:DeleteBucket"))
        self.assertEqual([finding.rule_id for finding in findings], [_TOPOLOGY_RULE_ID])

        service = inventory.get_by_address("aws_ecs_service.orders")
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert service is not None
        assert task_definition is not None
        service_facts = aws_facts(service)
        path = service_facts.ecs_s3_bucket_topology_destruction_paths[0]

        path["bucket_address"] = "aws_s3_bucket.stale"
        service_facts.set_ecs_s3_bucket_topology_destruction_paths([path])
        self.assertEqual(_reevaluate(inventory), [])

        path["bucket_address"] = "aws_s3_bucket.orders"
        service_facts.set_ecs_s3_bucket_topology_destruction_paths([path])
        task_facts = aws_facts(task_definition)
        task_facts.set_task_role_arn("arn:aws:iam::111122223333:role/other-task")
        self.assertEqual(_reevaluate(inventory), [])


if __name__ == "__main__":
    unittest.main()
