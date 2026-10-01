from __future__ import annotations

import json
import unittest
from copy import deepcopy

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ACCOUNT_ID,
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _caller_identity,
    _role,
    _role_policy_attachment,
    _service,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import _bucket_policy, _bucket_statement
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _load_balancer_path
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _service as _public_service
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.s3_object_scopes import s3_resource_for_bucket

_OTHER_ARN = "arn:aws:s3:::orders-archive"
_FOREIGN_ROLE = "arn:aws:iam::444455556666:role/orders-task"
_OPERATIONS = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket"]


def _resources(
    *,
    resource: str = "*",
    actions: str | list[str] = _OPERATIONS,
    role_arn: str = _TASK_ROLE_ARN,
    owner: bool = True,
) -> list[TerraformResource]:
    return [
        *([_caller_identity()] if owner else []),
        _bucket(),
        _role("orders_task", role_arn, [_statement("Allow", actions, resource)]),
        _task_definition(task_role_arn=role_arn, execution_role_arn=None),
        _service(),
    ]


def _facts(resources: list[TerraformResource], address: str = "aws_ecs_service.orders"):
    inventory = AwsNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    return aws_facts(workload)


def _authority(facts):
    return (
        [(p["bucket_arn"], p["matched_actions"], p["scope_evaluations"]) for p in facts.ecs_s3_access_paths],
        [(p["bucket_arn"], p["operation"], p["target_scope"]) for p in facts.ecs_s3_object_deletion_paths],
        [(p["bucket_arn"], p["operation"]) for p in facts.ecs_s3_bucket_topology_destruction_paths],
    )


class AwsS3BroadGrantTests(unittest.TestCase):
    def test_global_grant_fans_out_only_to_modeled_targets_and_keeps_operations(self) -> None:
        resources = [*_resources(), _bucket("archive", arn=_OTHER_ARN)]
        baseline = _facts(resources)
        self.assertEqual(len(baseline.ecs_s3_access_paths), 2)
        self.assertEqual(len(baseline.ecs_s3_object_deletion_paths), 4)
        self.assertEqual(len(baseline.ecs_s3_bucket_topology_destruction_paths), 2)
        for path in baseline.ecs_s3_access_paths:
            self.assertEqual(path["access_state"], "allowed")
            self.assertEqual(set(path["matched_actions"]), set(_OPERATIONS))
            self.assertEqual(path["policy_resources"], ["*"])
            self.assertEqual(path["bucket_account_id"], _ACCOUNT_ID)
            for scope in path["scope_evaluations"]:
                expected = path["bucket_arn"] + ("" if scope["action"] == "s3:DeleteBucket" else "/*")
                self.assertEqual(scope["resource"], expected)
        self.assertEqual(_authority(_facts(list(reversed(resources)))), _authority(baseline))
        self.assertEqual(_authority(_facts(resources, "aws_ecs_task_definition.orders")), _authority(baseline))

    def test_bucket_selector_and_prefix_stay_bounded(self) -> None:
        for selector in ("orders-*", "orders-????"):
            with self.subTest(selector=selector):
                resources = [
                    *_resources(resource=f"arn:aws:s3:::{selector}/public/*"),
                    _bucket("unrelated", arn="arn:aws:s3:::unrelated"),
                ]
                facts = _facts(resources)
                self.assertEqual(len(facts.ecs_s3_access_paths), 1)
                path = facts.ecs_s3_access_paths[0]
                self.assertEqual(set(path["matched_actions"]), set(_OPERATIONS) - {"s3:DeleteBucket"})
                self.assertEqual(
                    {scope["resource"] for scope in path["scope_evaluations"]}, {f"{_BUCKET_ARN}/public/*"}
                )
                self.assertEqual(
                    {p["target_scope"] for p in facts.ecs_s3_object_deletion_paths}, {f"{_BUCKET_ARN}/public/*"}
                )
                self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_resource_kinds_and_unsupported_patterns_do_not_expand_authority(self) -> None:
        cases = (
            (_BUCKET_ARN, "object_level", None),
            (f"{_BUCKET_ARN}/*", "bucket_level", None),
            ("arn:aws-cn:s3:::orders-*/*", "object_level", None),
            ("arn:aws:s3:::orders-${suffix}/*", "object_level", None),
            ("arn:aws:s3:::orders-[a-z]*/*", "object_level", None),
            ("arn:aws:s3:::orders-*", "bucket_level", _BUCKET_ARN),
            ("arn:aws:s3:::orders-*", "object_level", f"{_BUCKET_ARN}/*"),
        )
        for resource, kind, expected in cases:
            with self.subTest(resource=resource, kind=kind):
                self.assertEqual(s3_resource_for_bucket(resource, _BUCKET_ARN, kind), expected)
        facts = _facts(_resources(resource="arn:aws:s3:::orders-*/public/*.json"))
        self.assertFalse(any(path["access_state"] == "allowed" for path in facts.ecs_s3_access_paths))
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_broad_denies_and_conditions_cannot_be_bypassed(self) -> None:
        for source in ("identity", "bucket"):
            for conditional in (False, True):
                with self.subTest(source=source, conditional=conditional):
                    resources = _resources()
                    condition = {"Bool": {"aws:SecureTransport": "false"}} if conditional else None
                    if source == "identity":
                        role = next(r for r in resources if r.resource_type == "aws_iam_role")
                        document = {
                            "Statement": [
                                _statement("Allow", _OPERATIONS, "*"),
                                _statement("Deny", _OPERATIONS, "*", condition=condition),
                            ]
                        }
                        role.values["inline_policy"][0]["policy"] = json.dumps(document)
                    else:
                        resources.append(
                            _bucket_policy(
                                [_bucket_statement("Deny", _OPERATIONS, "*", _TASK_ROLE_ARN, condition=condition)]
                            )
                        )
                    facts = _facts(resources)
                    self.assertEqual(
                        facts.ecs_s3_access_paths[0]["access_state"], "unknown" if conditional else "denied"
                    )
                    self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
                    self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_disjoint_denies_and_other_operations_do_not_remove_prefix_grants(self) -> None:
        resources = _resources(resource="arn:aws:s3:::orders-*/public/*")
        resources.append(
            _bucket_policy(
                [
                    _bucket_statement("Deny", _OPERATIONS, f"{_BUCKET_ARN}/private/*", _TASK_ROLE_ARN),
                    _bucket_statement("Deny", "s3:PutObjectAcl", "*", _TASK_ROLE_ARN),
                    _bucket_statement("Deny", _OPERATIONS, "arn:aws-cn:s3:::orders-*/*", _TASK_ROLE_ARN),
                ]
            )
        )
        facts = _facts(resources)
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "allowed")
        self.assertEqual(len(facts.ecs_s3_object_deletion_paths), 2)
        # A wildcard bucket selector can consume key separators in a deny.
        resources[-1] = _bucket_policy(
            [
                _bucket_statement("Deny", _OPERATIONS, "arn:aws:s3:::orders-*/private/*", _TASK_ROLE_ARN),
            ]
        )
        facts = _facts(resources)
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])

    def test_boundaries_incomplete_policies_and_unknown_ownership_fail_closed(self) -> None:
        for gate in ("boundary", "unknown_boundary", "incomplete_identity", "incomplete_bucket", "ownership"):
            with self.subTest(gate=gate):
                resources = _resources(owner=gate != "ownership")
                role = next(r for r in resources if r.resource_type == "aws_iam_role")
                if gate == "boundary":
                    role.values["permissions_boundary"] = f"arn:aws:iam::{_ACCOUNT_ID}:policy/boundary"
                elif gate == "unknown_boundary":
                    role.unknown_values = {"permissions_boundary": True}
                elif gate == "incomplete_identity":
                    resources.append(
                        _role_policy_attachment(_TASK_ROLE_ARN, f"arn:aws:iam::{_ACCOUNT_ID}:policy/unmodeled")
                    )
                elif gate == "incomplete_bucket":
                    bucket = next(r for r in resources if r.resource_type == "aws_s3_bucket")
                    bucket.unknown_values = {"policy": True}
                facts = _facts(resources)
                self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
                self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
                self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_cross_account_grants_intersect_per_operation_and_resource(self) -> None:
        resources = _resources(role_arn=_FOREIGN_ROLE)
        absent = _facts(resources)
        self.assertFalse(any(p["access_state"] == "allowed" for p in absent.ecs_s3_access_paths))
        self.assertEqual(absent.ecs_s3_object_deletion_paths, [])
        resources.append(
            _bucket_policy(
                [
                    _bucket_statement(
                        "Allow", ["s3:GetObject", "s3:DeleteObject"], "arn:aws:s3:::orders-*/public/*", _FOREIGN_ROLE
                    ),
                    _bucket_statement("Allow", "s3:DeleteBucket", "*", _FOREIGN_ROLE),
                    _bucket_statement("Deny", "s3:GetObject", f"{_BUCKET_ARN}/private/*", _FOREIGN_ROLE),
                ]
            )
        )
        facts = _facts(resources)
        path = facts.ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["matched_actions"], ["s3:GetObject", "s3:DeleteObject"])
        self.assertFalse(path["same_account"])
        self.assertEqual(
            {(s["action"], s["resource"]) for s in path["scope_evaluations"] if s["modeled_access_state"] == "allowed"},
            {("s3:GetObject", f"{_BUCKET_ARN}/public/*"), ("s3:DeleteObject", f"{_BUCKET_ARN}/public/*")},
        )
        self.assertEqual(
            [(p["operation"], p["target_scope"]) for p in facts.ecs_s3_object_deletion_paths],
            [("s3:DeleteObject", f"{_BUCKET_ARN}/public/*")],
        )
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_cross_account_conditional_or_wrong_principal_grants_are_not_authority(self) -> None:
        for principal, condition in (
            (_TASK_ROLE_ARN, None),
            ("*", None),
            (_FOREIGN_ROLE, {"StringEquals": {"aws:SourceVpc": "vpc-runtime"}}),
        ):
            with self.subTest(principal=principal, condition=condition):
                resources = [
                    *_resources(role_arn=_FOREIGN_ROLE),
                    _bucket_policy(
                        [
                            _bucket_statement("Allow", _OPERATIONS, "*", principal, condition=condition),
                        ]
                    ),
                ]
                facts = _facts(resources)
                self.assertFalse(any(p["access_state"] == "allowed" for p in facts.ecs_s3_access_paths))
                self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
                self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_ambiguous_bucket_identity_never_produces_an_exact_path(self) -> None:
        resources = _resources()
        duplicate = deepcopy(next(r for r in resources if r.resource_type == "aws_s3_bucket"))
        duplicate.address = "aws_s3_bucket.duplicate"
        duplicate.name = "duplicate"
        facts = _facts([*resources, duplicate])
        self.assertEqual(facts.ecs_s3_access_paths, [])
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_bucket_local_ownership_survives_aliases_and_unrelated_accounts(self) -> None:
        resources = _resources()
        foreign = _bucket("foreign", arn="arn:aws:s3:::orders-foreign", provider_config_key="aws.foreign")
        unknown = _bucket("unknown", arn="arn:aws:s3:::orders-unknown", provider_config_key="aws.unknown")
        caller = _caller_identity("444455556666")
        caller.address = "data.aws_caller_identity.foreign"
        caller.provider_config_key = "aws.foreign"
        resources.extend([foreign, unknown, caller])
        facts = _facts(resources)
        self.assertEqual(
            {p["bucket_address"] for p in facts.ecs_s3_access_paths if p["access_state"] == "allowed"},
            {"aws_s3_bucket.orders"},
        )
        self.assertEqual({p["bucket_address"] for p in facts.ecs_s3_object_deletion_paths}, {"aws_s3_bucket.orders"})
        policy = _bucket_policy(
            [
                _bucket_statement("Allow", _OPERATIONS, "arn:aws:s3:::orders-*/public/*", _TASK_ROLE_ARN),
            ]
        )
        policy.values["bucket"] = "orders-foreign"
        policy.provider_config_key = "aws.foreign"
        resources.append(policy)
        facts = _facts(resources)
        self.assertEqual(
            {p["bucket_address"] for p in facts.ecs_s3_access_paths if p["access_state"] == "allowed"},
            {"aws_s3_bucket.orders", "aws_s3_bucket.foreign"},
        )
        self.assertEqual(
            {p["bucket_address"] for p in facts.ecs_s3_bucket_topology_destruction_paths}, {"aws_s3_bucket.orders"}
        )
        self.assertEqual(_authority(_facts(list(reversed(resources)))), _authority(facts))

    def test_unknown_bucket_policy_targets_constrain_broad_grants(self) -> None:
        policy = _bucket_policy([_bucket_statement("Deny", _OPERATIONS, "*", _TASK_ROLE_ARN)])
        policy.values["bucket"] = None
        policy.unknown_values = {"bucket": True}
        facts = _facts([*_resources(), policy])
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
        self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_unresolved_deny_resources_cannot_be_ignored_by_broad_grants(self) -> None:
        for resource in ("${var.target}", "arn:aws:s3:::${var.bucket}/*"):
            with self.subTest(resource=resource):
                resources = _resources()
                role = next(r for r in resources if r.resource_type == "aws_iam_role")
                role.values["inline_policy"][0]["policy"] = json.dumps(
                    {
                        "Statement": [
                            _statement("Allow", _OPERATIONS, "*"),
                            _statement("Deny", _OPERATIONS, resource),
                        ]
                    }
                )
                facts = _facts(resources)
                self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
                self.assertEqual(facts.ecs_s3_object_deletion_paths, [])
                self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_deny_bucket_wildcards_can_consume_object_key_separators(self) -> None:
        actions = ["s3:GetObject", "s3:DeleteObject"]
        for resource in (
            "arn:aws:s3:::orders-*",
            "arn:aws:s3:::orders-*report.json",
            "arn:aws:s3:::orders-*-backup/private/*",
        ):
            for source in ("identity", "bucket"):
                with self.subTest(resource=resource, source=source):
                    resources = _resources(actions=actions)
                    if source == "identity":
                        role = next(r for r in resources if r.resource_type == "aws_iam_role")
                        role.values["inline_policy"][0]["policy"] = json.dumps(
                            {
                                "Statement": [
                                    _statement("Allow", actions, "*"),
                                    _statement("Deny", actions, resource),
                                ]
                            }
                        )
                    else:
                        resources.append(_bucket_policy([_bucket_statement("Deny", actions, resource, _TASK_ROLE_ARN)]))
                    facts = _facts(resources)
                    self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
                    self.assertEqual(facts.ecs_s3_object_deletion_paths, [])

    def test_resource_policy_only_broad_deletion_keeps_boundary_and_ownership_checks(self) -> None:
        for boundary in (False, True):
            with self.subTest(boundary=boundary):
                resources = _resources(actions="s3:GetObject")
                resources.append(_bucket_policy([_bucket_statement("Allow", _OPERATIONS, "*", _TASK_ROLE_ARN)]))
                if boundary:
                    role = next(r for r in resources if r.resource_type == "aws_iam_role")
                    role.values["permissions_boundary"] = f"arn:aws:iam::{_ACCOUNT_ID}:policy/boundary"
                facts = _facts(resources)
                self.assertEqual(len(facts.ecs_s3_object_deletion_paths), 0 if boundary else 2)
                self.assertEqual(len(facts.ecs_s3_bucket_topology_destruction_paths), 0 if boundary else 1)
                # The identity-backed access surface does not synthesize resource-policy-only operations.
                self.assertEqual(facts.ecs_s3_access_paths[0]["matched_actions"], ["s3:GetObject"])

    def test_wildcard_actions_on_objects_never_authorize_bucket_deletion(self) -> None:
        facts = _facts(_resources(actions="s3:*", resource="arn:aws:s3:::orders-*/public/*"))
        path = facts.ecs_s3_access_paths[0]
        self.assertNotIn("s3:DeleteBucket", path["matched_actions"])
        self.assertNotIn("s3:PutBucketPolicy", path["matched_actions"])
        self.assertEqual({scope["resource"] for scope in path["scope_evaluations"]}, {f"{_BUCKET_ARN}/public/*"})
        self.assertEqual(len(facts.ecs_s3_object_deletion_paths), 2)
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])

    def test_public_findings_keep_mutation_object_deletion_and_topology_distinct(self) -> None:
        mutation = "aws-public-ecs-s3-mutation-access"
        deletion = "aws-public-ecs-s3-object-disruption"
        topology = "aws-public-ecs-s3-bucket-topology-disruption"
        for resource, expected in (
            ("*", {mutation, deletion, topology}),
            ("arn:aws:s3:::orders-*/public/*", {mutation, deletion}),
            ("arn:aws:s3:::unmodeled-*/*", set()),
        ):
            with self.subTest(resource=resource):
                resources = [
                    *[r for r in _resources(resource=resource) if r.resource_type != "aws_ecs_service"],
                    *_load_balancer_path(),
                    _public_service(),
                ]
                inventory = AwsNormalizer().normalize(resources)
                findings = StrideRuleEngine().evaluate(
                    inventory,
                    detect_trust_boundaries(inventory),
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({mutation, deletion, topology})),
                )
                self.assertEqual({finding.rule_id for finding in findings}, expected)
                for finding in findings:
                    self.assertIn("aws_s3_bucket.orders", finding.affected_resources)


if __name__ == "__main__":
    unittest.main()
