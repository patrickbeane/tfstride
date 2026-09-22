from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ACCOUNT_ID,
    _BUCKET_ARN,
    _EXECUTION_ROLE_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _normalize,
    _resource,
    _role,
    _service,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import _bucket_policy, _bucket_statement
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _evaluate, _load_balancer
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import _service as _public_service
from tfstride.models import TerraformResource
from tfstride.providers.aws.resource_facts import aws_facts


def _grant_role() -> TerraformResource:
    return _role("orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*")])


class AwsEcsS3BucketPolicyConstraintTests(unittest.TestCase):
    def test_principal_matching_preserves_runtime_identity(self) -> None:
        cases = (
            ("wildcard", "*", "denied"),
            ("AWS wildcard", {"AWS": "*"}, "denied"),
            ("task role", {"AWS": _TASK_ROLE_ARN}, "denied"),
            ("account root", {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:root"}, "denied"),
            ("account ID", {"AWS": _ACCOUNT_ID}, "denied"),
            ("principal list", {"AWS": [_EXECUTION_ROLE_ARN, _TASK_ROLE_ARN]}, "denied"),
            ("execution role", {"AWS": _EXECUTION_ROLE_ARN}, "allowed"),
            ("foreign account", {"AWS": "arn:aws:iam::444455556666:root"}, "allowed"),
            ("foreign partition", {"AWS": f"arn:aws-cn:iam::{_ACCOUNT_ID}:root"}, "allowed"),
            ("service", {"Service": "ecs-tasks.amazonaws.com"}, "allowed"),
            ("unknown principal", {"CanonicalUser": "unmapped-canonical-user"}, "unknown"),
            ("role session", {"AWS": f"arn:aws:sts::{_ACCOUNT_ID}:assumed-role/orders-task/session"}, "unknown"),
        )
        for label, principal, expected in cases:
            with self.subTest(label=label):
                deny = _statement("Deny", "s3:PutObject", "*")
                deny["Principal"] = principal
                inventory = _normalize(
                    [
                        _bucket_policy([deny]),
                        _bucket(),
                        _grant_role(),
                        _task_definition(),
                        _service(),
                    ]
                )
                for address in ("aws_ecs_task_definition.orders", "aws_ecs_service.orders"):
                    workload = inventory.get_by_address(address)
                    assert workload is not None
                    facts = aws_facts(workload)
                    path = facts.ecs_s3_access_paths[0]
                    self.assertEqual(path["access_state"], expected)
                    self.assertEqual(path["bucket_policy_source_addresses"], ["aws_s3_bucket_policy.orders"])
                    if expected == "denied":
                        self.assertEqual(path["denied_actions"], ["s3:PutObject"])
                        self.assertEqual(
                            path["bucket_policy_statements"][0]["source_address"], "aws_s3_bucket_policy.orders"
                        )
                        self.assertEqual(path["bucket_policy_statements"][0]["conditions"], [])
                    if expected == "unknown":
                        self.assertTrue(facts.ecs_s3_access_path_uncertainties)

    def test_conditions_and_unrelated_denies_preserve_scope(self) -> None:
        cases = (
            ("conditional", "s3:PutObject", "*", {"Bool": {"aws:SecureTransport": "false"}}, "unknown"),
            (
                "disjoint conditional",
                "s3:PutObject",
                f"{_BUCKET_ARN}/private/*",
                {"Bool": {"aws:SecureTransport": "false"}},
                "allowed",
            ),
            ("disjoint prefix", "s3:PutObject", f"{_BUCKET_ARN}/private/*", None, "allowed"),
            ("partial overlap", "s3:PutObject", f"{_BUCKET_ARN}/public/private/*", None, "unknown"),
            ("other action", "s3:GetObject", "*", None, "allowed"),
            ("other bucket", "s3:PutObject", "arn:aws:s3:::unrelated/*", None, "allowed"),
            ("wrong resource kind", "s3:PutObject", _BUCKET_ARN, None, "allowed"),
            ("symbolic resource", "s3:PutObject", "${aws_s3_bucket.orders.arn}/*", None, "unknown"),
            ("unknown bucket variable", "s3:PutObject", "arn:aws:s3:::${var.bucket}/*", None, "unknown"),
            (
                "variable in unrelated bucket",
                "s3:PutObject",
                "arn:aws:s3:::unrelated/${aws:username}/*",
                None,
                "allowed",
            ),
        )
        for label, action, resource, condition, expected in cases:
            with self.subTest(label=label):
                inventory, _, findings = _evaluate(
                    [
                        _load_balancer(),
                        _bucket(),
                        _grant_role(),
                        _task_definition(),
                        _public_service(),
                        _bucket_policy([_bucket_statement("Deny", action, resource, "*", condition=condition)]),
                    ]
                )
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                path = aws_facts(service).ecs_s3_access_paths[0]
                self.assertEqual(path["access_state"], expected)
                self.assertEqual(len(findings), 1 if expected == "allowed" else 0)
                if label == "conditional":
                    record = path["bucket_policy_statements"][0]
                    self.assertTrue(record["conditional"])
                    self.assertEqual(
                        record["conditions"], [{"operator": "Bool", "key": "aws:SecureTransport", "values": ["false"]}]
                    )
                if label == "disjoint conditional":
                    self.assertFalse(path["conditional_evaluation_required"])

    def test_incomplete_policy_constraints_fail_closed_for_inline_and_standalone_policies(self) -> None:
        valid = _bucket_statement("Allow", "s3:GetObject", "*", "*")
        cases: list[tuple[str, Any, bool]] = [
            ("unknown", None, True),
            ("stale unknown", json.dumps({"Statement": [valid]}), True),
            ("malformed", "{", False),
            ("empty document", "{}", False),
            (
                "NotPrincipal",
                json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "s3:PutObject",
                                "Resource": "*",
                                "NotPrincipal": {"AWS": _EXECUTION_ROLE_ARN},
                            }
                        ]
                    }
                ),
                False,
            ),
            (
                "NotAction",
                json.dumps(
                    {"Statement": [{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*", "Principal": "*"}]}
                ),
                False,
            ),
            (
                "NotResource",
                json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "s3:PutObject",
                                "NotResource": "arn:aws:s3:::other/*",
                                "Principal": "*",
                            }
                        ]
                    }
                ),
                False,
            ),
        ]
        for inline in (False, True):
            for label, document, unknown in cases:
                with self.subTest(inline=inline, label=label):
                    bucket = _bucket()
                    policy = (
                        bucket if inline else _resource("aws_s3_bucket_policy", "orders", {"bucket": "orders-data"})
                    )
                    policy.values["policy"] = document
                    if unknown:
                        policy.unknown_values = {"policy": True}
                    inventory = _normalize(
                        [
                            bucket,
                            *([] if inline else [policy]),
                            _grant_role(),
                            _task_definition(),
                            _service(),
                        ]
                    )
                    service = inventory.get_by_address("aws_ecs_service.orders")
                    assert service is not None
                    facts = aws_facts(service)
                    path = facts.ecs_s3_access_paths[0]
                    self.assertEqual(path["access_state"], "unknown")
                    self.assertTrue(path["role_policy_complete"])
                    self.assertFalse(path["bucket_policy_constraints_complete"])
                    self.assertTrue(
                        any(
                            "bucket policy" in reason or "bucket-policy" in reason
                            for reason in facts.ecs_s3_access_path_uncertainties
                        )
                    )

    def test_complete_inline_policy_is_applied(self) -> None:
        bucket = _bucket()
        bucket.values["policy"] = json.dumps({"Statement": [_bucket_statement("Deny", "s3:PutObject", "*", "*")]})
        inventory = _normalize([bucket, _grant_role(), _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        path = aws_facts(task).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "denied")
        self.assertEqual(path["bucket_policy_source_addresses"], [bucket.address])

    def test_bucket_allow_does_not_create_or_restore_identity_access(self) -> None:
        for statements in (
            None,
            [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"), _statement("Deny", "s3:PutObject", "*")],
        ):
            with self.subTest(statements=statements):
                inventory = _normalize(
                    [
                        _bucket(),
                        _role("orders_task", _TASK_ROLE_ARN, statements),
                        _task_definition(),
                        _bucket_policy([_bucket_statement("Allow", "s3:PutObject", "*", "*")]),
                    ]
                )
                task = inventory.get_by_address("aws_ecs_task_definition.orders")
                assert task is not None
                paths = aws_facts(task).ecs_s3_access_paths
                if statements is None:
                    self.assertEqual(paths, [])
                else:
                    self.assertEqual(paths[0]["access_state"], "denied")

    def test_conflicting_policy_sources_are_uncertain(self) -> None:
        for inline in (False, True):
            with self.subTest(inline=inline):
                bucket = _bucket()
                deny = _bucket_statement("Deny", "s3:PutObject", "*", "*")
                allow = _bucket_statement("Allow", "s3:PutObject", "*", "*")
                extra = []
                if inline:
                    bucket.values["policy"] = json.dumps({"Statement": [deny]})
                else:
                    second = _resource(
                        "aws_s3_bucket_policy",
                        "other",
                        {"bucket": "orders-data", "policy": json.dumps({"Statement": [deny]})},
                    )
                    extra.append(second)
                inventory = _normalize([bucket, _bucket_policy([allow]), *extra, _grant_role(), _task_definition()])
                task = inventory.get_by_address("aws_ecs_task_definition.orders")
                assert task is not None
                path = aws_facts(task).ecs_s3_access_paths[0]
                self.assertEqual(path["access_state"], "unknown")
                self.assertEqual(path["bucket_policy_statements"], [])

    def test_unresolved_targets_do_not_invent_denies_or_poison_unrelated_paths(self) -> None:
        cases = (
            ("unknown target", None, True, "s3:PutObject", "*", "aws", "unknown"),
            ("stale target", "other-bucket", True, "s3:PutObject", "*", "aws", "unknown"),
            ("exact unmodeled bucket", "other-bucket", False, "s3:PutObject", "*", "aws", "allowed"),
            ("unknown target unrelated action", None, True, "s3:GetObject", "*", "aws", "allowed"),
            (
                "unknown target unrelated scope",
                None,
                True,
                "s3:PutObject",
                f"{_BUCKET_ARN}/private/*",
                "aws",
                "allowed",
            ),
            ("unknown target foreign provider", None, True, "s3:PutObject", "*", "aws.foreign", "allowed"),
        )
        for label, target, unknown, action, resource, provider, expected in cases:
            with self.subTest(label=label):
                policy = _resource(
                    "aws_s3_bucket_policy",
                    "orders",
                    {
                        "bucket": target,
                        "policy": json.dumps({"Statement": [_bucket_statement("Deny", action, resource, "*")]}),
                    },
                    provider_config_key=provider,
                )
                if unknown:
                    policy.unknown_values = {"bucket": True}
                inventory = _normalize([_bucket(), policy, _grant_role(), _task_definition(), _service()])
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                facts = aws_facts(service)
                path = facts.ecs_s3_access_paths[0]
                self.assertEqual(path["access_state"], expected)
                if expected == "unknown":
                    self.assertEqual(path["modeled_access_state"], "unknown")
                    self.assertEqual(path["scope_evaluations"][0]["unresolved_deny_resources"], ["*"])
                    self.assertTrue(
                        any(
                            "target association is unresolved" in value
                            for value in facts.ecs_s3_access_path_uncertainties
                        )
                    )

    def test_unknown_target_and_unknown_policy_prevent_access_claim(self) -> None:
        policy = _resource("aws_s3_bucket_policy", "orders", {"bucket": None, "policy": None})
        policy.unknown_values = {"bucket": True, "policy": True}
        inventory = _normalize([_bucket(), policy, _grant_role(), _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        facts = aws_facts(task)
        path = facts.ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["bucket_policy_constraints_complete"])
        self.assertTrue(any("unknown after planning" in reason for reason in facts.ecs_s3_access_path_uncertainties))

    def test_uncertain_principal_only_constrains_its_own_actions_and_scopes(self) -> None:
        for action, resource in (("s3:GetObject", "*"), ("s3:PutObject", f"{_BUCKET_ARN}/private/*")):
            with self.subTest(action=action, resource=resource):
                deny = _statement("Deny", action, resource)
                deny["Principal"] = {"CanonicalUser": "unmapped-user"}
                inventory, _, findings = _evaluate(
                    [
                        _load_balancer(),
                        _bucket(),
                        _bucket_policy([deny]),
                        _grant_role(),
                        _task_definition(),
                        _public_service(),
                    ]
                )
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                path = aws_facts(service).ecs_s3_access_paths[0]
                self.assertEqual(path["access_state"], "allowed")
                self.assertEqual(path["scope_evaluations"][0]["unresolved_deny_resources"], [])
                self.assertEqual(len(findings), 1)

    def test_missing_provider_scope_does_not_prove_a_policy_target_unrelated(self) -> None:
        bucket = _bucket()
        bucket.provider_config_key = None
        policy = _bucket_policy([_bucket_statement("Deny", "s3:PutObject", "*", "*")])
        inventory = _normalize([bucket, policy, _grant_role(), _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        path = aws_facts(task).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["bucket_policy_statements"][0]["target_match"], "unknown")

    def test_uncertain_deny_leaves_an_independent_grant_available(self) -> None:
        policy = _bucket_policy([_bucket_statement("Deny", "s3:GetObject", "*", "*")])
        policy.values["bucket"] = None
        policy.unknown_values = {"bucket": True}
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement("Allow", ["s3:GetObject", "s3:PutObject"], f"{_BUCKET_ARN}/public/*"),
            ],
        )
        inventory = _normalize([_bucket(), policy, role, _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        path = aws_facts(task).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["matched_actions"], ["s3:PutObject"])
        self.assertEqual(path["unknown_actions"], ["s3:GetObject"])

    def test_bucket_policy_on_another_modeled_bucket_does_not_apply(self) -> None:
        other = _bucket("other", arn="arn:aws:s3:::other-data")
        policy = _bucket_policy([_bucket_statement("Deny", "s3:PutObject", "*", "*")])
        policy.values["bucket"] = "other-data"
        inventory = _normalize([other, policy, _bucket(), _grant_role(), _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        path = aws_facts(task).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["bucket_policy_source_addresses"], [])


if __name__ == "__main__":
    unittest.main()
