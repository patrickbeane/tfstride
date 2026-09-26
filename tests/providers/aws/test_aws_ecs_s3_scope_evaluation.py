from __future__ import annotations

import unittest
from itertools import permutations

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _normalize,
    _role,
    _service,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _evaluate,
    _load_balancer_path,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as _public_service,
)
from tfstride.providers.aws.resource_facts import aws_facts

_CONDITION = {"StringNotEquals": {"aws:SourceVpc": "vpc-private"}}


class AwsEcsS3ScopeEvaluationTests(unittest.TestCase):
    def test_deny_scope_relationships(self) -> None:
        cases = (
            ("global object deny", "s3:PutObject", "/public/*", "*", None, "denied"),
            ("global bucket deny", "s3:ListBucket", "", "*", None, "denied"),
            ("disjoint prefixes", "s3:PutObject", "/public/*", "/private/*", None, "allowed"),
            ("case sensitive keys", "s3:PutObject", "/Public/*", "/public/*", None, "allowed"),
            ("equal prefixes", "s3:PutObject", "/public/*", "/public/*", None, "denied"),
            ("covering prefix", "s3:PutObject", "/public/reports/*", "/public/*", None, "denied"),
            ("covering namespace", "s3:PutObject", "/public/*", "/*", None, "denied"),
            ("covered exact object", "s3:PutObject", "/public/report.json", "/public/*", None, "denied"),
            ("distinct exact objects", "s3:PutObject", "/public/a", "/public/b", None, "allowed"),
            ("partial prefix deny", "s3:PutObject", "/*", "/private/*", None, "unknown"),
            ("partial exact deny", "s3:PutObject", "/public/*", "/public/report.json", None, "unknown"),
            ("object deny cannot deny bucket action", "s3:ListBucket", "", "/*", None, "allowed"),
            ("bucket deny cannot deny object action", "s3:PutObject", "/*", "", None, "allowed"),
            ("conditional global deny", "s3:PutObject", "/public/*", "*", _CONDITION, "unknown"),
            ("conditional covering deny", "s3:PutObject", "/public/*", "/*", _CONDITION, "unknown"),
            ("conditional partial deny", "s3:PutObject", "/*", "/private/*", _CONDITION, "unknown"),
            ("conditional disjoint deny", "s3:PutObject", "/public/*", "/private/*", _CONDITION, "allowed"),
            ("unsupported deny glob", "s3:PutObject", "/public/*", "/public/*.json", None, "unknown"),
            ("wildcard bucket deny", "s3:PutObject", "/public/*", "arn:aws:s3:::orders-*/*", None, "unknown"),
            (
                "wildcard crossing separator",
                "s3:PutObject",
                "/public/*",
                "arn:aws:s3:::orders-*/private/*",
                None,
                "unknown",
            ),
            ("other bucket deny", "s3:PutObject", "/public/*", "arn:aws:s3:::archive/*", None, "allowed"),
            ("other partition deny", "s3:PutObject", "/public/*", "arn:aws-cn:s3:::orders-data/*", None, "allowed"),
        )
        for label, action, allow_suffix, deny_suffix, condition, expected in cases:
            with self.subTest(label=label):
                allow_resource = _BUCKET_ARN + allow_suffix
                deny_resource = (
                    deny_suffix if deny_suffix == "*" or deny_suffix.startswith("arn:") else _BUCKET_ARN + deny_suffix
                )
                inventory = _normalize(
                    [
                        _bucket(),
                        _role(
                            "orders_task",
                            _TASK_ROLE_ARN,
                            [
                                _statement("Allow", action, allow_resource),
                                _statement("Deny", action, deny_resource, condition=condition),
                            ],
                        ),
                        _task_definition(),
                        _service(),
                    ]
                )
                for address in ("aws_ecs_task_definition.orders", "aws_ecs_service.orders"):
                    workload = inventory.get_by_address(address)
                    assert workload is not None
                    facts = aws_facts(workload)
                    self.assertEqual(len(facts.ecs_s3_access_paths), 1)
                    path = facts.ecs_s3_access_paths[0]
                    self.assertEqual(path["access_state"], expected)
                    self.assertEqual(path["matched_actions"], [action] if expected == "allowed" else [])
                    self.assertEqual(path["denied_actions"], [action] if expected == "denied" else [])
                    self.assertEqual(path["unknown_actions"], [action] if expected == "unknown" else [])
                    evaluations = path["scope_evaluations"]
                    self.assertEqual(len(evaluations), 1)
                    self.assertEqual(evaluations[0]["action"], action)
                    self.assertEqual(evaluations[0]["resource"], allow_resource)
                    self.assertEqual(evaluations[0]["modeled_access_state"], expected)
                    if expected == "unknown":
                        self.assertTrue(facts.ecs_s3_access_path_uncertainties)
                    if deny_resource == "*":
                        self.assertIn("*", path["deny_policy_resources"])

    def test_independent_allow_scopes_survive_denied_and_uncertain_scopes(self) -> None:
        for condition, blocked_state in ((None, "denied"), (_CONDITION, "unknown")):
            with self.subTest(blocked_state=blocked_state):
                inventory, _, findings = _evaluate(
                    [
                        *_load_balancer_path(),
                        _bucket(),
                        _role(
                            "orders_task",
                            _TASK_ROLE_ARN,
                            [
                                _statement(
                                    "Allow",
                                    "s3:PutObject",
                                    [
                                        f"{_BUCKET_ARN}/private/*",
                                        f"{_BUCKET_ARN}/public/*",
                                    ],
                                ),
                                _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/private/*", condition=condition),
                            ],
                        ),
                        _task_definition(),
                        _public_service(),
                    ]
                )
                self.assertEqual([finding.rule_id for finding in findings], ["aws-public-ecs-s3-mutation-access"])
                workload = inventory.get_by_address("aws_ecs_service.orders")
                assert workload is not None
                path = aws_facts(workload).ecs_s3_access_paths[0]
                self.assertEqual(
                    [(scope["resource"], scope["modeled_access_state"]) for scope in path["scope_evaluations"]],
                    [(f"{_BUCKET_ARN}/private/*", blocked_state), (f"{_BUCKET_ARN}/public/*", "allowed")],
                )
                evidence = {item.key: item.values for item in findings[0].evidence}
                self.assertIn(
                    f"authorized_scopes=s3:PutObject on {_BUCKET_ARN}/public/*",
                    evidence["s3_mutation_paths"][0],
                )

    def test_partial_deny_does_not_hide_a_separate_exact_grant(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", [f"{_BUCKET_ARN}/*", f"{_BUCKET_ARN}/public/report.json"]),
                        _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/private/*"),
                    ],
                ),
                _task_definition(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert workload is not None
        path = aws_facts(workload).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(
            [(scope["resource"], scope["modeled_access_state"]) for scope in path["scope_evaluations"]],
            [(f"{_BUCKET_ARN}/*", "unknown"), (f"{_BUCKET_ARN}/public/report.json", "allowed")],
        )

    def test_action_resource_associations_and_results_are_order_independent(self) -> None:
        resources = [_BUCKET_ARN, f"{_BUCKET_ARN}/private/*", f"{_BUCKET_ARN}/public/*"]
        expected = [
            ("s3:ListBucket", _BUCKET_ARN, "denied"),
            ("s3:PutObject", f"{_BUCKET_ARN}/private/*", "denied"),
            ("s3:PutObject", f"{_BUCKET_ARN}/public/*", "allowed"),
        ]
        for reverse_resources in (False, True):
            allow_resources = list(reversed(resources)) if reverse_resources else resources
            statements = [
                _statement("Allow", ["s3:PutObject", "s3:ListBucket"], allow_resources),
                _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/private/*"),
                _statement("Deny", "s3:ListBucket", _BUCKET_ARN),
            ]
            for ordering in permutations(statements):
                with self.subTest(reverse_resources=reverse_resources, ordering=ordering):
                    inventory = _normalize(
                        [
                            _bucket(),
                            _role("orders_task", _TASK_ROLE_ARN, list(ordering)),
                            _task_definition(),
                        ]
                    )
                    workload = inventory.get_by_address("aws_ecs_task_definition.orders")
                    assert workload is not None
                    path = aws_facts(workload).ecs_s3_access_paths[0]
                    self.assertEqual(path["matched_actions"], ["s3:PutObject"])
                    self.assertEqual(path["denied_actions"], ["s3:ListBucket"])
                    self.assertEqual(
                        [
                            (scope["action"], scope["resource"], scope["modeled_access_state"])
                            for scope in path["scope_evaluations"]
                        ],
                        expected,
                    )

    def test_separate_denies_can_cover_all_separate_allow_scopes(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", [f"{_BUCKET_ARN}/public/*", f"{_BUCKET_ARN}/private/*"]),
                        _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/public/*"),
                        _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/private/*"),
                    ],
                ),
                _task_definition(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert workload is not None
        path = aws_facts(workload).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "denied")
        self.assertEqual(len(path["scope_evaluations"]), 2)
        self.assertTrue(all(scope["modeled_access_state"] == "denied" for scope in path["scope_evaluations"]))

    def test_unconditional_grant_is_not_hidden_by_duplicate_conditional_grant(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*", condition=_CONDITION),
                        _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*"),
                    ],
                ),
                _task_definition(),
            ]
        )
        workload = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert workload is not None
        path = aws_facts(workload).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(len(path["scope_evaluations"]), 1)

    def test_global_and_partial_denies_do_not_emit_mutation_findings(self) -> None:
        for resource, condition in (("*", None), (f"{_BUCKET_ARN}/private/*", None), ("*", _CONDITION)):
            with self.subTest(resource=resource, condition=condition):
                _, _, findings = _evaluate(
                    [
                        *_load_balancer_path(),
                        _bucket(),
                        _role(
                            "orders_task",
                            _TASK_ROLE_ARN,
                            [
                                _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                                _statement("Deny", "s3:PutObject", resource, condition=condition),
                            ],
                        ),
                        _task_definition(),
                        _public_service(),
                    ]
                )
                self.assertEqual([finding.rule_id for finding in findings], [])


if __name__ == "__main__":
    unittest.main()
