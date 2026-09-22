from __future__ import annotations

import json
import unittest

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
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
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _evaluate,
    _load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_s3_mutation_rules import (
    _service as _public_service,
)
from tests.providers.test_protected_data_key_authority_convergence import _aws_resources
from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_decoration.ecs_s3_access_paths import ModelEcsS3AccessPathsStage
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder

_BOUNDARY_ARN = "arn:aws:iam::111122223333:policy/orders-boundary"


def _boundary_roles() -> dict[str, TerraformResource]:
    roles: dict[str, TerraformResource] = {}
    for name, boundary, unknown in (
        ("configured", _BOUNDARY_ARN, False),
        ("unknown", None, True),
        ("unknown with stale value", _BOUNDARY_ARN, True),
        ("malformed", {"arn": _BOUNDARY_ARN}, False),
    ):
        role = _role("orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")])
        role.values["permissions_boundary"] = boundary
        if unknown:
            role.unknown_values = {"permissions_boundary": True}
        roles[name] = role
    return roles


class AwsEcsS3PermissionsBoundaryTests(unittest.TestCase):
    def test_configured_and_unknown_boundaries_preserve_uncertain_task_and_service_paths(self) -> None:
        for name, role_resource in _boundary_roles().items():
            with self.subTest(name=name):
                inventory = _normalize([_bucket(), role_resource, _task_definition(), _service()])
                role = inventory.get_by_address(role_resource.address)
                assert role is not None
                role_facts = aws_facts(role)
                self.assertEqual(role_facts.iam_policy_completeness_state, "complete")
                self.assertEqual(
                    role_facts.iam_permissions_boundary_state,
                    "configured" if name == "configured" else "unknown",
                )
                for address in ("aws_ecs_task_definition.orders", "aws_ecs_service.orders"):
                    workload = inventory.get_by_address(address)
                    assert workload is not None
                    facts = aws_facts(workload)
                    self.assertEqual(len(facts.ecs_s3_access_paths), 1)
                    path = facts.ecs_s3_access_paths[0]
                    self.assertEqual(path["modeled_access_state"], "allowed")
                    self.assertTrue(path["role_policy_complete"])
                    self.assertEqual(path["matched_actions"], ["s3:PutObject"])
                    self.assertEqual(path["scope_evaluations"][0]["modeled_access_state"], "allowed")
                    self.assertEqual(path["access_state"], "unknown")
                    uncertainties = facts.ecs_s3_access_path_uncertainties
                    self.assertTrue(
                        any(
                            "aws_iam_role.orders_task" in value and "permissions-boundary" in value
                            for value in uncertainties
                        )
                    )
                    if name == "configured":
                        self.assertTrue(
                            any(
                                _BOUNDARY_ARN in value and "intersection is not modeled" in value
                                for value in uncertainties
                            )
                        )
                    else:
                        for reason in role_facts.iam_permissions_boundary_uncertainties:
                            self.assertTrue(any(reason in value for value in uncertainties))

    def test_boundaries_suppress_public_mutation_findings(self) -> None:
        for name, role in _boundary_roles().items():
            with self.subTest(name=name):
                _, _, findings = _evaluate(
                    [
                        _load_balancer(),
                        _bucket(),
                        role,
                        _task_definition(),
                        _public_service(),
                    ]
                )
                self.assertEqual([finding.rule_id for finding in findings], [])

    def test_modeled_permissive_boundary_does_not_imply_compatibility(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _boundary_roles()["configured"],
                _resource(
                    "aws_iam_policy",
                    "boundary",
                    {
                        "arn": _BOUNDARY_ARN,
                        "policy": json.dumps({"Statement": [_statement("Allow", "s3:*", "*")]}),
                    },
                ),
                _task_definition(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
        self.assertTrue(any("intersection is not modeled" in value for value in facts.ecs_s3_access_path_uncertainties))

    def test_absent_boundary_and_execution_role_boundary_do_not_block_task_role_access(self) -> None:
        for explicit_null in (False, True):
            with self.subTest(explicit_null=explicit_null):
                task_role = _role(
                    "orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")]
                )
                if explicit_null:
                    task_role.values["permissions_boundary"] = None
                execution_role = _role("orders_execution", _EXECUTION_ROLE_ARN)
                execution_role.values["permissions_boundary"] = _BOUNDARY_ARN
                inventory = _normalize([_bucket(), task_role, execution_role, _task_definition(), _service()])
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                facts = aws_facts(service)
                self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "allowed")
                self.assertEqual(facts.ecs_s3_access_path_uncertainties, [])

    def test_missing_normalized_boundary_state_does_not_imply_absence(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role("orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")]),
                _task_definition(),
            ]
        )
        role = inventory.get_by_address("aws_iam_role.orders_task")
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert role is not None and task is not None
        aws_facts(role).set(AwsResourceMetadata.IAM_PERMISSIONS_BOUNDARY_STATE, None)
        resources = list(inventory.resources)
        ModelEcsS3AccessPathsStage().apply(
            resources,
            AwsDecorationContext(index=AwsResourceIndexBuilder().build(resources)),
        )
        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
        self.assertTrue(
            any("permissions-boundary state is unresolved" in value for value in facts.ecs_s3_access_path_uncertainties)
        )

    def test_boundary_cannot_restore_explicitly_denied_access(self) -> None:
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                _statement("Deny", "s3:PutObject", "*"),
            ],
        )
        role.values["permissions_boundary"] = _BOUNDARY_ARN
        inventory = _normalize([_bucket(), role, _task_definition()])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        path = aws_facts(task).ecs_s3_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "denied")
        self.assertEqual(path["access_state"], "denied")
        self.assertEqual(path["matched_actions"], [])

    def test_boundaries_prevent_payload_read_and_decrypt_convergence(self) -> None:
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                resources = _aws_resources()
                role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
                role.values["permissions_boundary"] = _BOUNDARY_ARN
                if unknown:
                    role.unknown_values = {"permissions_boundary": True}
                inventory = _normalize(resources)
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                facts = aws_facts(service)
                self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "unknown")
                self.assertEqual(facts.ecs_s3_protected_data_convergences, [])
                self.assertTrue(
                    any("permissions-boundary" in value for value in facts.ecs_s3_access_path_uncertainties)
                )


if __name__ == "__main__":
    unittest.main()
