from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_secrets_manager_operation_authorization import (
    _EXECUTION_ROLE_ARN,
    _ROLE_ARN,
    _SECRET_ARN,
    _policy,
    _resource,
    _role,
    _secret,
    _statement,
    _unresolved_attachment,
)
from tests.providers.test_public_workload_managed_key_operation_boundaries import (
    _aws_ecs_service,
    _aws_public_edge,
    _aws_task_definition,
)
from tests.providers.test_public_workload_secret_integrity_boundaries import (
    _aws_execution_role_with_secret_admin,
    _aws_runtime_role,
    _aws_secret_policy,
)
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


def _task_definition(
    *,
    task_role_arn: str | None = _ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
) -> TerraformResource:
    return _resource(
        "aws_ecs_task_definition",
        "orders",
        {
            "arn": "arn:aws:ecs:us-east-1:111122223333:task-definition/orders:1",
            "family": "orders",
            "revision": 1,
            "task_role_arn": task_role_arn,
            "execution_role_arn": execution_role_arn,
            "network_mode": "awsvpc",
            "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
        },
        unknown_values={"task_role_arn": True} if task_role_arn is None else None,
    )


def _service() -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": "orders:1",
        },
    )


class AwsEcsSecretManagementPathTests(unittest.TestCase):
    def test_task_role_mutation_authority_projects_to_service_with_exact_evidence(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                *_aws_public_edge(),
                _aws_runtime_role(),
                _aws_execution_role_with_secret_admin(),
                _aws_task_definition(),
                _aws_ecs_service(),
                _secret(),
                _aws_secret_policy(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_paths = aws_facts(task_definition).ecs_secret_management_paths
        self.assertEqual(
            [path["operation"] for path in task_paths],
            [
                "secretsmanager:PutSecretValue",
                "secretsmanager:UpdateSecret",
                "secretsmanager:UpdateSecretVersionStage",
            ],
        )
        self.assertEqual(
            [path["operation_class"] for path in task_paths],
            [
                "value_mutation",
                "value_mutation",
                "version_stage_mutation",
            ],
        )
        self.assertTrue(all(path["management_effect"] == "tampering" for path in task_paths))
        self.assertTrue(all(path["role_kind"] == "ecs_task_role" for path in task_paths))
        self.assertTrue(all(path["role_arn"] == _ROLE_ARN for path in task_paths))
        self.assertNotIn(
            _EXECUTION_ROLE_ARN,
            {path["role_arn"] for path in task_paths},
        )
        self.assertTrue(all(path["secret_arn"] == _SECRET_ARN for path in task_paths))
        self.assertTrue(
            all(
                path["terraform_recovery_window_in_days"] == 21
                and path["recovery_window_evidence_scope"] == "terraform_resource_deletion_only"
                for path in task_paths
            )
        )

        put_path = next(path for path in task_paths if path["operation"] == "secretsmanager:PutSecretValue")
        self.assertEqual(
            put_path["authorization_bases"],
            ["identity_policy", "resource_policy_direct"],
        )
        self.assertTrue(put_path["conditional_policy_evidence_present"])
        self.assertFalse(put_path["authorization_requires_condition_evaluation"])
        self.assertEqual(
            put_path["secrets_manager_resource_policy_source_addresses"],
            ["aws_secretsmanager_secret_policy.orders"],
        )
        self.assertEqual(
            put_path["authorization_record"]["authorization_state"],
            "allowed",
        )

        service_paths = aws_facts(service).ecs_secret_management_paths
        self.assertEqual(len(service_paths), 3)
        self.assertTrue(all(path["workload_address"] == service.address for path in service_paths))
        self.assertTrue(all(path["task_definition_address"] == task_definition.address for path in service_paths))
        self.assertTrue(all(path["internet_facing_load_balancers"] == ["aws_lb.public"] for path in service_paths))

    def test_delete_authority_is_a_disruption_path_without_runtime_recovery_claim(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _secret(recovery_window_in_days=30),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:DeleteSecret",
                    )
                ),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        path = aws_facts(task_definition).ecs_secret_management_paths[0]
        self.assertEqual(path["operation"], "secretsmanager:DeleteSecret")
        self.assertEqual(path["operation_class"], "destructive_administration")
        self.assertEqual(path["management_effect"], "disruption")
        self.assertEqual(path["authorization_bases"], ["identity_policy"])
        self.assertEqual(path["terraform_recovery_window_in_days"], 30)
        self.assertEqual(
            path["recovery_window_evidence_scope"],
            "terraform_resource_deletion_only",
        )
        self.assertEqual(
            aws_facts(service).ecs_secret_management_paths[0]["operation"],
            "secretsmanager:DeleteSecret",
        )

    def test_execution_role_authority_never_becomes_runtime_management_path(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _secret(),
                _role(),
                _role(
                    _statement(
                        "Allow",
                        [
                            "secretsmanager:PutSecretValue",
                            "secretsmanager:DeleteSecret",
                        ],
                    ),
                    name="orders_execution",
                    role_arn=_EXECUTION_ROLE_ARN,
                ),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        secret = inventory.get_by_address("aws_secretsmanager_secret.orders")
        assert task_definition is not None
        assert service is not None
        assert secret is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_secret_management_paths,
            [],
        )
        self.assertEqual(aws_facts(service).ecs_secret_management_paths, [])
        self.assertEqual(
            {
                authorization["principal_arn"]
                for authorization in aws_facts(secret).secrets_manager_operation_authorizations
            },
            {_EXECUTION_ROLE_ARN},
        )

    def test_unknown_authorization_becomes_uncertainty_without_a_path(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _secret(),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                        condition={"StringEquals": {"aws:PrincipalTag/environment": "production"}},
                    )
                ),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_secret_management_paths,
            [],
        )
        self.assertTrue(
            any(
                "unresolved secretsmanager:PutSecretValue authorization" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_secret_management_path_uncertainties
            )
        )
        self.assertEqual(aws_facts(service).ecs_secret_management_paths, [])
        self.assertTrue(aws_facts(service).ecs_secret_management_path_uncertainties)

    def test_unresolved_attached_policy_remains_visible_without_paths(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _secret(),
                _role(),
                _unresolved_attachment(),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_secret_management_paths,
            [],
        )
        self.assertTrue(
            any(
                "identity-policy evidence is incomplete" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_secret_management_path_uncertainties
            )
        )
        self.assertTrue(aws_facts(service).ecs_secret_management_path_uncertainties)

    def test_unknown_task_role_arn_remains_visible_without_a_path(self) -> None:
        role = _resource(
            "aws_iam_role",
            "orders_task",
            {
                "name": "orders-task",
                "arn": None,
                "inline_policy": [
                    {
                        "name": "secret-management",
                        "policy": _policy(
                            _statement(
                                "Allow",
                                "secretsmanager:PutSecretValue",
                            )
                        ),
                    }
                ],
            },
            unknown_values={"arn": True},
        )
        inventory = AwsNormalizer().normalize(
            [
                _secret(),
                role,
                _task_definition(
                    task_role_arn="aws_iam_role.orders_task",
                ),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_secret_management_paths,
            [],
        )
        self.assertTrue(
            any(
                "has no exact IAM role ARN" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_secret_management_path_uncertainties
            )
        )

    def test_unknown_secret_identity_does_not_create_a_management_path(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _secret(arn=None),
                _role(
                    _statement(
                        "Allow",
                        "secretsmanager:PutSecretValue",
                    )
                ),
                _task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(
            aws_facts(task_definition).ecs_secret_management_paths,
            [],
        )
        self.assertTrue(
            any(
                "has no exact ARN" in uncertainty
                for uncertainty in aws_facts(task_definition).ecs_secret_management_path_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
