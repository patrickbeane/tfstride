from __future__ import annotations

import json
import unittest
from copy import deepcopy
from typing import cast

from tests.providers.aws.test_aws_ecs_kms_operation_paths import _grant
from tests.providers.test_protected_data_key_authority_convergence import (
    _AWS_BUCKET_ARN,
    AWS_KEY_ARNS,
    _aws_bucket_encryption,
    _aws_exact_key_mismatch_resources,
    _aws_identity_statement,
    _aws_key_policy,
    _aws_resources,
    _reference_resolution,
    aws_role,
)
from tfstride.models import (
    NormalizedResource,
    ResourceInventory,
    TerraformReferenceResolutionState,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs_s3_protected_data_convergence import (
    ModelEcsS3ProtectedDataConvergenceStage,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_EXECUTION_ROLE_ARN = "arn:aws:iam::111122223333:role/orders-execution"


def _resource(
    inventory: ResourceInventory,
    address: str,
) -> NormalizedResource:
    resource = inventory.get_by_address(address)
    assert resource is not None
    return resource


def _normalize(resources: list[TerraformResource]) -> ResourceInventory:
    return AwsNormalizer().normalize(resources)


def _inline_policy_document(
    role: TerraformResource,
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    inline_policies = cast(
        list[dict[str, object]],
        role.values["inline_policy"],
    )
    inline_policy = inline_policies[0]
    policy = inline_policy["policy"]
    assert isinstance(policy, str)
    policy_document = cast(dict[str, object], json.loads(policy))
    statements = cast(
        list[dict[str, object]],
        policy_document["Statement"],
    )
    return inline_policy, policy_document, statements


class AwsEcsS3ProtectedDataConvergenceTests(unittest.TestCase):
    def test_exact_task_role_read_dependency_and_decrypt_authority_converge(
        self,
    ) -> None:
        inventory = _normalize(_aws_resources())
        service = _resource(inventory, "aws_ecs_service.orders")
        task_definition = _resource(
            inventory,
            "aws_ecs_task_definition.orders",
        )
        facts = aws_facts(service)

        self.assertEqual(len(facts.ecs_s3_protected_data_convergences), 1)
        convergence = facts.ecs_s3_protected_data_convergences[0]
        self.assertEqual(convergence["workload_address"], service.address)
        self.assertEqual(convergence["workload_type"], "aws_ecs_service")
        self.assertEqual(
            convergence["task_definition_address"],
            task_definition.address,
        )
        self.assertEqual(
            convergence["role_address"],
            "aws_iam_role.orders_task",
        )
        self.assertEqual(
            convergence["role_arn"],
            "arn:aws:iam::111122223333:role/orders-task",
        )
        self.assertEqual(
            convergence["bucket_address"],
            "aws_s3_bucket.orders",
        )
        self.assertEqual(convergence["bucket_arn"], _AWS_BUCKET_ARN)
        self.assertEqual(convergence["key_address"], "aws_kms_key.data")
        self.assertEqual(convergence["key_arn"], AWS_KEY_ARNS["data"])
        self.assertEqual(convergence["operation"], "kms:Decrypt")
        self.assertEqual(convergence["access_class"], "read")
        self.assertIs(convergence["runtime_identity_match"], True)
        self.assertIs(convergence["protected_resource_match"], True)
        self.assertIs(convergence["key_identity_match"], True)
        self.assertEqual(convergence["convergence_state"], "resolved")
        self.assertEqual(
            convergence["evaluation_basis"],
            "exact_s3_access_kms_dependency_and_decrypt_authority",
        )
        self.assertEqual(
            convergence["access_path"]["role_arn"],
            convergence["key_operation_path"]["role_arn"],
        )
        self.assertEqual(
            convergence["access_path"]["bucket_address"],
            convergence["encryption_dependency"]["dependent_address"],
        )
        self.assertEqual(
            convergence["key_operation_path"]["key_address"],
            convergence["encryption_dependency"]["key_address"],
        )
        self.assertEqual(
            convergence["encryption_dependency"]["reference_kind"],
            "alias_arn",
        )
        self.assertEqual(
            convergence["encryption_dependency"]["alias_address"],
            "aws_kms_alias.data",
        )
        self.assertEqual(convergence["posture_uncertainties"], [])
        self.assertEqual(
            facts.ecs_s3_protected_data_convergence_uncertainties,
            [],
        )
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_protected_data_convergences,
            [],
        )

    def test_symbolic_exact_key_dependency_converges_when_kms_ownership_is_known(
        self,
    ) -> None:
        resources = [
            resource
            for resource in _aws_resources()
            if resource.address != "aws_s3_bucket_server_side_encryption_configuration.orders"
        ]
        encryption = _aws_bucket_encryption(
            key_reference=None,
            resolution=_reference_resolution(
                (
                    "rule",
                    0,
                    "apply_server_side_encryption_by_default",
                    0,
                    "kms_master_key_id",
                ),
                (("aws_kms_key.data", ".arn"),),
                state=TerraformReferenceResolutionState.SYMBOLIC,
            ),
        )
        rules = encryption.values["rule"]
        assert isinstance(rules, list)
        defaults = rules[0]["apply_server_side_encryption_by_default"]
        assert isinstance(defaults, list)
        defaults[0]["sse_algorithm"] = "aws:kms"
        unknown_rules = cast(
            list[dict[str, object]],
            encryption.unknown_values["rule"],
        )
        unknown_defaults = cast(
            list[dict[str, object]],
            unknown_rules[0]["apply_server_side_encryption_by_default"],
        )
        unknown_defaults[0].pop("sse_algorithm", None)
        resources.append(encryption)

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        convergence = aws_facts(service).ecs_s3_protected_data_convergences[0]
        dependency = convergence["encryption_dependency"]
        self.assertEqual(dependency["reference_provenance"], "configuration_reference")
        self.assertEqual(dependency["reference_kind"], "terraform_reference")
        self.assertEqual(
            dependency["candidate_targets"],
            [{"address": "aws_kms_key.data", "target_kind": "key"}],
        )
        self.assertEqual(
            dependency["encryption_ownership_state"],
            "customer_managed",
        )
        self.assertEqual(convergence["key_address"], "aws_kms_key.data")

    def test_symbolic_key_with_unknown_encryption_algorithm_remains_uncertain(
        self,
    ) -> None:
        resources = [
            resource
            for resource in _aws_resources()
            if resource.address != "aws_s3_bucket_server_side_encryption_configuration.orders"
        ]
        resources.append(
            _aws_bucket_encryption(
                key_reference=None,
                resolution=_reference_resolution(
                    (
                        "rule",
                        0,
                        "apply_server_side_encryption_by_default",
                        0,
                        "kms_master_key_id",
                    ),
                    (("aws_kms_key.data", ".arn"),),
                    state=TerraformReferenceResolutionState.SYMBOLIC,
                ),
            )
        )

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        dependency = aws_facts(bucket).kms_encryption_dependencies[0]
        facts = aws_facts(service)
        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertEqual(
            dependency["encryption_ownership_state"],
            "customer_managed",
        )
        self.assertEqual(facts.ecs_s3_protected_data_convergences, [])
        self.assertTrue(
            any(
                "sse_algorithm is unknown after planning" in uncertainty
                for uncertainty in (facts.ecs_s3_protected_data_convergence_uncertainties)
            )
        )

    def test_service_managed_sse_kms_stays_quiet(self) -> None:
        resources = [
            resource
            for resource in _aws_resources()
            if resource.address != "aws_s3_bucket_server_side_encryption_configuration.orders"
        ]
        encryption = _aws_bucket_encryption()
        rules = cast(list[dict[str, object]], encryption.values["rule"])
        defaults = cast(
            list[dict[str, object]],
            rules[0]["apply_server_side_encryption_by_default"],
        )
        defaults[0]["kms_master_key_id"] = None
        resources.append(encryption)

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        bucket = _resource(inventory, "aws_s3_bucket.orders")

        self.assertEqual(
            aws_facts(bucket).s3_encryption_algorithm,
            "aws:kms",
        )
        self.assertEqual(
            aws_facts(bucket).kms_encryption_dependencies,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_s3_protected_data_convergences,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_s3_protected_data_convergence_uncertainties,
            [],
        )

    def test_resolved_service_managed_dependency_is_not_uncertain(self) -> None:
        inventory = _normalize(_aws_resources())
        service = _resource(inventory, "aws_ecs_service.orders")
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        dependency = deepcopy(aws_facts(bucket).kms_encryption_dependencies[0])
        dependency["encryption_ownership_state"] = "service_managed"
        aws_facts(bucket).set_kms_encryption_dependency_posture(
            dependencies=[dependency],
            uncertainties=[],
        )

        resources = list(inventory.resources)
        ModelEcsS3ProtectedDataConvergenceStage().apply(
            resources,
            AwsDecorationContext(
                index=AwsResourceIndexBuilder().build(resources),
            ),
        )

        self.assertEqual(
            aws_facts(service).ecs_s3_protected_data_convergences,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_s3_protected_data_convergence_uncertainties,
            [],
        )

    def test_exact_but_unequal_keys_do_not_converge(self) -> None:
        inventory = _normalize(_aws_exact_key_mismatch_resources())
        service = _resource(inventory, "aws_ecs_service.orders")
        bucket = _resource(inventory, "aws_s3_bucket.orders")
        facts = aws_facts(service)
        access_path = facts.ecs_s3_access_paths[0]
        operation_path = facts.ecs_kms_operation_paths[0]
        dependency = aws_facts(bucket).kms_encryption_dependencies[0]

        self.assertEqual(access_path["role_arn"], operation_path["role_arn"])
        self.assertEqual(
            access_path["bucket_address"],
            dependency["dependent_address"],
        )
        self.assertEqual(dependency["resolution_state"], "resolved")
        self.assertNotEqual(
            dependency["key_address"],
            operation_path["key_address"],
        )
        self.assertEqual(
            facts.ecs_s3_protected_data_convergences,
            [],
        )
        self.assertEqual(
            facts.ecs_s3_protected_data_convergence_uncertainties,
            [],
        )

    def test_ambiguous_dependency_remains_uncertain_without_convergence(
        self,
    ) -> None:
        inventory = _normalize(_aws_resources(ambiguous_dependency=True))
        service = _resource(inventory, "aws_ecs_service.orders")
        facts = aws_facts(service)

        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "allowed")
        self.assertEqual(
            [path["operation"] for path in facts.ecs_kms_operation_paths],
            ["kms:Decrypt"],
        )
        self.assertEqual(facts.ecs_s3_protected_data_convergences, [])
        self.assertTrue(
            any(
                "KMS dependency is ambiguous" in uncertainty
                for uncertainty in (facts.ecs_s3_protected_data_convergence_uncertainties)
            )
        )

    def test_conditional_denied_and_incomplete_authority_fail_closed(
        self,
    ) -> None:
        cases = {
            "conditional_kms": _aws_resources(
                kms_condition={
                    "StringEquals": {
                        "kms:EncryptionContext:service": "orders",
                    }
                }
            ),
            "conditional_s3": _aws_resources(
                s3_condition={
                    "StringLike": {
                        "s3:prefix": ["customer/*"],
                    }
                }
            ),
            "denied_kms": _aws_resources(deny_decrypt=True),
            "incomplete_policy": _aws_resources(unresolved_policy=True),
        }
        for case, resources in cases.items():
            with self.subTest(case=case):
                inventory = _normalize(resources)
                service = _resource(inventory, "aws_ecs_service.orders")
                self.assertEqual(
                    aws_facts(service).ecs_s3_protected_data_convergences,
                    [],
                )

    def test_bucket_policy_denies_constrain_payload_convergence_by_action(self) -> None:
        for action, condition, expected in (
            ("s3:GetObject", None, 0),
            ("s3:GetObject", {"Bool": {"aws:SecureTransport": "false"}}, 0),
            ("s3:ListBucket", None, 1),
        ):
            with self.subTest(action=action, condition=condition):
                resources = _aws_resources()
                statement = {"Effect": "Deny", "Action": action, "Resource": "*", "Principal": "*"}
                if condition is not None:
                    statement["Condition"] = condition
                resources.append(
                    TerraformResource(
                        address="aws_s3_bucket_policy.data",
                        mode="managed",
                        resource_type="aws_s3_bucket_policy",
                        name="data",
                        provider_name="registry.terraform.io/hashicorp/aws",
                        values={
                            "bucket": _AWS_BUCKET_ARN.removeprefix("arn:aws:s3:::"),
                            "policy": json.dumps({"Statement": [statement]}),
                        },
                        provider_config_key=None,
                    )
                )
                inventory = _normalize(resources)
                service = _resource(inventory, "aws_ecs_service.orders")
                facts = aws_facts(service)
                self.assertEqual(len(facts.ecs_s3_protected_data_convergences), expected)

    def test_s3_deny_scopes_constrain_payload_read_convergence(self) -> None:
        for deny_resource, expected_count in (
            ("*", 0),
            (f"{_AWS_BUCKET_ARN}/private/*", 1),
            (f"{_AWS_BUCKET_ARN}/public/private/*", 0),
        ):
            with self.subTest(deny_resource=deny_resource):
                resources = _aws_resources()
                role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
                inline_policy, document, statements = _inline_policy_document(role)
                read_allow = next(statement for statement in statements if statement.get("Action") == "s3:GetObject")
                read_allow["Resource"] = f"{_AWS_BUCKET_ARN}/public/*"
                statements.append(
                    {
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "Resource": deny_resource,
                    }
                )
                inline_policy["policy"] = json.dumps(document)
                inventory = _normalize(resources)
                facts = aws_facts(_resource(inventory, "aws_ecs_service.orders"))
                self.assertEqual(len(facts.ecs_s3_protected_data_convergences), expected_count)

    def test_unrelated_s3_deny_and_condition_do_not_suppress_exact_read(
        self,
    ) -> None:
        resources = _aws_resources()
        role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
        inline_policy, policy_document, statements = _inline_policy_document(role)
        statements.extend(
            [
                {
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": f"{_AWS_BUCKET_ARN}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:RestoreObject",
                    "Resource": f"{_AWS_BUCKET_ARN}/*",
                    "Condition": {"StringEquals": {"s3:x-amz-restore-request": "true"}},
                },
            ]
        )
        inline_policy["policy"] = json.dumps(policy_document)

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        facts = aws_facts(service)
        access = facts.ecs_s3_access_paths[0]
        self.assertIn("read", access["access_classes"])
        self.assertIn("write", access["denied_access_classes"])
        self.assertIn("write", access["unknown_access_classes"])
        self.assertTrue(access["explicit_deny"])
        self.assertTrue(access["conditional_evaluation_required"])
        self.assertEqual(len(facts.ecs_s3_protected_data_convergences), 1)

    def test_incidental_constrained_grant_does_not_hide_direct_authority(
        self,
    ) -> None:
        resources = _aws_resources()
        resources.append(_grant("data_runtime", "data", ["Decrypt"]))

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        facts = aws_facts(service)
        operation = facts.ecs_kms_operation_paths[0]
        self.assertEqual(
            set(operation["authorization_bases"]),
            {"key_policy_direct", "grant"},
        )
        self.assertEqual(operation["constraint_state"], "encryption_context")
        self.assertEqual(len(facts.ecs_s3_protected_data_convergences), 1)
        self.assertFalse(
            any(
                "not proven compatible with S3 data" in uncertainty
                for uncertainty in (facts.ecs_s3_protected_data_convergence_uncertainties)
            )
        )

    def test_encryption_context_grant_is_not_assumed_compatible_with_s3(
        self,
    ) -> None:
        resources = _aws_resources()
        role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
        inline_policy, policy_document, statements = _inline_policy_document(role)
        policy_document["Statement"] = [
            statement for statement in statements if statement.get("Action") != "kms:Decrypt"
        ]
        inline_policy["policy"] = json.dumps(policy_document)
        key = next(resource for resource in resources if resource.address == "aws_kms_key.data")
        key.values["policy"] = _aws_key_policy(direct_runtime_allow=False)
        resources.append(_grant("data_runtime", "data", ["Decrypt"]))

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        facts = aws_facts(service)
        self.assertEqual(
            [path["constraint_state"] for path in facts.ecs_kms_operation_paths],
            ["encryption_context"],
        )
        self.assertEqual(facts.ecs_s3_protected_data_convergences, [])
        self.assertTrue(
            any(
                "not proven compatible with S3 data" in uncertainty
                for uncertainty in (facts.ecs_s3_protected_data_convergence_uncertainties)
            )
        )

    def test_bucket_metadata_read_does_not_become_protected_data_access(
        self,
    ) -> None:
        resources = _aws_resources()
        role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
        inline_policy, policy_document, statements = _inline_policy_document(role)
        for statement in statements:
            if statement.get("Action") == "s3:GetObject":
                statement["Action"] = "s3:ListBucket"
                statement["Resource"] = _AWS_BUCKET_ARN
        inline_policy["policy"] = json.dumps(policy_document)

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        facts = aws_facts(service)
        self.assertEqual(facts.ecs_s3_access_paths[0]["access_state"], "allowed")
        self.assertIn("read", facts.ecs_s3_access_paths[0]["access_classes"])
        self.assertEqual(facts.ecs_s3_protected_data_convergences, [])
        self.assertEqual(
            facts.ecs_s3_protected_data_convergence_uncertainties,
            [],
        )

    def test_execution_role_authority_is_not_runtime_convergence(self) -> None:
        resources = _aws_resources()
        task_role = next(resource for resource in resources if resource.address == "aws_iam_role.orders_task")
        task_role.values["inline_policy"] = []
        key = next(resource for resource in resources if resource.address == "aws_kms_key.data")
        key.values["policy"] = _aws_key_policy(direct_runtime_allow=False)
        resources.append(
            aws_role(
                "orders_execution",
                _EXECUTION_ROLE_ARN,
                [
                    _aws_identity_statement(
                        "Allow",
                        "kms:Decrypt",
                        AWS_KEY_ARNS["data"],
                    ),
                    _aws_identity_statement(
                        "Allow",
                        "s3:GetObject",
                        f"{_AWS_BUCKET_ARN}/*",
                    ),
                ],
            )
        )

        inventory = _normalize(resources)
        service = _resource(inventory, "aws_ecs_service.orders")
        normalized_key = _resource(inventory, "aws_kms_key.data")
        execution_authorizations = [
            authorization
            for authorization in aws_facts(normalized_key).kms_operation_authorizations
            if authorization["principal_arn"] == _EXECUTION_ROLE_ARN and authorization["operation"] == "kms:Decrypt"
        ]
        self.assertEqual(
            [authorization["authorization_state"] for authorization in execution_authorizations],
            ["allowed"],
        )
        self.assertEqual(aws_facts(service).ecs_s3_access_paths, [])
        self.assertEqual(aws_facts(service).ecs_kms_operation_paths, [])
        self.assertEqual(
            aws_facts(service).ecs_s3_protected_data_convergences,
            [],
        )


if __name__ == "__main__":
    unittest.main()
