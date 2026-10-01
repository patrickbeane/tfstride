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
    _resource,
    _role,
    _role_policy_attachment,
    _service,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import (
    _object_lock,
    _versioning,
)
from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_decoration.ecs_s3_bucket_topology_destruction_paths import (
    current_s3_bucket_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)

_DELETE_BUCKET = "s3:DeleteBucket"
_FOREIGN_ACCOUNT_ID = "444455556666"
_FOREIGN_TASK_ROLE_ARN = f"arn:aws:iam::{_FOREIGN_ACCOUNT_ID}:role/orders-task"


def _caller_identity(
    account_id: str | None = _ACCOUNT_ID,
    *,
    unknown: bool = False,
    address: str = "data.aws_caller_identity.current",
    provider_config_key: str = "aws",
) -> TerraformResource:
    values: dict[str, object] = {}
    if account_id is not None:
        values = {
            "account_id": account_id,
            "id": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
        }
    return TerraformResource(
        address=address,
        mode="data",
        resource_type="aws_caller_identity",
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        provider_config_key=provider_config_key,
        unknown_values={"account_id": True} if unknown else {},
    )


def _bucket_policy(
    statements: list[dict[str, Any]],
    *,
    name: str = "orders",
    bucket: str = "orders-data",
) -> TerraformResource:
    return _resource(
        "aws_s3_bucket_policy",
        name,
        {
            "bucket": bucket,
            "policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": statements,
                }
            ),
        },
    )


def _bucket_statement(
    effect: str,
    action: str,
    resource: str,
    *,
    principal: str = _TASK_ROLE_ARN,
    condition: dict[str, object] | None = None,
) -> dict[str, Any]:
    statement = _statement(
        effect,
        action,
        resource,
        condition=condition,
    )
    statement["Principal"] = {"AWS": principal}
    return statement


def _symbolic_resolution(
    path: tuple[str | int, ...],
    reference: str,
    *target_addresses: str,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=tuple(
            TerraformReferenceTarget(
                address=address,
                reference=reference,
            )
            for address in target_addresses
        ),
    )


def _normalize(
    *,
    role_statements: list[dict[str, Any]] | None = None,
    role_arn: str = _TASK_ROLE_ARN,
    bucket: TerraformResource | None = None,
    task_definition: TerraformResource | None = None,
    bucket_policy: TerraformResource | None = None,
    caller_identity: TerraformResource | None = None,
    include_caller_identity: bool = True,
    extra: list[TerraformResource] | None = None,
    provider_config_key: str = "aws",
):
    resources: list[TerraformResource] = []
    if include_caller_identity:
        resources.append(caller_identity or _caller_identity(provider_config_key=provider_config_key))
    resources.extend(
        [
            bucket or _bucket(provider_config_key=provider_config_key),
            _role(
                "orders_task",
                role_arn,
                role_statements,
                provider_config_key=provider_config_key,
            ),
        ]
    )
    if bucket_policy is not None:
        resources.append(bucket_policy)
    resources.extend(
        [
            task_definition
            or _task_definition(
                task_role_arn=role_arn,
                execution_role_arn=None,
                provider_config_key=provider_config_key,
            ),
            _service(provider_config_key=provider_config_key),
            *(extra or []),
        ]
    )
    inventory = AwsNormalizer().normalize(resources)
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert task is not None
    assert service is not None
    return inventory, task, service


class AwsEcsS3BucketTopologyDestructionPathTests(unittest.TestCase):
    def test_task_role_authority_preserves_exact_bucket_and_recovery_boundary(
        self,
    ) -> None:
        _inventory, task, service = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            extra=[_versioning("Enabled"), _object_lock()],
        )

        task_paths = aws_facts(task).ecs_s3_bucket_topology_destruction_paths
        service_paths = aws_facts(service).ecs_s3_bucket_topology_destruction_paths
        self.assertEqual(len(task_paths), 1)
        self.assertEqual(len(service_paths), 1)

        path = task_paths[0]
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(path["bucket_address"], "aws_s3_bucket.orders")
        self.assertEqual(path["bucket_arn"], _BUCKET_ARN)
        self.assertEqual(path["operation"], _DELETE_BUCKET)
        self.assertEqual(path["target_scope"], "exact_s3_bucket")
        self.assertEqual(path["authorization_bases"], ["identity_policy"])
        self.assertEqual(path["matched_actions"], [_DELETE_BUCKET])
        self.assertTrue(path["same_account"])
        self.assertTrue(path["identity_policy_complete"])
        self.assertTrue(path["bucket_policy_complete"])
        self.assertFalse(path["explicit_deny"])
        self.assertFalse(path["conditional_evaluation_required"])
        self.assertEqual(
            path["lifecycle_compatibility_state"],
            "bucket_emptiness_not_established",
        )

        recovery = path["recovery_evidence"]
        self.assertTrue(recovery["bucket_emptiness_required"])
        self.assertEqual(recovery["bucket_emptiness_state"], "not_established")
        self.assertTrue(recovery["versioning_enabled"])
        self.assertTrue(recovery["object_lock_enabled"])
        self.assertEqual(
            recovery["object_lock_default_retention_mode"],
            "GOVERNANCE",
        )
        self.assertFalse(recovery["out_of_plan_object_inventory_evaluated"])
        self.assertEqual(recovery["attached_access_point_state"], "not_established")
        self.assertFalse(recovery["successful_deletion_observed"])
        self.assertFalse(recovery["recovery_observed"])
        self.assertTrue(recovery["uncertainties"])
        self.assertEqual(service_paths[0]["workload_address"], service.address)
        self.assertEqual(
            service_paths[0]["task_definition_address"],
            task.address,
        )
        self.assertEqual(service_paths[0]["internet_facing_load_balancers"], [])

    def test_same_account_direct_bucket_policy_is_effective(self) -> None:
        _inventory, task, _service_resource = _normalize(
            bucket_policy=_bucket_policy(
                [
                    _bucket_statement(
                        "Allow",
                        _DELETE_BUCKET,
                        _BUCKET_ARN,
                    )
                ]
            ),
        )

        path = aws_facts(task).ecs_s3_bucket_topology_destruction_paths[0]
        self.assertEqual(path["authorization_bases"], ["bucket_policy_direct"])
        self.assertEqual(
            path["authorization_source_addresses"],
            ["aws_s3_bucket_policy.orders"],
        )
        self.assertEqual(
            path["bucket_policy_source_addresses"],
            ["aws_s3_bucket_policy.orders"],
        )
        statement = path["authorization_statements"][0]
        self.assertEqual(statement["source_kind"], "bucket_policy")
        self.assertEqual(statement["principal_match"], "role")
        self.assertEqual(statement["matching_resources"], [_BUCKET_ARN])

    def test_exact_symbolic_bucket_policy_target_participates_in_authorization(
        self,
    ) -> None:
        bucket_reference = "aws_s3_bucket.orders.id"
        allow_policy = _bucket_policy(
            [
                _bucket_statement(
                    "Allow",
                    _DELETE_BUCKET,
                    _BUCKET_ARN,
                )
            ],
            bucket=bucket_reference,
        )
        allow_policy.reference_resolutions = (
            _symbolic_resolution(
                ("bucket",),
                bucket_reference,
                "aws_s3_bucket.orders",
            ),
        )
        _inventory, task, _service_resource = _normalize(
            bucket_policy=allow_policy,
        )

        path = aws_facts(task).ecs_s3_bucket_topology_destruction_paths[0]
        self.assertEqual(path["authorization_bases"], ["bucket_policy_direct"])
        self.assertEqual(
            path["bucket_policy_source_addresses"],
            ["aws_s3_bucket_policy.orders"],
        )

        deny_policy = _bucket_policy(
            [
                _bucket_statement(
                    "Deny",
                    _DELETE_BUCKET,
                    _BUCKET_ARN,
                )
            ],
            bucket=bucket_reference,
        )
        deny_policy.reference_resolutions = allow_policy.reference_resolutions
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            bucket_policy=deny_policy,
        )
        self.assertEqual(
            aws_facts(task).ecs_s3_bucket_topology_destruction_paths,
            [],
        )

    def test_ambiguous_symbolic_bucket_policy_target_fails_closed(self) -> None:
        bucket_reference = "aws_s3_bucket.orders.id"
        policy = _bucket_policy(
            [
                _bucket_statement(
                    "Deny",
                    _DELETE_BUCKET,
                    _BUCKET_ARN,
                )
            ],
            bucket=bucket_reference,
        )
        policy.reference_resolutions = (
            _symbolic_resolution(
                ("bucket",),
                bucket_reference,
                "aws_s3_bucket.orders",
                "aws_s3_bucket.archive",
                state=TerraformReferenceResolutionState.AMBIGUOUS,
            ),
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            bucket_policy=policy,
        )

        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "unresolved S3 bucket-policy target" in uncertainty
                for uncertainty in (facts.ecs_s3_bucket_topology_destruction_path_uncertainties)
            )
        )

    def test_explicit_denies_conditions_and_incompleteness_fail_closed(
        self,
    ) -> None:
        cases: dict[str, dict[str, object]] = {
            "identity deny": {
                "role_statements": [
                    _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
                    _statement("Deny", _DELETE_BUCKET, _BUCKET_ARN),
                ],
            },
            "bucket deny": {
                "role_statements": [
                    _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
                ],
                "bucket_policy": _bucket_policy(
                    [
                        _bucket_statement(
                            "Deny",
                            _DELETE_BUCKET,
                            _BUCKET_ARN,
                        )
                    ]
                ),
            },
            "conditional allow": {
                "role_statements": [
                    _statement(
                        "Allow",
                        _DELETE_BUCKET,
                        _BUCKET_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ],
            },
            "incomplete identity policy": {
                "role_statements": [
                    _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
                ],
                "extra": [
                    _role_policy_attachment(
                        _TASK_ROLE_ARN,
                        "arn:aws:iam::aws:policy/ExternalS3Administration",
                    )
                ],
            },
        }

        for case, kwargs in cases.items():
            with self.subTest(case=case):
                _inventory, task, _service_resource = _normalize(**kwargs)  # type: ignore[arg-type]
                facts = aws_facts(task)
                self.assertEqual(
                    facts.ecs_s3_bucket_topology_destruction_paths,
                    [],
                )
                if case not in {"identity deny", "bucket deny"}:
                    self.assertTrue(facts.ecs_s3_bucket_topology_destruction_path_uncertainties)

    def test_default_provider_caller_does_not_establish_aliased_bucket_ownership(
        self,
    ) -> None:
        _inventory, task, service = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            bucket=_bucket(provider_config_key="aws.archive"),
        )

        self.assertEqual(
            aws_facts(task).ecs_s3_bucket_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_s3_bucket_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "bucket ownership compatibility" in uncertainty
                for uncertainty in aws_facts(task).ecs_s3_bucket_topology_destruction_path_uncertainties
            )
        )

    def test_matching_aliased_provider_configuration_establishes_ownership(
        self,
    ) -> None:
        inventory, task, service = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            provider_config_key="aws.archive",
        )

        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        caller = inventory.get_by_address("data.aws_caller_identity.current")
        assert bucket is not None
        assert role is not None
        assert caller is not None
        self.assertEqual(bucket.provider_config_key, "aws.archive")
        self.assertEqual(role.provider_config_key, "aws.archive")
        self.assertEqual(caller.provider_config_key, "aws.archive")
        self.assertEqual(
            len(aws_facts(task).ecs_s3_bucket_topology_destruction_paths),
            1,
        )
        self.assertEqual(
            len(aws_facts(service).ecs_s3_bucket_topology_destruction_paths),
            1,
        )

    def test_bucket_owner_compatibility_requires_resolved_caller_identity(
        self,
    ) -> None:
        bucket_without_provider_key = _bucket()
        bucket_without_provider_key.provider_config_key = None
        cases = {
            "missing provider configuration": {
                "bucket": bucket_without_provider_key,
            },
            "absent": {
                "include_caller_identity": False,
            },
            "unknown": {
                "caller_identity": _caller_identity(
                    account_id=None,
                    unknown=True,
                ),
            },
            "ambiguous": {
                "extra": [
                    _caller_identity(
                        account_id=_FOREIGN_ACCOUNT_ID,
                        address="data.aws_caller_identity.archive",
                    )
                ],
            },
        }
        for case, kwargs in cases.items():
            with self.subTest(case=case):
                _inventory, task, _service_resource = _normalize(
                    role_statements=[
                        _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
                    ],
                    **kwargs,
                )
                facts = aws_facts(task)
                self.assertEqual(
                    facts.ecs_s3_bucket_topology_destruction_paths,
                    [],
                )
                self.assertTrue(
                    any(
                        "bucket ownership compatibility" in uncertainty
                        for uncertainty in (facts.ecs_s3_bucket_topology_destruction_path_uncertainties)
                    )
                )

    def test_current_path_helper_recomputes_identity_and_bucket_policy_authority(
        self,
    ) -> None:
        inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
        )
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert bucket is not None
        assert role is not None
        context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(list(inventory.resources)))
        self.assertIsNotNone(
            current_s3_bucket_topology_destruction_path(
                task,
                bucket,
                context,
            )
        )

        role.policy_statements = ()
        self.assertIsNone(
            current_s3_bucket_topology_destruction_path(
                task,
                bucket,
                context,
            )
        )

        inventory, task, _service_resource = _normalize(
            bucket_policy=_bucket_policy(
                [
                    _bucket_statement(
                        "Allow",
                        _DELETE_BUCKET,
                        _BUCKET_ARN,
                    )
                ]
            ),
        )
        bucket = inventory.get_by_address("aws_s3_bucket.orders")
        policy = inventory.get_by_address("aws_s3_bucket_policy.orders")
        assert bucket is not None
        assert policy is not None
        context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(list(inventory.resources)))
        self.assertIsNotNone(
            current_s3_bucket_topology_destruction_path(
                task,
                bucket,
                context,
            )
        )

        deny = _bucket_statement(
            "Deny",
            _DELETE_BUCKET,
            _BUCKET_ARN,
        )
        policy.policy_statements = (parse_policy_statement(deny),)
        aws_facts(policy).set_policy_document(
            {
                "Version": "2012-10-17",
                "Statement": [deny],
            }
        )
        self.assertIsNone(
            current_s3_bucket_topology_destruction_path(
                task,
                bucket,
                context,
            )
        )

    def test_cross_account_task_role_is_not_promoted_even_with_two_sided_allow(
        self,
    ) -> None:
        _inventory, task, _service_resource = _normalize(
            role_arn=_FOREIGN_TASK_ROLE_ARN,
            role_statements=[
                _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
            ],
            bucket_policy=_bucket_policy(
                [
                    _bucket_statement(
                        "Allow",
                        _DELETE_BUCKET,
                        _BUCKET_ARN,
                        principal=_FOREIGN_TASK_ROLE_ARN,
                    )
                ]
            ),
        )

        self.assertEqual(
            aws_facts(task).ecs_s3_bucket_topology_destruction_paths,
            [],
        )

    def test_exact_symbolic_role_and_bucket_references_preserve_provenance(
        self,
    ) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        bucket_reference = "aws_s3_bucket.orders.arn"
        task_definition = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
        )
        task_definition.unknown_values["task_role_arn"] = True
        task_definition.reference_resolutions = (
            _symbolic_resolution(
                ("task_role_arn",),
                role_reference,
                "aws_iam_role.orders_task",
            ),
        )
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [_statement("Allow", _DELETE_BUCKET, bucket_reference)],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                bucket_reference,
                "aws_s3_bucket.orders",
            ),
        )
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity(),
                _bucket(),
                role,
                task_definition,
                _service(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        paths = aws_facts(task).ecs_s3_bucket_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_reference"], role_reference)
        self.assertEqual(paths[0]["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(
            paths[0]["authorization_statements"][0]["matching_resources"],
            [bucket_reference],
        )

    def test_symbolic_looking_bucket_string_without_provenance_is_quiet(
        self,
    ) -> None:
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement(
                    "Allow",
                    _DELETE_BUCKET,
                    "aws_s3_bucket.orders.arn",
                )
            ]
        )

        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])
        self.assertEqual(
            facts.ecs_s3_bucket_topology_destruction_path_uncertainties,
            [],
        )

    def test_ambiguous_symbolic_task_role_fails_closed_with_uncertainty(
        self,
    ) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        task_definition = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
        )
        task_definition.unknown_values["task_role_arn"] = True
        task_definition.reference_resolutions = (
            _symbolic_resolution(
                ("task_role_arn",),
                role_reference,
                "aws_iam_role.orders_task",
                "aws_iam_role.other_task",
                state=TerraformReferenceResolutionState.AMBIGUOUS,
            ),
        )
        inventory = AwsNormalizer().normalize(
            [
                _caller_identity(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", _DELETE_BUCKET, _BUCKET_ARN)],
                ),
                _role(
                    "other_task",
                    f"arn:aws:iam::{_ACCOUNT_ID}:role/other-task",
                    [],
                ),
                task_definition,
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])
        self.assertTrue(facts.ecs_s3_bucket_topology_destruction_path_uncertainties)

    def test_execution_role_authority_never_becomes_runtime_bucket_deletion(
        self,
    ) -> None:
        execution_role = _role(
            "orders_execution",
            _EXECUTION_ROLE_ARN,
            [_statement("Allow", _DELETE_BUCKET, _BUCKET_ARN)],
        )
        _inventory, task, service = _normalize(extra=[execution_role])

        self.assertEqual(
            aws_facts(task).ecs_s3_bucket_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_s3_bucket_topology_destruction_paths,
            [],
        )

    def test_unresolved_bucket_policy_is_operation_and_principal_local(
        self,
    ) -> None:
        exact_role_allow = [
            _statement("Allow", _DELETE_BUCKET, _BUCKET_ARN),
        ]
        unrelated = _bucket_policy(
            [
                _bucket_statement(
                    "Deny",
                    "s3:DeleteObject",
                    f"{_BUCKET_ARN}/*",
                    principal=(f"arn:aws:iam::{_ACCOUNT_ID}:role/archive-task"),
                )
            ],
            name="archive_dynamic",
            bucket="aws_s3_bucket.archive_dynamic.id",
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=exact_role_allow,
            extra=[unrelated],
        )
        self.assertEqual(
            len(aws_facts(task).ecs_s3_bucket_topology_destruction_paths),
            1,
        )

        relevant = _bucket_policy(
            [
                _bucket_statement(
                    "Deny",
                    _DELETE_BUCKET,
                    _BUCKET_ARN,
                )
            ],
            name="orders_dynamic",
            bucket="aws_s3_bucket.orders_dynamic.id",
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=exact_role_allow,
            extra=[relevant],
        )
        facts = aws_facts(task)
        self.assertEqual(facts.ecs_s3_bucket_topology_destruction_paths, [])
        self.assertTrue(
            any(
                "unresolved S3 bucket-policy target" in uncertainty
                for uncertainty in (facts.ecs_s3_bucket_topology_destruction_path_uncertainties)
            )
        )


if __name__ == "__main__":
    unittest.main()
