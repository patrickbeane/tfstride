from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_KEY_ID = "11111111-1111-1111-1111-111111111111"
_KEY_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/{_KEY_ID}"
_ALIAS_NAME = "alias/data"
_ALIAS_ARN = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:{_ALIAS_NAME}"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
    reference_resolutions: tuple[TerraformReferenceResolution, ...] = (),
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
        reference_resolutions=reference_resolutions,
    )


def _key(
    name: str = "data",
    *,
    key_id: str = _KEY_ID,
    key_arn: str = _KEY_ARN,
    exact_identity: bool = True,
) -> TerraformResource:
    values: dict[str, Any] = {
        "key_usage": "ENCRYPT_DECRYPT",
        "key_spec": "SYMMETRIC_DEFAULT",
        "origin": "AWS_KMS",
        "multi_region": False,
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        values.update({"id": key_id, "key_id": key_id, "arn": key_arn})
    else:
        values.update({"id": None, "key_id": None, "arn": None})
        unknown_values.update({"id": True, "key_id": True, "arn": True})
    return _resource(
        "aws_kms_key",
        name,
        values,
        unknown_values=unknown_values,
    )


def _alias(
    name: str = "data",
    *,
    exact_identity: bool = True,
    target_key_id: str = _KEY_ID,
    target_key_arn: str = _KEY_ARN,
) -> TerraformResource:
    values: dict[str, Any] = {
        "target_key_id": target_key_id,
        "target_key_arn": target_key_arn,
    }
    unknown_values: dict[str, Any] = {}
    if exact_identity:
        values.update({"id": _ALIAS_NAME, "name": _ALIAS_NAME, "arn": _ALIAS_ARN})
    else:
        values.update({"id": None, "name": None, "arn": None})
        unknown_values.update({"id": True, "name": True, "arn": True})
    return _resource(
        "aws_kms_alias",
        name,
        values,
        unknown_values=unknown_values,
    )


def _resolution(
    path: tuple[str | int, ...],
    targets: tuple[tuple[str, str], ...],
    *,
    state: TerraformReferenceResolutionState = TerraformReferenceResolutionState.SYMBOLIC,
) -> TerraformReferenceResolution:
    references = tuple(f"{address}{suffix}" for address, suffix in targets)
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=references,
        targets=tuple(
            TerraformReferenceTarget(address=address, reference=reference)
            for (address, _), reference in zip(targets, references, strict=True)
        ),
    )


def _unknown_dynamodb(
    name: str,
    resolution: TerraformReferenceResolution,
) -> TerraformResource:
    return _resource(
        "aws_dynamodb_table",
        name,
        {
            "name": name,
            "arn": f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/{name}",
            "server_side_encryption": [{"enabled": True, "kms_key_arn": None}],
        },
        unknown_values={
            "server_side_encryption": [{"kms_key_arn": True}],
        },
        reference_resolutions=(resolution,),
    )


def _unknown_queue(
    name: str,
    resolution: TerraformReferenceResolution,
) -> TerraformResource:
    return _resource(
        "aws_sqs_queue",
        name,
        {
            "name": name,
            "arn": f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:{name}",
            "kms_master_key_id": None,
            "sqs_managed_sse_enabled": False,
        },
        unknown_values={"kms_master_key_id": True},
        reference_resolutions=(resolution,),
    )


def _cloudtrail(
    name: str,
    reference: str | None,
    *,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    return _resource(
        "aws_cloudtrail",
        name,
        {
            "id": name,
            "name": name,
            "kms_key_id": reference,
        },
        unknown_values={"kms_key_id": True} if resolution is not None else None,
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


def _ecr_repository(
    name: str,
    reference: str | None,
    *,
    resolution: TerraformReferenceResolution | None = None,
) -> TerraformResource:
    return _resource(
        "aws_ecr_repository",
        name,
        {
            "id": name,
            "name": name,
            "encryption_configuration": [
                {
                    "encryption_type": "KMS",
                    "kms_key": reference,
                }
            ],
        },
        unknown_values=({"encryption_configuration": [{"kms_key": True}]} if resolution is not None else None),
        reference_resolutions=(resolution,) if resolution is not None else (),
    )


class AwsKmsEncryptionDependencyTests(unittest.TestCase):
    def test_exact_native_key_references_cover_supported_encrypted_resources(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _resource(
                    "aws_cloudtrail",
                    "orders",
                    {
                        "id": "orders",
                        "name": "orders",
                        "arn": f"arn:aws:cloudtrail:us-east-1:{_ACCOUNT_ID}:trail/orders",
                        "kms_key_id": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_dynamodb_table",
                    "orders",
                    {
                        "name": "orders",
                        "arn": f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/orders",
                        "server_side_encryption": [{"enabled": True, "kms_key_arn": _KEY_ARN}],
                    },
                ),
                _resource(
                    "aws_db_instance",
                    "orders",
                    {
                        "id": "orders",
                        "identifier": "orders",
                        "arn": f"arn:aws:rds:us-east-1:{_ACCOUNT_ID}:db:orders",
                        "storage_encrypted": True,
                        "kms_key_id": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_s3_bucket",
                    "orders",
                    {
                        "id": "orders",
                        "bucket": "orders",
                        "arn": "arn:aws:s3:::orders",
                    },
                ),
                _resource(
                    "aws_s3_bucket_server_side_encryption_configuration",
                    "orders",
                    {
                        "id": "orders",
                        "bucket": "orders",
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "sse_algorithm": "aws:kms",
                                        "kms_master_key_id": _KEY_ARN,
                                    }
                                ]
                            }
                        ],
                    },
                ),
                _resource(
                    "aws_secretsmanager_secret",
                    "orders",
                    {
                        "id": "orders",
                        "name": "orders",
                        "arn": f"arn:aws:secretsmanager:us-east-1:{_ACCOUNT_ID}:secret:orders",
                        "kms_key_id": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_sns_topic",
                    "orders",
                    {
                        "name": "orders",
                        "arn": f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:orders",
                        "kms_master_key_id": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_sqs_queue",
                    "orders",
                    {
                        "name": "orders",
                        "arn": f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders",
                        "kms_master_key_id": _KEY_ARN,
                        "sqs_managed_sse_enabled": False,
                    },
                ),
                _resource(
                    "aws_ecr_repository",
                    "orders",
                    {
                        "id": "orders",
                        "name": "orders",
                        "arn": f"arn:aws:ecr:us-east-1:{_ACCOUNT_ID}:repository/orders",
                        "encryption_configuration": [{"encryption_type": "KMS", "kms_key": _KEY_ARN}],
                    },
                ),
            ]
        )

        expected_dependencies = {
            "aws_cloudtrail.orders": ("aws_cloudtrail.orders", ["kms_key_id"]),
            "aws_dynamodb_table.orders": (
                "aws_dynamodb_table.orders",
                ["server_side_encryption", 0, "kms_key_arn"],
            ),
            "aws_db_instance.orders": ("aws_db_instance.orders", ["kms_key_id"]),
            "aws_s3_bucket.orders": (
                "aws_s3_bucket_server_side_encryption_configuration.orders",
                [
                    "rule",
                    0,
                    "apply_server_side_encryption_by_default",
                    0,
                    "kms_master_key_id",
                ],
            ),
            "aws_secretsmanager_secret.orders": (
                "aws_secretsmanager_secret.orders",
                ["kms_key_id"],
            ),
            "aws_sns_topic.orders": ("aws_sns_topic.orders", ["kms_master_key_id"]),
            "aws_sqs_queue.orders": ("aws_sqs_queue.orders", ["kms_master_key_id"]),
            "aws_ecr_repository.orders": (
                "aws_ecr_repository.orders",
                ["encryption_configuration", 0, "kms_key"],
            ),
        }
        for address, (source_address, configuration_path) in expected_dependencies.items():
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependencies = aws_facts(resource).kms_encryption_dependencies
                self.assertEqual(len(dependencies), 1)
                dependency = dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(dependency["reference_provenance"], "planned_value")
                self.assertEqual(dependency["reference_kind"], "key_arn")
                self.assertEqual(dependency["dependency_source_address"], source_address)
                self.assertEqual(dependency["configuration_path"], configuration_path)
                self.assertEqual(dependency["key_address"], "aws_kms_key.data")
                self.assertEqual(dependency["key_arn"], _KEY_ARN)
                self.assertEqual(dependency["key_id"], _KEY_ID)
                self.assertEqual(
                    dependency["candidate_targets"],
                    [{"address": "aws_kms_key.data", "target_kind": "key"}],
                )
                self.assertEqual(dependency["posture_uncertainties"], [])

        key = inventory.get_by_address("aws_kms_key.data")
        assert key is not None
        self.assertEqual(
            [dependency["dependent_address"] for dependency in aws_facts(key).kms_encryption_dependencies],
            sorted(expected_dependencies),
        )

    def test_customer_aliases_resolve_through_one_exact_modeled_key(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _alias(),
                _resource(
                    "aws_sqs_queue",
                    "by_name",
                    {
                        "name": "by-name",
                        "kms_master_key_id": _ALIAS_NAME,
                        "sqs_managed_sse_enabled": False,
                    },
                ),
                _resource(
                    "aws_secretsmanager_secret",
                    "by_arn",
                    {
                        "name": "by-arn",
                        "kms_key_id": _ALIAS_ARN,
                    },
                ),
            ]
        )

        for address, reference_kind in (
            ("aws_sqs_queue.by_name", "alias_name"),
            ("aws_secretsmanager_secret.by_arn", "alias_arn"),
        ):
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependency = aws_facts(resource).kms_encryption_dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(dependency["reference_kind"], reference_kind)
                self.assertEqual(
                    dependency["candidate_targets"],
                    [{"address": "aws_kms_alias.data", "target_kind": "alias"}],
                )
                self.assertEqual(dependency["alias_address"], "aws_kms_alias.data")
                self.assertEqual(dependency["alias_name"], _ALIAS_NAME)
                self.assertEqual(dependency["alias_arn"], _ALIAS_ARN)
                self.assertEqual(dependency["key_address"], "aws_kms_key.data")
                self.assertEqual(dependency["key_arn"], _KEY_ARN)

        key = inventory.get_by_address("aws_kms_key.data")
        assert key is not None
        self.assertEqual(len(aws_facts(key).kms_encryption_dependencies), 2)

    def test_conflicting_alias_target_evidence_fails_closed(self) -> None:
        alias_name = "alias/conflicting"
        alias_arn = f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:{alias_name}"
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _resource(
                    "aws_kms_alias",
                    "conflicting",
                    {
                        "id": alias_name,
                        "name": alias_name,
                        "arn": alias_arn,
                        "target_key_id": ("99999999-9999-9999-9999-999999999999"),
                        "target_key_arn": _KEY_ARN,
                    },
                ),
                _resource(
                    "aws_sqs_queue",
                    "conflicting",
                    {
                        "name": "conflicting",
                        "kms_master_key_id": alias_name,
                        "sqs_managed_sse_enabled": False,
                    },
                ),
            ]
        )

        queue = inventory.get_by_address("aws_sqs_queue.conflicting")
        key = inventory.get_by_address("aws_kms_key.data")
        assert queue is not None
        assert key is not None
        dependency = aws_facts(queue).kms_encryption_dependencies[0]
        self.assertEqual(dependency["resolution_state"], "unresolved")
        self.assertEqual(
            dependency["candidate_targets"],
            [
                {
                    "address": "aws_kms_alias.conflicting",
                    "target_kind": "alias",
                }
            ],
        )
        self.assertIsNone(dependency["alias_address"])
        self.assertIsNone(dependency["key_address"])
        self.assertEqual(
            dependency["posture_uncertainties"],
            [
                "aws_kms_alias.conflicting target reference "
                "99999999-9999-9999-9999-999999999999 does not resolve to a modeled KMS key"
            ],
        )
        self.assertEqual(
            aws_facts(queue).kms_encryption_dependency_uncertainties,
            [
                "aws_sqs_queue.conflicting: aws_kms_alias.conflicting target reference "
                "99999999-9999-9999-9999-999999999999 does not resolve to a modeled KMS key"
            ],
        )
        self.assertEqual(aws_facts(key).kms_encryption_dependencies, [])

    def test_cloudtrail_and_ecr_require_exact_key_arn_references(self) -> None:
        source_builders = (
            (
                "cloudtrail",
                _cloudtrail,
                ("kms_key_id",),
            ),
            (
                "ecr",
                _ecr_repository,
                ("encryption_configuration", 0, "kms_key"),
            ),
        )
        reference_cases = (
            ("symbolic_arn", None, "aws_kms_key.data", ".arn", "resolved"),
            ("symbolic_id", None, "aws_kms_key.data", ".id", "unsupported"),
            ("symbolic_key_id", None, "aws_kms_key.data", ".key_id", "unsupported"),
            ("symbolic_alias_name", None, "aws_kms_alias.data", ".name", "unsupported"),
            ("native_key_id", _KEY_ID, None, None, "unsupported"),
            ("native_alias_name", _ALIAS_NAME, None, None, "unsupported"),
            ("native_alias_arn", _ALIAS_ARN, None, None, "unsupported"),
        )

        for source_name, builder, path in source_builders:
            for case_name, reference, target_address, suffix, expected_state in reference_cases:
                with self.subTest(source=source_name, reference=case_name):
                    resolution = (
                        _resolution(path, ((target_address, suffix),))
                        if target_address is not None and suffix is not None
                        else None
                    )
                    source = builder(
                        case_name,
                        reference,
                        resolution=resolution,
                    )
                    inventory = AwsNormalizer().normalize([_key(), _alias(), source])
                    normalized = inventory.get_by_address(source.address)
                    assert normalized is not None
                    dependencies = aws_facts(normalized).kms_encryption_dependencies
                    self.assertEqual(len(dependencies), 1)
                    dependency = dependencies[0]
                    self.assertEqual(
                        dependency["resolution_state"],
                        expected_state,
                    )
                    if expected_state == "resolved":
                        self.assertEqual(
                            dependency["key_address"],
                            "aws_kms_key.data",
                        )
                    else:
                        self.assertIsNone(dependency["key_address"])
                        self.assertIsNone(dependency["alias_address"])

    def test_aws_managed_and_default_encryption_do_not_create_dependencies(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _resource(
                    "aws_cloudtrail",
                    "default",
                    {"id": "default", "name": "default"},
                ),
                _resource(
                    "aws_dynamodb_table",
                    "default",
                    {"name": "default"},
                ),
                _resource(
                    "aws_dynamodb_table",
                    "aws_managed",
                    {
                        "name": "aws-managed",
                        "server_side_encryption": [
                            {
                                "enabled": True,
                                "kms_key_arn": "alias/aws/dynamodb",
                            }
                        ],
                    },
                ),
                _resource(
                    "aws_db_instance",
                    "default",
                    {
                        "id": "default",
                        "identifier": "default",
                        "storage_encrypted": True,
                    },
                ),
                _resource(
                    "aws_s3_bucket",
                    "default",
                    {"id": "default", "bucket": "default"},
                ),
                _resource(
                    "aws_s3_bucket_server_side_encryption_configuration",
                    "default",
                    {
                        "id": "default",
                        "bucket": "default",
                        "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
                    },
                ),
                _resource(
                    "aws_secretsmanager_secret",
                    "default",
                    {"name": "default"},
                ),
                _resource(
                    "aws_sns_topic",
                    "default",
                    {
                        "name": "default",
                        "kms_master_key_id": "alias/aws/sns",
                    },
                ),
                _resource(
                    "aws_sqs_queue",
                    "default",
                    {
                        "name": "default",
                        "kms_master_key_id": "alias/aws/sqs",
                        "sqs_managed_sse_enabled": False,
                    },
                ),
                _resource(
                    "aws_ecr_repository",
                    "default",
                    {
                        "name": "default",
                        "encryption_configuration": [{"encryption_type": "KMS"}],
                    },
                ),
            ]
        )

        for resource in inventory.resources:
            if resource.resource_type not in {
                "aws_cloudtrail",
                "aws_dynamodb_table",
                "aws_db_instance",
                "aws_s3_bucket",
                "aws_secretsmanager_secret",
                "aws_sns_topic",
                "aws_sqs_queue",
                "aws_ecr_repository",
            }:
                continue
            with self.subTest(address=resource.address):
                facts = aws_facts(resource)
                self.assertEqual(facts.kms_encryption_dependencies, [])
                self.assertEqual(facts.kms_encryption_dependency_uncertainties, [])

    def test_symbolic_resolution_preserves_confidence_and_suffix_contracts(
        self,
    ) -> None:
        exact = _resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            (("aws_kms_key.data", ".arn"),),
        )
        wrong_suffix = _resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            (("aws_kms_key.data", ".id"),),
        )
        unresolved = _resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            (("aws_kms_key.data", ".arn"),),
            state=TerraformReferenceResolutionState.UNRESOLVED,
        )
        ambiguous = _resolution(
            ("server_side_encryption", 0, "kms_key_arn"),
            (
                ("aws_kms_key.data", ".arn"),
                ("aws_kms_key.audit", ".arn"),
                ("aws_kms_key.data", ".arn"),
            ),
            state=TerraformReferenceResolutionState.AMBIGUOUS,
        )
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _key(
                    "audit",
                    key_id="22222222-2222-2222-2222-222222222222",
                    key_arn=(f"arn:aws:kms:us-east-1:{_ACCOUNT_ID}:key/22222222-2222-2222-2222-222222222222"),
                ),
                _unknown_dynamodb("exact", exact),
                _unknown_dynamodb("wrong_suffix", wrong_suffix),
                _unknown_dynamodb("unresolved", unresolved),
                _unknown_dynamodb("ambiguous", ambiguous),
            ]
        )

        exact_table = inventory.get_by_address("aws_dynamodb_table.exact")
        wrong_table = inventory.get_by_address("aws_dynamodb_table.wrong_suffix")
        unresolved_table = inventory.get_by_address("aws_dynamodb_table.unresolved")
        ambiguous_table = inventory.get_by_address("aws_dynamodb_table.ambiguous")
        assert exact_table is not None
        assert wrong_table is not None
        assert unresolved_table is not None
        assert ambiguous_table is not None

        exact_dependency = aws_facts(exact_table).kms_encryption_dependencies[0]
        self.assertEqual(exact_dependency["resolution_state"], "resolved")
        self.assertEqual(
            exact_dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertEqual(exact_dependency["reference_kind"], "terraform_reference")
        self.assertEqual(exact_dependency["key_address"], "aws_kms_key.data")

        wrong_dependency = aws_facts(wrong_table).kms_encryption_dependencies[0]
        self.assertEqual(wrong_dependency["resolution_state"], "unsupported")
        self.assertEqual(wrong_dependency["key_address"], None)
        self.assertEqual(
            wrong_dependency["candidate_targets"],
            [{"address": "aws_kms_key.data", "target_kind": "key"}],
        )

        unresolved_dependency = aws_facts(unresolved_table).kms_encryption_dependencies[0]
        self.assertEqual(unresolved_dependency["resolution_state"], "unresolved")
        self.assertIsNone(unresolved_dependency["key_address"])
        self.assertEqual(
            unresolved_dependency["candidate_targets"],
            [{"address": "aws_kms_key.data", "target_kind": "key"}],
        )

        ambiguous_dependency = aws_facts(ambiguous_table).kms_encryption_dependencies[0]
        self.assertEqual(ambiguous_dependency["resolution_state"], "ambiguous")
        self.assertEqual(
            ambiguous_dependency["configuration_path"],
            ["server_side_encryption", 0, "kms_key_arn"],
        )
        self.assertEqual(
            ambiguous_dependency["reference_provenance"],
            "configuration_reference",
        )
        self.assertEqual(ambiguous_dependency["reference_kind"], "terraform_reference")
        self.assertIsNone(ambiguous_dependency["key_address"])
        self.assertEqual(
            ambiguous_dependency["posture_uncertainties"],
            [
                "Terraform configuration reference has multiple modeled KMS targets",
                "server_side_encryption.kms_key_arn is unknown after planning",
            ],
        )
        self.assertEqual(
            ambiguous_dependency["candidate_targets"],
            [
                {"address": "aws_kms_key.audit", "target_kind": "key"},
                {"address": "aws_kms_key.data", "target_kind": "key"},
            ],
        )
        self.assertEqual(
            aws_facts(ambiguous_table).kms_encryption_dependency_uncertainties,
            [
                "aws_dynamodb_table.ambiguous: Terraform configuration reference has multiple modeled KMS targets",
                "aws_dynamodb_table.ambiguous: server_side_encryption.kms_key_arn is unknown after planning",
            ],
        )

        data_key = inventory.get_by_address("aws_kms_key.data")
        audit_key = inventory.get_by_address("aws_kms_key.audit")
        assert data_key is not None
        assert audit_key is not None
        self.assertEqual(
            [dependency["dependent_address"] for dependency in aws_facts(data_key).kms_encryption_dependencies],
            ["aws_dynamodb_table.exact"],
        )
        self.assertEqual(aws_facts(audit_key).kms_encryption_dependencies, [])

    def test_symbolic_alias_and_missing_native_identity_remain_distinct(
        self,
    ) -> None:
        resolved_alias = _resolution(
            ("kms_master_key_id",),
            (("aws_kms_alias.data", ".name"),),
        )
        unresolved_alias = _resolution(
            ("kms_master_key_id",),
            (("aws_kms_alias.unresolved", ".name"),),
        )
        inventory = AwsNormalizer().normalize(
            [
                _key(),
                _alias(),
                _alias("unresolved", exact_identity=False),
                _unknown_queue("resolved", resolved_alias),
                _unknown_queue("unresolved", unresolved_alias),
            ]
        )

        resolved_queue = inventory.get_by_address("aws_sqs_queue.resolved")
        unresolved_queue = inventory.get_by_address("aws_sqs_queue.unresolved")
        assert resolved_queue is not None
        assert unresolved_queue is not None

        resolved = aws_facts(resolved_queue).kms_encryption_dependencies[0]
        self.assertEqual(resolved["resolution_state"], "resolved")
        self.assertEqual(resolved["alias_address"], "aws_kms_alias.data")
        self.assertEqual(resolved["key_address"], "aws_kms_key.data")

        unresolved = aws_facts(unresolved_queue).kms_encryption_dependencies[0]
        self.assertEqual(unresolved["resolution_state"], "unresolved")
        self.assertEqual(
            unresolved["candidate_targets"],
            [{"address": "aws_kms_alias.unresolved", "target_kind": "alias"}],
        )
        self.assertIsNone(unresolved["alias_address"])
        self.assertIsNone(unresolved["key_address"])
        self.assertEqual(
            unresolved["posture_uncertainties"],
            [
                "aws_kms_alias.unresolved does not retain the provider-native identity required "
                "by aws_kms_alias.unresolved.name",
                "kms_master_key_id is unknown after planning",
            ],
        )
        self.assertEqual(
            aws_facts(unresolved_queue).kms_encryption_dependency_uncertainties,
            [
                "aws_sqs_queue.unresolved: aws_kms_alias.unresolved does not retain the "
                "provider-native identity required by aws_kms_alias.unresolved.name",
                "aws_sqs_queue.unresolved: kms_master_key_id is unknown after planning",
            ],
        )

    def test_replica_only_unknowns_do_not_create_primary_dependencies(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _resource(
                    "aws_dynamodb_table",
                    "replica_only",
                    {
                        "name": "replica-only",
                        "replica": [
                            {
                                "region_name": "us-west-2",
                                "kms_key_arn": None,
                            }
                        ],
                    },
                    unknown_values={
                        "replica": [{"kms_key_arn": True}],
                    },
                ),
                _resource(
                    "aws_secretsmanager_secret",
                    "replica_only",
                    {
                        "name": "replica-only",
                        "replica": [
                            {
                                "region": "us-west-2",
                                "kms_key_id": None,
                            }
                        ],
                    },
                    unknown_values={
                        "replica": [{"kms_key_id": True}],
                    },
                ),
            ]
        )

        for address, field in (
            ("aws_dynamodb_table.replica_only", "kms_key_arn"),
            ("aws_secretsmanager_secret.replica_only", "kms_key_id"),
        ):
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependencies = aws_facts(resource).kms_encryption_dependencies
                self.assertEqual(len(dependencies), 1)
                dependency = dependencies[0]
                self.assertEqual(
                    dependency["configuration_path"],
                    ["replica", 0, field],
                )
                self.assertEqual(
                    dependency["resolution_state"],
                    "unresolved",
                )

    def test_replica_key_dependencies_keep_native_block_paths(self) -> None:
        replica_key_id = "33333333-3333-3333-3333-333333333333"
        replica_key_arn = f"arn:aws:kms:us-west-2:{_ACCOUNT_ID}:key/{replica_key_id}"
        inventory = AwsNormalizer().normalize(
            [
                _key(
                    "replica",
                    key_id=replica_key_id,
                    key_arn=replica_key_arn,
                ),
                _resource(
                    "aws_dynamodb_table",
                    "global",
                    {
                        "name": "global",
                        "replica": [
                            {
                                "region_name": "us-west-2",
                                "kms_key_arn": replica_key_arn,
                            }
                        ],
                    },
                ),
                _resource(
                    "aws_secretsmanager_secret",
                    "global",
                    {
                        "name": "global",
                        "replica": [
                            {
                                "region": "us-west-2",
                                "kms_key_id": replica_key_arn,
                            }
                        ],
                    },
                ),
            ]
        )

        for address, field in (
            ("aws_dynamodb_table.global", "kms_key_arn"),
            ("aws_secretsmanager_secret.global", "kms_key_id"),
        ):
            with self.subTest(address=address):
                resource = inventory.get_by_address(address)
                assert resource is not None
                dependency = aws_facts(resource).kms_encryption_dependencies[0]
                self.assertEqual(dependency["resolution_state"], "resolved")
                self.assertEqual(
                    dependency["configuration_path"],
                    ["replica", 0, field],
                )
                self.assertEqual(
                    dependency["key_address"],
                    "aws_kms_key.replica",
                )


if __name__ == "__main__":
    unittest.main()
