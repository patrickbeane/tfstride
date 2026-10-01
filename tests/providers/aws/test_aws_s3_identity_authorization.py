from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _ARCHIVE_BUCKET_ARN,
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _bucket,
    _normalize,
    _role,
    _role_policy_attachment,
    _statement,
)
from tests.providers.aws.test_aws_ecs_s3_object_deletion_paths import _bucket_policy, _bucket_statement
from tfstride.models import NormalizedResource, TerraformResource
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder
from tfstride.providers.aws.s3_bucket_policies import S3BucketPolicySources, prepare_s3_bucket_policy_sources
from tfstride.providers.aws.s3_identity_authorization import (
    assess_s3_identity_policy,
    evaluate_s3_identity_authorization,
)


def _inputs(
    resources: list[TerraformResource],
) -> tuple[dict[str, NormalizedResource], dict[str, S3BucketPolicySources]]:
    # Authorization is usable without a task definition, service, or projected path.
    normalized = list(_normalize(resources).resources)
    context = AwsDecorationContext(index=AwsResourceIndexBuilder().build(normalized))
    return context.index.resources_by_address, prepare_s3_bucket_policy_sources(normalized, context)


class AwsS3IdentityAuthorizationTests(unittest.TestCase):
    def test_one_target_preserves_action_scope_and_bucket_policy_constraints(self) -> None:
        resources, sources = _inputs(
            [
                _bucket(),
                _bucket("archive", arn=_ARCHIVE_BUCKET_ARN),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:ListBucket", "s3:PutObject"],
                            [_BUCKET_ARN, f"{_BUCKET_ARN}/public/*", f"{_BUCKET_ARN}/private/*"],
                        ),
                    ],
                ),
                _bucket_policy([_bucket_statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/private/*", _TASK_ROLE_ARN)]),
            ]
        )
        identity = assess_s3_identity_policy(resources["aws_iam_role.orders_task"])
        bucket = resources["aws_s3_bucket.orders"]
        result = evaluate_s3_identity_authorization(identity, bucket, sources[bucket.address])
        assert result is not None
        self.assertEqual((result.bucket_address, result.bucket_arn), (bucket.address, _BUCKET_ARN))
        self.assertEqual(result.access_state, "allowed")
        self.assertEqual(result.assessment["allowed_actions"], ["s3:ListBucket", "s3:PutObject"])
        self.assertEqual(
            [
                (scope["action"], scope["resource"], scope["modeled_access_state"])
                for scope in result.assessment["scope_evaluations"]
            ],
            [
                ("s3:ListBucket", _BUCKET_ARN, "allowed"),
                ("s3:PutObject", f"{_BUCKET_ARN}/private/*", "denied"),
                ("s3:PutObject", f"{_BUCKET_ARN}/public/*", "allowed"),
            ],
        )
        self.assertEqual(result.bucket_constraints.source_addresses, ("aws_s3_bucket_policy.orders",))
        archive = resources["aws_s3_bucket.archive"]
        self.assertIsNone(evaluate_s3_identity_authorization(identity, archive, sources[archive.address]))

    def test_effective_state_keeps_boundary_and_completeness_gates(self) -> None:
        for gate in ("permissions_boundary", "identity_policy", "bucket_policy"):
            with self.subTest(gate=gate):
                role = _role(
                    "orders_task", _TASK_ROLE_ARN, [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*")]
                )
                bucket = _bucket()
                extra = []
                if gate == "permissions_boundary":
                    role.values["permissions_boundary"] = "arn:aws:iam::111122223333:policy/boundary"
                elif gate == "identity_policy":
                    extra.append(_role_policy_attachment(_TASK_ROLE_ARN, "arn:aws:iam::aws:policy/ExternalS3Policy"))
                else:
                    bucket.unknown_values = {"policy": True}
                resources, sources = _inputs([bucket, role, *extra])
                identity = assess_s3_identity_policy(resources["aws_iam_role.orders_task"])
                target = resources["aws_s3_bucket.orders"]
                result = evaluate_s3_identity_authorization(identity, target, sources[target.address])
                assert result is not None
                self.assertEqual(result.modeled_access_state, "allowed")
                self.assertEqual(result.access_state, "unknown")
                self.assertTrue(identity.uncertainties or result.uncertainties)


if __name__ == "__main__":
    unittest.main()
