from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.observations import observe_aws_controls


def _resource(
    address: str,
    resource_type: str,
    *,
    metadata: dict[str, object],
    public_exposure: bool = False,
    provider_config_key: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="aws",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=ResourceCategory.DATA,
        metadata=metadata,
        public_exposure=public_exposure,
        provider_config_key=provider_config_key,
    )


class AwsObservationTests(unittest.TestCase):
    def test_public_access_block_observation_preserves_all_matching_controls_in_any_input_order(self) -> None:
        bucket = _resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            metadata={
                AwsResourceMetadata.BUCKET_NAME: "logs",
                AwsResourceMetadata.BUCKET_ACL: "public-read",
                AwsResourceMetadata.PUBLIC_ACCESS_BLOCK: {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            },
        )
        first_block = _resource(
            "aws_s3_bucket_public_access_block.first",
            "aws_s3_bucket_public_access_block",
            metadata={AwsResourceMetadata.BUCKET_NAME: "logs"},
        )
        second_block = _resource(
            "aws_s3_bucket_public_access_block.second",
            "aws_s3_bucket_public_access_block",
            metadata={AwsResourceMetadata.BUCKET_NAME: "logs"},
        )

        for controls in ([first_block, second_block], [second_block, first_block]):
            with self.subTest(order=[control.address for control in controls]):
                observations = observe_aws_controls(ResourceInventory(provider="aws", resources=[bucket, *controls]))
                observation = next(
                    item for item in observations if item.observation_id == "aws-s3-public-access-block-observed"
                )

                self.assertEqual(
                    observation.affected_resources,
                    [bucket.address, first_block.address, second_block.address],
                )

    def test_public_access_block_weak_reference_stays_in_provider_configuration(self) -> None:
        bucket = _resource(
            "aws_s3_bucket.logs",
            "aws_s3_bucket",
            metadata={
                AwsResourceMetadata.BUCKET_NAME: "logs",
                AwsResourceMetadata.BUCKET_ACL: "public-read",
                AwsResourceMetadata.PUBLIC_ACCESS_BLOCK: {"block_public_acls": True},
            },
            provider_config_key="aws.primary",
        )
        primary_block = _resource(
            "aws_s3_bucket_public_access_block.primary",
            "aws_s3_bucket_public_access_block",
            metadata={AwsResourceMetadata.BUCKET_NAME: "logs"},
            provider_config_key="aws.primary",
        )
        secondary_block = _resource(
            "aws_s3_bucket_public_access_block.secondary",
            "aws_s3_bucket_public_access_block",
            metadata={AwsResourceMetadata.BUCKET_NAME: "logs"},
            provider_config_key="aws.secondary",
        )

        for controls in ([primary_block, secondary_block], [secondary_block, primary_block]):
            with self.subTest(order=[control.address for control in controls]):
                observations = observe_aws_controls(ResourceInventory(provider="aws", resources=[bucket, *controls]))
                observation = next(
                    item for item in observations if item.observation_id == "aws-s3-public-access-block-observed"
                )

                self.assertEqual(
                    observation.affected_resources,
                    [bucket.address, primary_block.address],
                )


if __name__ == "__main__":
    unittest.main()
