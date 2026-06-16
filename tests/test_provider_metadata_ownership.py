from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.metadata_ownership import ProviderMetadataOwnershipError


def _resource(provider: str) -> NormalizedResource:
    return NormalizedResource(
        address=f"{provider}_resource.app",
        provider=provider,
        resource_type=f"{provider}_resource",
        name="app",
        category=ResourceCategory.COMPUTE,
    )


class ProviderMetadataOwnershipTests(unittest.TestCase):
    def test_aws_facts_accept_aws_owned_metadata_writes(self) -> None:
        resource = _resource("aws")
        facts = aws_facts(resource)

        facts.set(AwsResourceMetadata.TASK_ROLE_ARN, "arn:aws:iam::111122223333:role/task")
        facts.set(AwsResourceMetadata.POLICY_DOCUMENT, {"Statement": []})

        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(resource.get_metadata_field(AwsResourceMetadata.POLICY_DOCUMENT), {"Statement": []})

    def test_gcp_facts_accept_gcp_owned_metadata_writes(self) -> None:
        resource = _resource("gcp")
        facts = gcp_facts(resource)

        facts.set(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL, "app@tfstride.iam.gserviceaccount.com")
        facts.set(GcpResourceMetadata.POLICY_DOCUMENT, {"bindings": []})
        facts.extend(
            GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES,
            ["google_secret_manager_secret_iam_member.public"],
        )

        self.assertEqual(facts.service_account_email, "app@tfstride.iam.gserviceaccount.com")
        self.assertEqual(facts.policy_document, {"bindings": []})
        self.assertEqual(
            facts.resource_policy_source_addresses,
            ["google_secret_manager_secret_iam_member.public"],
        )

    def test_aws_facts_reject_gcp_owned_metadata_writes(self) -> None:
        resource = _resource("aws")

        with self.assertRaisesRegex(ProviderMetadataOwnershipError, "not writable through aws resource facts"):
            aws_facts(resource).set(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL, "app@example.com")

        self.assertNotIn(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL.key, resource.metadata)

    def test_gcp_facts_reject_aws_owned_metadata_writes(self) -> None:
        resource = _resource("gcp")

        with self.assertRaisesRegex(ProviderMetadataOwnershipError, "not writable through gcp resource facts"):
            gcp_facts(resource).set(AwsResourceMetadata.TASK_ROLE_ARN, "arn:aws:iam::111122223333:role/task")

        self.assertNotIn(AwsResourceMetadata.TASK_ROLE_ARN.key, resource.metadata)

    def test_provider_facts_reject_same_key_from_wrong_namespace(self) -> None:
        resource = _resource("aws")

        with self.assertRaisesRegex(ProviderMetadataOwnershipError, "use a field from AwsResourceMetadata"):
            aws_facts(resource).set(GcpResourceMetadata.NAME, "app")

        self.assertNotIn(AwsResourceMetadata.NAME.key, resource.metadata)


if __name__ == "__main__":
    unittest.main()