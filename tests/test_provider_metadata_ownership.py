from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.contracts import DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.metadata_ownership import ProviderMetadataOwnershipError
from tfstride.resource_metadata import (
    BoolDictMetadataField,
    BoolMetadataField,
    DictListMetadataField,
    DictMetadataField,
    IntMapMetadataField,
    MetadataField,
    OptionalIntMetadataField,
    OptionalStringMetadataField,
    StringListMetadataField,
)


def _resource(provider: str) -> NormalizedResource:
    return NormalizedResource(
        address=f"{provider}_resource.app",
        provider=provider,
        resource_type=f"{provider}_resource",
        name="app",
        category=ResourceCategory.COMPUTE,
    )


def _metadata_fields_by_name(namespace: type) -> dict[str, MetadataField[Any]]:
    return {
        name: value
        for name, value in vars(namespace).items()
        if isinstance(value, MetadataField)
    }


def _sample_metadata_value(field: MetadataField[Any]) -> Any:
    if isinstance(field, BoolMetadataField):
        return True
    if isinstance(field, StringListMetadataField):
        return ["sample"]
    if isinstance(field, OptionalStringMetadataField):
        return "sample"
    if isinstance(field, OptionalIntMetadataField):
        return 1
    if isinstance(field, DictListMetadataField):
        return [{"sample": "value"}]
    if isinstance(field, BoolDictMetadataField):
        return {"sample": True}
    if isinstance(field, IntMapMetadataField):
        return {"sample": 1}
    if isinstance(field, DictMetadataField):
        return {"sample": "value"}
    raise AssertionError(f"No sample value configured for {type(field).__name__}.")


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

    def test_provider_facts_accept_all_fields_from_their_own_metadata_namespace(self) -> None:
        provider_cases = (
            ("aws", AwsResourceMetadata, aws_facts),
            ("gcp", GcpResourceMetadata, gcp_facts),
        )

        for provider, namespace, facts_factory in provider_cases:
            with self.subTest(provider=provider):
                resource = _resource(provider)
                facts = facts_factory(resource)

                for field_name, field in _metadata_fields_by_name(namespace).items():
                    with self.subTest(provider=provider, field_name=field_name):
                        facts.set(field, _sample_metadata_value(field))

    def test_provider_facts_reject_all_foreign_provider_owned_metadata_fields(self) -> None:
        contract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT
        provider_cases = (
            ("aws", aws_facts, AwsResourceMetadata, "gcp", GcpResourceMetadata),
            ("gcp", gcp_facts, GcpResourceMetadata, "aws", AwsResourceMetadata),
        )

        for provider, facts_factory, own_namespace, foreign_provider, foreign_namespace in provider_cases:
            facts = facts_factory(_resource(provider))
            own_namespace_name = own_namespace.__name__
            foreign_fields = _metadata_fields_by_name(foreign_namespace)

            for field_name in sorted(contract.provider_owned_fields[foreign_provider]):
                field = foreign_fields[field_name]
                with self.subTest(provider=provider, foreign_provider=foreign_provider, field_name=field_name):
                    with self.assertRaisesRegex(
                        ProviderMetadataOwnershipError,
                        f"use a field from {own_namespace_name}",
                    ):
                        facts.set(field, _sample_metadata_value(field))


if __name__ == "__main__":
    unittest.main()