from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.resource_metadata import ResourceMetadata


def _resource(metadata: dict[str, object] | None = None) -> NormalizedResource:
    return NormalizedResource(
        address="aws_ecs_service.app",
        provider="aws",
        resource_type="aws_ecs_service",
        name="app",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
    )


class AwsResourceFactsTests(unittest.TestCase):
    def test_reads_aws_provider_metadata(self) -> None:
        resource = _resource(
            {
                "cluster": "arn:aws:ecs:us-east-1:111122223333:cluster/app",
                "task_definition": "app:7",
                "task_role_arn": "arn:aws:iam::111122223333:role/task",
                "requires_compatibilities": ["FARGATE"],
            }
        )

        facts = aws_facts(resource)

        self.assertIsInstance(facts, AwsResourceFacts)
        self.assertEqual(facts.cluster_reference, "arn:aws:ecs:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.task_definition_reference, "app:7")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(facts.requires_compatibilities, ["FARGATE"])

    def test_writes_aws_provider_metadata_through_resource_fields(self) -> None:
        resource = _resource()
        facts = aws_facts(resource)

        facts.set_network_mode("awsvpc")
        facts.set_task_role_arn("arn:aws:iam::111122223333:role/task")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_public_exposure_reason("service is internet-facing")

        self.assertEqual(facts.network_mode, "awsvpc")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(
            resource.get_metadata_field(ResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES),
            ["app:7"],
        )
        self.assertEqual(resource.public_exposure_reasons, ["service is internet-facing"])
        self.assertFalse(hasattr(resource, "task_role_arn"))

    def test_policy_document_is_mutated_only_through_facts_facade(self) -> None:
        resource = _resource()
        facts = aws_facts(resource)
        policy_document = {"Statement": [{"Effect": "Allow"}]}

        facts.set_policy_document(policy_document)
        policy_document["Statement"].append({"Effect": "Deny"})

        self.assertEqual(facts.policy_document, {"Statement": [{"Effect": "Allow"}]})

    def test_aws_provider_metadata_access_is_centralized_in_facts_facade(self) -> None:
        aws_provider_root = Path(__file__).resolve().parents[1] / "src" / "tfstride" / "providers" / "aws"
        offenders: list[str] = []

        for path in sorted(aws_provider_root.glob("*.py")):
            if path.name == "resource_facts.py":
                continue
            text = path.read_text(encoding="utf-8")
            if "ResourceMetadata" in text or "get_metadata_field(" in text or "set_metadata_field(" in text:
                offenders.append(path.name)

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()