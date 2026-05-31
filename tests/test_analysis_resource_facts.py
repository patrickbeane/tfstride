from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.analysis.resource_facts import AnalysisResourceFacts, analysis_facts
from tfstride.models import NormalizedResource, ResourceCategory


def _resource(
    metadata: dict[str, object] | None = None,
    *,
    provider: str = "aws",
    resource_type: str = "aws_s3_bucket",
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.logs",
        provider=provider,
        resource_type=resource_type,
        name="logs",
        category=ResourceCategory.DATA,
        metadata=metadata,
    )


class AnalysisResourceFactsTests(unittest.TestCase):
    def test_reads_provider_backed_analysis_facts(self) -> None:
        resource = _resource(
            {
                "bucket": "logs",
                "acl": "public-read",
                "public_access_block": {"block_public_acls": True},
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
                "engine": "postgres",
                "resource_policy_source_addresses": ["aws_s3_bucket_policy.logs"],
            }
        )

        facts = analysis_facts(resource)

        self.assertIsInstance(facts, AnalysisResourceFacts)
        self.assertEqual(facts.bucket_name, "logs")
        self.assertEqual(facts.bucket_acl, "public-read")
        self.assertEqual(facts.public_access_block, {"block_public_acls": True})
        self.assertEqual(facts.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.database_engine, "postgres")
        self.assertEqual(facts.resource_policy_source_addresses, ["aws_s3_bucket_policy.logs"])

    def test_non_aws_resources_return_neutral_analysis_facts(self) -> None:
        resource = _resource(
            {
                "bucket": "logs",
                "acl": "public-read",
                "public_access_block": {"block_public_acls": True},
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
                "engine": "postgres",
                "resource_policy_source_addresses": ["google_storage_bucket_iam_binding.logs"],
            },
            provider="gcp",
            resource_type="google_storage_bucket",
        )

        facts = analysis_facts(resource)

        self.assertIsNone(facts.bucket_name)
        self.assertEqual(facts.bucket_acl, "")
        self.assertIsNone(facts.public_access_block)
        self.assertEqual(facts.policy_document, {})
        self.assertEqual(facts.trust_statements, [])
        self.assertIsNone(facts.database_engine)
        self.assertEqual(facts.resource_policy_source_addresses, [])

    def test_returns_detached_collections(self) -> None:
        resource = _resource(
            {
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
            }
        )
        facts = analysis_facts(resource)

        policy_document = facts.policy_document
        trust_statements = facts.trust_statements
        policy_document["Statement"].append({"Effect": "Deny"})
        trust_statements[0]["Effect"] = "Deny"

        self.assertEqual(facts.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])

    def test_analysis_metadata_reads_are_centralized_in_facts_facade(self) -> None:
        analysis_root = Path(__file__).resolve().parents[1] / "src" / "tfstride" / "analysis"
        offenders: list[str] = []

        for path in sorted(analysis_root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if "ResourceMetadata" in text or "get_metadata_field(" in text:
                offenders.append(path.name)

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()