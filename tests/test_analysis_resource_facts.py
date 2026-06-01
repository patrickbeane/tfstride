from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tfstride.analysis.resource_facts import AnalysisResourceFacts, analysis_facts
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.resource_facts import ProviderResourceFactsRegistry


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


@dataclass(frozen=True, slots=True)
class FakeProviderFacts:
    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return f"{self.resource.provider}-logs"

    @property
    def bucket_acl(self) -> str:
        return "private"

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return {"block_public_acls": True}

    @property
    def policy_document(self) -> dict[str, Any]:
        return {"Statement": [{"Effect": "Allow"}]}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return [{"Effect": "Allow"}]

    @property
    def engine(self) -> str | None:
        return "spanner"

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return ["google_storage_bucket_iam_binding.logs"]

    @property
    def service_account_email(self) -> str | None:
        return "fake@example.iam.gserviceaccount.com"

    @property
    def service_account_member(self) -> str | None:
        return "serviceAccount:fake@example.iam.gserviceaccount.com"

    @property
    def service_account_reference(self) -> str | None:
        return "google_service_account.fake.email"


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
        self.assertIsNone(facts.service_account_email)
        self.assertIsNone(facts.service_account_member)
        self.assertIsNone(facts.service_account_reference)

    def test_gcp_resources_return_provider_owned_bucket_facts_with_neutral_defaults(self) -> None:
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

        self.assertEqual(facts.bucket_name, "logs")
        self.assertEqual(facts.bucket_acl, "")
        self.assertIsNone(facts.public_access_block)
        self.assertEqual(facts.policy_document, {})
        self.assertEqual(facts.trust_statements, [])
        self.assertIsNone(facts.database_engine)
        self.assertEqual(facts.resource_policy_source_addresses, [])
        self.assertIsNone(facts.service_account_email)
        self.assertIsNone(facts.service_account_member)
        self.assertIsNone(facts.service_account_reference)

    def test_gcp_service_account_facts_read_provider_owned_identity_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL.key: "tfstride-web@example.iam.gserviceaccount.com",
                GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER.key: (
                    "serviceAccount:tfstride-web@example.iam.gserviceaccount.com"
                ),
            },
            provider="gcp",
            resource_type="google_service_account",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.service_account_email, "tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(
            facts.service_account_member,
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertIsNone(facts.service_account_reference)

    def test_registered_provider_facts_are_used_without_analysis_branching(self) -> None:
        calls: list[NormalizedResource] = []

        def gcp_facts(resource: NormalizedResource) -> FakeProviderFacts:
            calls.append(resource)
            return FakeProviderFacts(resource)

        resource = _resource(provider="gcp", resource_type="google_storage_bucket")
        registry = ProviderResourceFactsRegistry([("gcp", gcp_facts)])

        facts = analysis_facts(resource, facts_registry=registry)

        self.assertEqual(calls, [resource])
        self.assertEqual(facts.bucket_name, "gcp-logs")
        self.assertEqual(facts.bucket_acl, "private")
        self.assertEqual(facts.public_access_block, {"block_public_acls": True})
        self.assertEqual(facts.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.database_engine, "spanner")
        self.assertEqual(
            facts.resource_policy_source_addresses,
            ["google_storage_bucket_iam_binding.logs"],
        )
        self.assertEqual(facts.service_account_email, "fake@example.iam.gserviceaccount.com")
        self.assertEqual(facts.service_account_member, "serviceAccount:fake@example.iam.gserviceaccount.com")
        self.assertEqual(facts.service_account_reference, "google_service_account.fake.email")

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

    def test_analysis_resource_facts_does_not_import_aws_directly(self) -> None:
        analysis_root = Path(__file__).resolve().parents[1] / "src" / "tfstride" / "analysis"
        text = (analysis_root / "resource_facts.py").read_text(encoding="utf-8")

        self.assertNotIn("tfstride.providers.aws", text)
        self.assertNotIn('provider == "aws"', text)
        self.assertNotIn('provider != "aws"', text)


if __name__ == "__main__":
    unittest.main()