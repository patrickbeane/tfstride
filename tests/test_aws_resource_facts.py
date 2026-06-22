from __future__ import annotations

import re
import unittest

from tests.helpers.paths import SOURCE_ROOT
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts import (
    AwsIamFacts,
    AwsResourceFacts,
    AwsSqlFacts,
    AwsStorageFacts,
    aws_fact_domains,
    aws_facts,
)
from tfstride.providers.resource_facts import (
    NeutralProviderComputeFacts,
    NeutralProviderGkeFacts,
    NeutralProviderWorkloadFacts,
)


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
                "engine": "postgres",
                "trust_statements": [{"Effect": "Allow"}],
            }
        )

        facts = aws_facts(resource)

        self.assertIsInstance(facts, AwsResourceFacts)
        self.assertEqual(facts.cluster_reference, "arn:aws:ecs:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.task_definition_reference, "app:7")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(facts.requires_compatibilities, ["FARGATE"])
        self.assertEqual(facts.engine, "postgres")
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])

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
            resource.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES),
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

    def test_raw_aws_facts_expose_only_aws_owned_fact_properties(self) -> None:
        facts = aws_facts(_resource())
        unsupported_defaults = {
            "gcs_uniform_bucket_level_access",
            "gcs_public_access_prevention",
            "gcs_versioning_enabled",
            "gcs_default_kms_key_name",
            "customer_managed_encryption",
            "project",
            "reference_values",
            "iam_target_reference",
            "iam_bindings",
            "custom_role_id",
            "custom_role_permissions",
            "organization_id",
            "folder_id",
            "service_account_email",
            "service_account_member",
            "service_account_reference",
            "iam_role",
            "iam_member",
            "cloud_sql_authorized_networks",
            "cloud_sql_backup_enabled",
            "cloud_sql_point_in_time_recovery_enabled",
            "cloud_sql_ipv4_enabled",
            "cloud_sql_private_network",
            "cloud_sql_require_ssl",
            "cloud_sql_ssl_mode",
            "deletion_protection",
            "os_login_enabled",
            "network_tags",
            "internet_ingress_firewalls",
            "fronted_by_internet_facing_load_balancer",
            "internet_facing_load_balancer_addresses",
            "load_balancer_frontends",
            "load_balancer_reachable_backends",
            "gke_endpoint",
            "gke_private_endpoint_enabled",
            "gke_private_nodes_enabled",
            "gke_master_authorized_networks",
            "gke_workload_identity_enabled",
            "gke_workload_identity_pool",
            "gke_node_service_account",
            "gke_node_oauth_scopes",
            "gke_node_metadata_mode",
            "gke_legacy_metadata_endpoints_enabled",
            "workload_identity_members",
            "workload_identity_scopes",
        }

        for fact_name in sorted(unsupported_defaults):
            with self.subTest(fact_name=fact_name):
                self.assertFalse(hasattr(facts, fact_name))

    def test_aws_fact_domains_add_neutral_defaults_at_analysis_boundary(self) -> None:
        resource = _resource(
            {
                AwsResourceMetadata.BUCKET_NAME: "logs",
                AwsResourceMetadata.BUCKET_ACL: "private",
                AwsResourceMetadata.POLICY_DOCUMENT: {"Statement": []},
                AwsResourceMetadata.TRUST_STATEMENTS: [{"Effect": "Allow"}],
                AwsResourceMetadata.ENGINE: "postgres",
            }
        )

        domains = aws_fact_domains(resource)

        self.assertIsInstance(domains.storage, AwsStorageFacts)
        self.assertIsInstance(domains.iam, AwsIamFacts)
        self.assertIsInstance(domains.sql, AwsSqlFacts)
        self.assertIsInstance(domains.gke, NeutralProviderGkeFacts)
        self.assertIsInstance(domains.compute, NeutralProviderComputeFacts)
        self.assertIsInstance(domains.workload, NeutralProviderWorkloadFacts)
        self.assertEqual(domains.storage.bucket_name, "logs")
        self.assertEqual(domains.storage.bucket_acl, "private")
        self.assertIsNone(domains.storage.gcs_uniform_bucket_level_access)
        self.assertEqual(domains.iam.policy_document, {"Statement": []})
        self.assertEqual(domains.iam.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(domains.iam.reference_values, [])
        self.assertIsNone(domains.iam.service_account_email)
        self.assertEqual(domains.sql.engine, "postgres")
        self.assertEqual(domains.sql.cloud_sql_authorized_networks, [])
        self.assertIsNone(domains.gke.gke_endpoint)
        self.assertFalse(domains.compute.fronted_by_internet_facing_load_balancer)
        self.assertEqual(domains.workload.workload_identity_members, [])

    def test_aws_provider_metadata_access_is_centralized_in_namespace_and_facts(self) -> None:
        aws_provider_root = SOURCE_ROOT / "providers" / "aws"
        resource_metadata_reference = re.compile(r"\bResourceMetadata\b")
        offenders: list[str] = []

        for path in sorted(aws_provider_root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if path.name == "metadata.py":
                if "get_metadata_field(" in text or "set_metadata_field(" in text:
                    offenders.append(path.name)
                continue
            if path.name == "resource_facts.py":
                if resource_metadata_reference.search(text):
                    offenders.append(path.name)
                continue
            if (
                resource_metadata_reference.search(text)
                or "get_metadata_field(" in text
                or "set_metadata_field(" in text
            ):
                offenders.append(path.name)

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
