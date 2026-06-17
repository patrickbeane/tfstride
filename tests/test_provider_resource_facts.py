from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_facts import (
    NeutralProviderComputeFacts,
    NeutralProviderGkeFacts,
    NeutralProviderIamFacts,
    NeutralProviderResourceFacts,
    NeutralProviderSqlFacts,
    NeutralProviderStorageFacts,
    NeutralProviderWorkloadFacts,
    ProviderComputeFacts,
    ProviderGkeFacts,
    ProviderIamFacts,
    ProviderResourceFactDomains,
    ProviderResourceFactsNotRegisteredError,
    ProviderResourceFactsRegistry,
    ProviderResourceFactsRegistryError,
    ProviderSqlFacts,
    ProviderStorageFacts,
    ProviderWorkloadFacts,
)


def _resource(provider: str = "aws") -> NormalizedResource:
    return NormalizedResource(
        address="example.resource",
        provider=provider,
        resource_type="example_resource",
        name="resource",
        category=ResourceCategory.DATA,
    )


def _protocol_properties(protocol: type) -> set[str]:
    return {
        name
        for name, value in vars(protocol).items()
        if isinstance(value, property)
    }


@dataclass(frozen=True, slots=True)
class RecordingFacts:
    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return f"{self.resource.provider}-bucket"

    @property
    def bucket_acl(self) -> str:
        return "private"

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return {"block_public_acls": True}

    @property
    def policy_document(self) -> dict[str, Any]:
        return {"Statement": []}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return [{"Effect": "Allow"}]

    @property
    def engine(self) -> str | None:
        return "postgres"

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return ["example.policy"]


class ProviderResourceFactsRegistryTests(unittest.TestCase):
    def test_provider_fact_domain_protocols_are_disjoint(self) -> None:
        domains = {
            "storage": {
                "bucket_name",
                "bucket_acl",
                "public_access_block",
                "gcs_uniform_bucket_level_access",
                "gcs_public_access_prevention",
                "gcs_versioning_enabled",
                "gcs_default_kms_key_name",
                "customer_managed_encryption",
            },
            "iam": {
                "policy_document",
                "trust_statements",
                "resource_policy_source_addresses",
                "project",
                "resource_name",
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
            },
            "sql": {
                "engine",
                "cloud_sql_authorized_networks",
                "cloud_sql_backup_enabled",
                "cloud_sql_point_in_time_recovery_enabled",
                "cloud_sql_ipv4_enabled",
                "cloud_sql_private_network",
                "cloud_sql_require_ssl",
                "cloud_sql_ssl_mode",
                "deletion_protection",
            },
            "gke": {
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
            },
            "compute": {
                "os_login_enabled",
                "network_tags",
                "internet_ingress_firewalls",
                "fronted_by_internet_facing_load_balancer",
                "internet_facing_load_balancer_addresses",
                "load_balancer_frontends",
                "load_balancer_reachable_backends",
            },
            "workload": {
                "workload_identity_members",
                "workload_identity_scopes",
            },
        }
        protocols = {
            "storage": ProviderStorageFacts,
            "iam": ProviderIamFacts,
            "sql": ProviderSqlFacts,
            "gke": ProviderGkeFacts,
            "compute": ProviderComputeFacts,
            "workload": ProviderWorkloadFacts,
        }

        for domain, expected_properties in domains.items():
            with self.subTest(domain=domain):
                self.assertEqual(_protocol_properties(protocols[domain]), expected_properties)

        for domain, properties in domains.items():
            other_properties = set().union(
                *(other for other_domain, other in domains.items() if other_domain != domain)
            )
            with self.subTest(domain=domain):
                self.assertFalse(properties & other_properties)

    def test_neutral_resource_facts_composes_domain_defaults(self) -> None:
        facts = NeutralProviderResourceFacts(_resource("unknown"))

        self.assertIsInstance(facts, NeutralProviderStorageFacts)
        self.assertIsInstance(facts, NeutralProviderIamFacts)
        self.assertIsInstance(facts, NeutralProviderSqlFacts)
        self.assertIsInstance(facts, NeutralProviderGkeFacts)
        self.assertIsInstance(facts, NeutralProviderComputeFacts)
        self.assertIsInstance(facts, NeutralProviderWorkloadFacts)
        self.assertEqual(facts.bucket_acl, "")
        self.assertEqual(facts.policy_document, {})
        self.assertIsNone(facts.engine)
        self.assertEqual(facts.gke_master_authorized_networks, [])
        self.assertFalse(facts.fronted_by_internet_facing_load_balancer)
        self.assertEqual(facts.workload_identity_members, [])

    def test_registers_and_returns_factories_by_provider_name(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        registry = ProviderResourceFactsRegistry([("AWS", factory)])

        self.assertIs(registry.get(" aws "), factory)
        self.assertEqual(registry.providers(), ("aws",))

    def test_facts_for_adapts_legacy_provider_facts_across_domains(self) -> None:
        calls: list[NormalizedResource] = []

        def factory(resource: NormalizedResource) -> RecordingFacts:
            calls.append(resource)
            return RecordingFacts(resource)

        resource = _resource("aws")
        facts = ProviderResourceFactsRegistry([("aws", factory)]).facts_for(resource)

        self.assertEqual(calls, [resource])
        self.assertIsInstance(facts, ProviderResourceFactDomains)
        self.assertIsInstance(facts.storage, RecordingFacts)
        self.assertIs(facts.iam, facts.storage)
        self.assertIs(facts.sql, facts.storage)
        self.assertIs(facts.gke, facts.storage)
        self.assertIs(facts.compute, facts.storage)
        self.assertIs(facts.workload, facts.storage)
        self.assertEqual(facts.storage.bucket_name, "aws-bucket")

    def test_facts_for_preserves_pre_split_domain_bundle(self) -> None:
        resource = _resource("aws")
        storage = RecordingFacts(resource)
        iam = RecordingFacts(resource)
        neutral = NeutralProviderResourceFacts(resource)
        provider_facts = ProviderResourceFactDomains(
            storage=storage,
            iam=iam,
            sql=neutral,
            gke=neutral,
            compute=neutral,
            workload=neutral,
        )

        def factory(resource: NormalizedResource) -> ProviderResourceFactDomains:
            return provider_facts

        facts = ProviderResourceFactsRegistry([("aws", factory)]).facts_for(resource)

        self.assertIs(facts, provider_facts)
        self.assertIs(facts.storage, storage)
        self.assertIs(facts.iam, iam)
        self.assertIs(facts.sql, neutral)

    def test_facts_for_returns_neutral_facts_for_unregistered_providers(self) -> None:
        resource = _resource("gcp")
        facts = ProviderResourceFactsRegistry().facts_for(resource)

        self.assertIsInstance(facts, ProviderResourceFactDomains)
        self.assertIsInstance(facts.storage, NeutralProviderResourceFacts)
        self.assertIs(facts.iam, facts.storage)
        self.assertIs(facts.sql, facts.storage)
        self.assertIs(facts.gke, facts.storage)
        self.assertIs(facts.compute, facts.storage)
        self.assertIs(facts.workload, facts.storage)
        self.assertIsNone(facts.storage.bucket_name)
        self.assertEqual(facts.storage.bucket_acl, "")
        self.assertIsNone(facts.storage.public_access_block)
        self.assertIsNone(facts.storage.gcs_uniform_bucket_level_access)
        self.assertIsNone(facts.storage.gcs_public_access_prevention)
        self.assertIsNone(facts.storage.gcs_versioning_enabled)
        self.assertIsNone(facts.storage.gcs_default_kms_key_name)
        self.assertIsNone(facts.storage.customer_managed_encryption)
        self.assertEqual(facts.iam.policy_document, {})
        self.assertEqual(facts.iam.trust_statements, [])
        self.assertEqual(facts.iam.resource_policy_source_addresses, [])
        self.assertIsNone(facts.iam.project)
        self.assertIsNone(facts.iam.resource_name)
        self.assertEqual(facts.iam.reference_values, [])
        self.assertIsNone(facts.iam.iam_target_reference)
        self.assertEqual(facts.iam.iam_bindings, [])
        self.assertIsNone(facts.iam.custom_role_id)
        self.assertEqual(facts.iam.custom_role_permissions, [])
        self.assertIsNone(facts.iam.organization_id)
        self.assertIsNone(facts.iam.folder_id)
        self.assertIsNone(facts.iam.service_account_email)
        self.assertIsNone(facts.iam.service_account_member)
        self.assertIsNone(facts.iam.service_account_reference)
        self.assertIsNone(facts.iam.iam_role)
        self.assertIsNone(facts.iam.iam_member)
        self.assertIsNone(facts.sql.engine)
        self.assertEqual(facts.sql.cloud_sql_authorized_networks, [])
        self.assertIsNone(facts.sql.cloud_sql_backup_enabled)
        self.assertIsNone(facts.sql.cloud_sql_point_in_time_recovery_enabled)
        self.assertIsNone(facts.sql.cloud_sql_ipv4_enabled)
        self.assertIsNone(facts.sql.cloud_sql_private_network)
        self.assertIsNone(facts.sql.cloud_sql_require_ssl)
        self.assertIsNone(facts.sql.cloud_sql_ssl_mode)
        self.assertIsNone(facts.sql.deletion_protection)
        self.assertIsNone(facts.gke.gke_endpoint)
        self.assertIsNone(facts.gke.gke_private_endpoint_enabled)
        self.assertIsNone(facts.gke.gke_private_nodes_enabled)
        self.assertEqual(facts.gke.gke_master_authorized_networks, [])
        self.assertIsNone(facts.gke.gke_workload_identity_enabled)
        self.assertIsNone(facts.gke.gke_workload_identity_pool)
        self.assertIsNone(facts.gke.gke_node_service_account)
        self.assertEqual(facts.gke.gke_node_oauth_scopes, [])
        self.assertIsNone(facts.gke.gke_node_metadata_mode)
        self.assertIsNone(facts.gke.gke_legacy_metadata_endpoints_enabled)
        self.assertIsNone(facts.compute.os_login_enabled)
        self.assertEqual(facts.compute.network_tags, [])
        self.assertEqual(facts.compute.internet_ingress_firewalls, [])
        self.assertFalse(facts.compute.fronted_by_internet_facing_load_balancer)
        self.assertEqual(facts.compute.internet_facing_load_balancer_addresses, [])
        self.assertEqual(facts.compute.load_balancer_frontends, [])
        self.assertEqual(facts.compute.load_balancer_reachable_backends, [])
        self.assertEqual(facts.workload.workload_identity_members, [])
        self.assertEqual(facts.workload.workload_identity_scopes, [])

    def test_rejects_duplicate_provider_registration(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        registry = ProviderResourceFactsRegistry([("aws", factory)])

        with self.assertRaises(ProviderResourceFactsRegistryError):
            registry.register("AWS", factory)

    def test_rejects_empty_provider_names(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        with self.assertRaises(ProviderResourceFactsRegistryError):
            ProviderResourceFactsRegistry([(" ", factory)])

    def test_rejects_non_callable_factories(self) -> None:
        registry = ProviderResourceFactsRegistry()

        with self.assertRaises(ProviderResourceFactsRegistryError):
            registry.register("aws", object())

    def test_missing_provider_lookup_raises_specific_error(self) -> None:
        registry = ProviderResourceFactsRegistry()

        with self.assertRaises(ProviderResourceFactsNotRegisteredError):
            registry.get("aws")


if __name__ == "__main__":
    unittest.main()