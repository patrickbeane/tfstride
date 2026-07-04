from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_facts import (
    NeutralProviderComputeFacts,
    NeutralProviderIamFacts,
    NeutralProviderResourceFacts,
    NeutralProviderSqlFacts,
    NeutralProviderStorageFacts,
    NeutralProviderWorkloadFacts,
    ProviderComputeFacts,
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
    return {name for name, value in vars(protocol).items() if isinstance(value, property)}


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


def _fact_domains(facts: RecordingFacts) -> ProviderResourceFactDomains:
    return ProviderResourceFactDomains(
        storage=facts,
        iam=facts,
        sql=facts,
        compute=facts,
        workload=facts,
    )


class ProviderResourceFactsRegistryTests(unittest.TestCase):
    def test_provider_fact_domain_protocols_are_disjoint(self) -> None:
        domains = {
            "storage": {
                "bucket_name",
                "bucket_acl",
                "public_access_block",
                "uniform_bucket_level_access",
                "public_access_prevention",
                "versioning_enabled",
                "default_kms_key_name",
                "customer_managed_encryption",
                "gcs_retention_period_seconds",
                "gcs_retention_policy_locked",
                "gcs_retention_policy_configuration",
                "gcs_retention_policy_uncertainties",
                "secret_manager_replication_mode",
                "secret_manager_kms_key_names",
                "secret_manager_replication",
                "secret_manager_posture_uncertainties",
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
                "org_policy_constraint",
                "org_policy_rules",
                "org_policy_allowed_values",
                "org_policy_denied_values",
                "org_policy_enforced",
                "org_policy_inherit_from_parent",
                "org_policy_restore_default",
                "org_policy_scope_type",
                "org_policy_scope",
                "service_account_key_keepers",
                "service_account_key_algorithm",
                "service_account_public_key_type",
                "service_account_id",
                "service_account_key_valid_after",
                "service_account_key_valid_before",
            },
            "sql": {
                "engine",
                "authorized_networks",
                "backup_enabled",
                "point_in_time_recovery_enabled",
                "ipv4_enabled",
                "private_network",
                "require_ssl",
                "ssl_mode",
                "deletion_protection",
            },
            "compute": {
                "os_login_enabled",
                "network_tags",
                "internet_ingress_firewalls",
                "fronted_by_internet_facing_load_balancer",
                "internet_facing_load_balancer_addresses",
                "load_balancer_frontends",
                "load_balancer_reachable_backends",
                "forwarding_rule_target",
                "forwarding_rule_load_balancing_scheme",
                "forwarding_rule_ip_address",
                "forwarding_rule_ports",
                "load_balancer_ssl_policy",
                "load_balancer_certificate_map",
                "ssl_policy_min_tls_version",
                "ssl_policy_profile",
                "ssl_policy_custom_features",
                "ssl_policy_enabled_features",
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
                "gke_logging_service",
                "gke_logging_components",
                "gke_control_plane_logging_state",
                "gke_logging_config",
                "gke_network_policy_state",
                "gke_network_policy_provider",
                "gke_network_policy",
                "gke_database_encryption_state",
                "gke_database_encryption_key_name",
                "gke_secrets_encryption_state",
                "gke_database_encryption",
                "gke_legacy_abac_enabled",
                "gke_legacy_abac_state",
                "gke_client_certificate_auth_enabled",
                "gke_client_certificate_auth_state",
                "gke_basic_auth_state",
                "gke_basic_auth_username",
                "gke_basic_auth_password_configured",
                "gke_master_auth",
                "gke_client_certificate_config",
                "gke_release_channel",
                "gke_release_channel_config",
                "gke_shielded_nodes_enabled",
                "gke_shielded_nodes_state",
                "gke_shielded_nodes_config",
                "gke_binary_authorization_evaluation_mode",
                "gke_binary_authorization_state",
                "gke_binary_authorization",
                "gke_posture_uncertainties",
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
            "compute": ProviderComputeFacts,
            "workload": ProviderWorkloadFacts,
        }

        self.assertEqual(
            tuple(ProviderResourceFactDomains.__dataclass_fields__),
            ("storage", "iam", "sql", "compute", "workload"),
        )

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
        self.assertIsInstance(facts, NeutralProviderComputeFacts)
        self.assertIsInstance(facts, NeutralProviderWorkloadFacts)
        self.assertEqual(facts.bucket_acl, "")
        self.assertEqual(facts.policy_document, {})
        self.assertIsNone(facts.engine)
        self.assertFalse(facts.fronted_by_internet_facing_load_balancer)
        self.assertEqual(facts.workload_identity_members, [])

    def test_registers_and_returns_factories_by_provider_name(self) -> None:
        def factory(resource: NormalizedResource) -> ProviderResourceFactDomains:
            return _fact_domains(RecordingFacts(resource))

        registry = ProviderResourceFactsRegistry([("AWS", factory)])

        self.assertIs(registry.get(" aws "), factory)
        self.assertEqual(registry.providers(), ("aws",))

    def test_facts_for_delegates_to_registered_provider_domain_factory(self) -> None:
        calls: list[NormalizedResource] = []

        def factory(resource: NormalizedResource) -> ProviderResourceFactDomains:
            calls.append(resource)
            return _fact_domains(RecordingFacts(resource))

        resource = _resource("aws")
        facts = ProviderResourceFactsRegistry([("aws", factory)]).facts_for(resource)

        self.assertEqual(calls, [resource])
        self.assertIsInstance(facts, ProviderResourceFactDomains)
        self.assertIsInstance(facts.storage, RecordingFacts)
        self.assertIs(facts.iam, facts.storage)
        self.assertIs(facts.sql, facts.storage)
        self.assertIs(facts.compute, facts.storage)
        self.assertIs(facts.workload, facts.storage)
        self.assertEqual(facts.storage.bucket_name, "aws-bucket")

    def test_facts_for_returns_registered_domain_bundle(self) -> None:
        resource = _resource("aws")
        storage = RecordingFacts(resource)
        iam = RecordingFacts(resource)
        neutral = NeutralProviderResourceFacts(resource)
        provider_facts = ProviderResourceFactDomains(
            storage=storage,
            iam=iam,
            sql=neutral,
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
        self.assertIs(facts.compute, facts.storage)
        self.assertIs(facts.workload, facts.storage)
        self.assertIsNone(facts.storage.bucket_name)
        self.assertEqual(facts.storage.bucket_acl, "")
        self.assertIsNone(facts.storage.public_access_block)
        self.assertIsNone(facts.storage.uniform_bucket_level_access)
        self.assertIsNone(facts.storage.public_access_prevention)
        self.assertIsNone(facts.storage.versioning_enabled)
        self.assertIsNone(facts.storage.default_kms_key_name)
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
        self.assertEqual(facts.sql.authorized_networks, [])
        self.assertIsNone(facts.sql.backup_enabled)
        self.assertIsNone(facts.sql.point_in_time_recovery_enabled)
        self.assertIsNone(facts.sql.ipv4_enabled)
        self.assertIsNone(facts.sql.private_network)
        self.assertIsNone(facts.sql.require_ssl)
        self.assertIsNone(facts.sql.ssl_mode)
        self.assertIsNone(facts.sql.deletion_protection)
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
        def factory(resource: NormalizedResource) -> ProviderResourceFactDomains:
            return _fact_domains(RecordingFacts(resource))

        registry = ProviderResourceFactsRegistry([("aws", factory)])

        with self.assertRaises(ProviderResourceFactsRegistryError):
            registry.register("AWS", factory)

    def test_rejects_empty_provider_names(self) -> None:
        def factory(resource: NormalizedResource) -> ProviderResourceFactDomains:
            return _fact_domains(RecordingFacts(resource))

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
