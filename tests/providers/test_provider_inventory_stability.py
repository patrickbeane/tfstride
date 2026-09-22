from __future__ import annotations

import unittest
from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tests.integration.analysis_support import (
    AZURE_FIXTURE_PATH,
    AZURE_IDENTITY_FIXTURE_PATH,
    FIXTURE_PATH,
    GCP_FIXTURE_PATH,
)
from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import NormalizedResource
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES
from tfstride.resource_metadata import InventoryMetadata

_PolicyStatementSnapshot = tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class _DecoratedResourceExpectation:
    address: str
    vpc_id: str | None = None
    subnet_ids: tuple[str, ...] = ()
    security_group_ids: tuple[str, ...] = ()
    attached_role_arns: tuple[str, ...] = ()
    policy_statements: tuple[_PolicyStatementSnapshot, ...] = ()
    public_access_configured: bool = False
    public_exposure: bool = False
    direct_internet_reachable: bool = False
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _FindingProfile:
    severity_counts: Mapping[str, int]
    rule_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class _ProviderInventoryCase:
    provider: str
    fixture_path: Path
    expected_addresses: tuple[str, ...]
    supported_resource_types: Collection[str]
    expected_supported_type_count: int
    expected_input_count: int
    expected_unsupported_resources: tuple[str, ...]
    expected_unsupported_resource_types: Mapping[str, int]
    expected_primary_account_id: str | None
    expected_registered_rule_count: int
    expected_decorated_resources: tuple[_DecoratedResourceExpectation, ...]
    expected_finding_profile: _FindingProfile


_AWS_DECORATED_RESOURCES = (
    _DecoratedResourceExpectation(
        address="aws_instance.app",
        vpc_id="vpc-001",
        subnet_ids=("subnet-public-001",),
        security_group_ids=("sg-app-001",),
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
    ),
    _DecoratedResourceExpectation(
        address="aws_s3_bucket.assets",
        policy_statements=(
            (
                "Allow",
                ("s3:GetObject",),
                ("arn:aws:s3:::customer-assets/*",),
                ("*",),
            ),
        ),
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
    ),
    _DecoratedResourceExpectation(
        address="aws_iam_role.workload",
        policy_statements=(
            (
                "Allow",
                ("s3:*", "kms:Decrypt", "iam:PassRole", "sts:AssumeRole"),
                ("*",),
                (),
            ),
            ("Allow", ("ec2:*", "iam:*"), ("*",), ()),
        ),
        metadata={
            "attached_policy_arns": ["arn:aws:iam::111122223333:policy/admin-like"],
            "attached_policy_addresses": ["aws_iam_policy.admin_like"],
        },
    ),
    _DecoratedResourceExpectation(
        address="aws_lambda_function.processor",
        vpc_id="vpc-001",
        subnet_ids=("subnet-private-001",),
        security_group_ids=("sg-app-001",),
        attached_role_arns=("arn:aws:iam::111122223333:role/workload-role",),
    ),
)

_GCP_DECORATED_RESOURCES = (
    _DecoratedResourceExpectation(
        address="google_compute_instance.web",
        vpc_id="google_compute_network.main.id",
        subnet_ids=("google_compute_subnetwork.app.id",),
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
        metadata={
            "internet_ingress_firewalls": [
                "google_compute_firewall.public_app",
                "google_compute_firewall.public_ssh",
            ],
        },
    ),
    _DecoratedResourceExpectation(
        address="google_storage_bucket.logs",
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
        metadata={
            "gcp_resource_policy_source_addresses": ["google_storage_bucket_iam_member.public_logs_reader"],
            "iam_bindings": [
                {
                    "members": ["allUsers"],
                    "role": "roles/storage.objectViewer",
                    "source": "google_storage_bucket_iam_member.public_logs_reader",
                }
            ],
        },
    ),
)

_AZURE_DECORATED_RESOURCES = (
    _DecoratedResourceExpectation(
        address="azurerm_storage_account.assets",
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
        metadata={
            "public_container_addresses": ["azurerm_storage_container.public_assets"],
        },
    ),
    _DecoratedResourceExpectation(
        address="azurerm_storage_container.public_assets",
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
        metadata={
            "resolved_storage_account_address": "azurerm_storage_account.assets",
        },
    ),
    _DecoratedResourceExpectation(
        address="azurerm_network_interface.web",
        vpc_id="azurerm_virtual_network.main",
        subnet_ids=("azurerm_subnet.web",),
        security_group_ids=(
            "azurerm_network_security_group.web_nic",
            "azurerm_network_security_group.web_subnet",
        ),
        public_access_configured=True,
        metadata={
            "resolved_subnet_addresses": ["azurerm_subnet.web"],
            "resolved_network_security_group_addresses": ["azurerm_network_security_group.web_nic"],
            "resolved_public_ip_addresses": ["azurerm_public_ip.web"],
        },
    ),
    _DecoratedResourceExpectation(
        address="azurerm_linux_virtual_machine.web",
        vpc_id="azurerm_virtual_network.main",
        subnet_ids=("azurerm_subnet.web",),
        security_group_ids=(
            "azurerm_network_security_group.web_nic",
            "azurerm_network_security_group.web_subnet",
        ),
        public_access_configured=True,
        public_exposure=True,
        direct_internet_reachable=True,
        metadata={
            "resolved_network_interface_addresses": ["azurerm_network_interface.web"],
            "resolved_public_ip_addresses": ["azurerm_public_ip.web"],
        },
    ),
)

_AWS_FINDING_PROFILE = _FindingProfile(
    severity_counts={"high": 4, "medium": 10, "low": 1},
    rule_counts={
        "aws-database-permissive-ingress": 1,
        "aws-iam-privileged-role-assignment": 1,
        "aws-iam-wildcard-permissions": 2,
        "aws-missing-tier-segmentation": 1,
        "aws-public-alb-waf-missing": 1,
        "aws-public-compute-broad-ingress": 1,
        "aws-rds-cloudwatch-log-exports-missing": 1,
        "aws-role-trust-expansion": 1,
        "aws-role-trust-missing-narrowing": 1,
        "aws-s3-public-access": 1,
        "aws-vpc-flow-logs-not-configured": 1,
        "aws-workload-kms-vpc-endpoint-missing": 1,
        "aws-workload-role-sensitive-permissions": 1,
        "aws-workload-s3-vpc-endpoint-missing": 1,
    },
)

_GCP_FINDING_PROFILE = _FindingProfile(
    severity_counts={"high": 6, "medium": 20},
    rule_counts={
        "gcp-bigquery-public-access": 1,
        "gcp-cloud-sql-backup-disabled": 1,
        "gcp-cloud-sql-deletion-protection-disabled": 1,
        "gcp-cloud-sql-public-authorized-network": 1,
        "gcp-cloud-sql-public-ip-without-private-network": 1,
        "gcp-cloud-sql-ssl-not-required": 1,
        "gcp-cloud-sql-zonal-availability": 1,
        "gcp-compute-os-login-disabled": 1,
        "gcp-gcs-customer-managed-encryption-missing": 1,
        "gcp-gcs-public-access": 1,
        "gcp-gcs-public-access-prevention-not-enforced": 1,
        "gcp-gcs-retention-policy-insufficient": 1,
        "gcp-gcs-versioning-disabled": 1,
        "gcp-inherited-iam-blast-radius": 1,
        "gcp-public-compute-broad-ingress": 1,
        "gcp-public-workload-sensitive-data-access": 1,
        "gcp-pubsub-public-access": 1,
        "gcp-pubsub-subscription-dead-letter-policy-missing": 1,
        "gcp-pubsub-topic-customer-managed-encryption-missing": 1,
        "gcp-secret-manager-customer-managed-encryption-missing": 1,
        "gcp-secret-manager-lifecycle-posture-incomplete": 1,
        "gcp-sensitive-resource-iam-external-access": 2,
        "gcp-service-account-key-effective-access": 1,
        "gcp-service-account-key-hygiene": 1,
        "gcp-subnetwork-flow-logs-not-configured": 1,
    },
)

_AZURE_FINDING_PROFILE = _FindingProfile(
    severity_counts={"high": 3, "medium": 16, "low": 5},
    rule_counts={
        "azure-aks-api-server-public-unrestricted": 1,
        "azure-aks-azure-policy-not-enabled": 1,
        "azure-aks-defender-not-enabled": 1,
        "azure-aks-key-management-service-not-configured": 1,
        "azure-aks-local-accounts-not-disabled": 1,
        "azure-aks-monitoring-agent-not-enabled": 1,
        "azure-aks-network-policy-missing": 1,
        "azure-aks-rbac-posture-weak": 1,
        "azure-aks-workload-identity-not-enabled": 1,
        "azure-diagnostic-settings-missing": 3,
        "azure-key-vault-missing-private-endpoint": 1,
        "azure-key-vault-public-network-access": 1,
        "azure-key-vault-purge-protection-disabled": 1,
        "azure-nsg-flow-logs-not-configured": 2,
        "azure-public-compute-broad-ingress": 1,
        "azure-storage-account-minimum-tls-below-1-2": 1,
        "azure-storage-account-missing-private-endpoint": 1,
        "azure-storage-account-nested-public-access-enabled": 1,
        "azure-storage-account-public-network-unrestricted": 1,
        "azure-storage-account-shared-key-enabled": 1,
        "azure-storage-container-public-access": 1,
    },
)


_PROVIDER_INVENTORY_CASES = (
    _ProviderInventoryCase(
        provider="aws",
        fixture_path=FIXTURE_PATH,
        expected_addresses=(
            "aws_vpc.main",
            "aws_subnet.public_app",
            "aws_subnet.private_data",
            "aws_internet_gateway.main",
            "aws_route_table.public",
            "aws_nat_gateway.main",
            "aws_route_table.private",
            "aws_route_table_association.public_app",
            "aws_route_table_association.private_data",
            "aws_security_group.app",
            "aws_security_group_rule.app_ssh_from_internet",
            "aws_security_group_rule.app_http_from_internet",
            "aws_security_group.db",
            "aws_security_group_rule.db_from_public_app",
            "aws_security_group_rule.db_from_internet",
            "aws_lb.web",
            "aws_instance.app",
            "aws_db_instance.app",
            "aws_s3_bucket.assets",
            "aws_iam_role.workload",
            "aws_iam_policy.admin_like",
            "aws_iam_role_policy_attachment.workload_admin_like",
            "aws_lambda_function.processor",
        ),
        supported_resource_types=SUPPORTED_AWS_TYPES,
        expected_supported_type_count=70,
        expected_input_count=24,
        expected_unsupported_resources=("aws_cloudwatch_log_group.processor",),
        expected_unsupported_resource_types={"aws_cloudwatch_log_group": 1},
        expected_primary_account_id="111122223333",
        expected_registered_rule_count=104,
        expected_decorated_resources=_AWS_DECORATED_RESOURCES,
        expected_finding_profile=_AWS_FINDING_PROFILE,
    ),
    _ProviderInventoryCase(
        provider="gcp",
        fixture_path=GCP_FIXTURE_PATH,
        expected_addresses=(
            "google_compute_network.main",
            "google_compute_subnetwork.app",
            "google_compute_route.default_internet",
            "google_compute_firewall.public_ssh",
            "google_compute_firewall.public_app",
            "google_service_account.web",
            "google_service_account_key.web",
            "google_compute_instance.web",
            "google_sql_database_instance.app",
            "google_storage_bucket.logs",
            "google_storage_bucket_iam_member.public_logs_reader",
            "google_secret_manager_secret.api_key",
            "google_secret_manager_secret_iam_member.public_accessor",
            "google_kms_crypto_key.customer",
            "google_kms_crypto_key_iam_member.partner_decrypter",
            "google_pubsub_topic.events",
            "google_pubsub_subscription.events",
            "google_pubsub_topic_iam_member.public_publisher",
            "google_bigquery_dataset.analytics",
            "google_bigquery_table.events",
            "google_bigquery_dataset_iam_binding.analytics_viewers",
            "google_project_iam_member.web_viewer",
            "google_logging_project_sink.processor",
        ),
        supported_resource_types=SUPPORTED_GCP_TYPES,
        expected_supported_type_count=118,
        expected_input_count=23,
        expected_unsupported_resources=(),
        expected_unsupported_resource_types={},
        expected_primary_account_id=None,
        expected_registered_rule_count=97,
        expected_decorated_resources=_GCP_DECORATED_RESOURCES,
        expected_finding_profile=_GCP_FINDING_PROFILE,
    ),
    _ProviderInventoryCase(
        provider="azure",
        fixture_path=AZURE_FIXTURE_PATH,
        expected_addresses=(
            "azurerm_storage_account.assets",
            "azurerm_storage_account_network_rules.assets",
            "azurerm_storage_container.public_assets",
            "azurerm_virtual_network.main",
            "azurerm_subnet.web",
            "azurerm_network_security_group.web_subnet",
            "azurerm_subnet_network_security_group_association.web",
            "azurerm_network_security_group.web_nic",
            "azurerm_network_security_rule.allow_ssh",
            "azurerm_public_ip.web",
            "azurerm_network_interface.web",
            "azurerm_network_interface_security_group_association.web",
            "azurerm_linux_virtual_machine.web",
            "azurerm_kubernetes_cluster.platform",
            "azurerm_key_vault.application",
        ),
        supported_resource_types=SUPPORTED_AZURE_TYPES,
        expected_supported_type_count=63,
        expected_input_count=15,
        expected_unsupported_resources=(),
        expected_unsupported_resource_types={},
        expected_primary_account_id=None,
        expected_registered_rule_count=116,
        expected_decorated_resources=_AZURE_DECORATED_RESOURCES,
        expected_finding_profile=_AZURE_FINDING_PROFILE,
    ),
)


def _decorated_resource_snapshot(
    resource: NormalizedResource,
    metadata_keys: Collection[str],
) -> _DecoratedResourceExpectation:
    metadata = resource.metadata_snapshot()
    return _DecoratedResourceExpectation(
        address=resource.address,
        vpc_id=resource.vpc_id,
        subnet_ids=resource.subnet_ids,
        security_group_ids=resource.security_group_ids,
        attached_role_arns=resource.attached_role_arns,
        policy_statements=tuple(
            (
                statement.effect,
                tuple(statement.actions),
                tuple(statement.resources),
                tuple(statement.principals),
            )
            for statement in resource.policy_statements
        ),
        public_access_configured=resource.public_access_configured,
        public_exposure=resource.public_exposure,
        direct_internet_reachable=resource.direct_internet_reachable,
        metadata={key: metadata[key] for key in metadata_keys},
    )


class ProviderInventoryStabilityTests(unittest.TestCase):
    maxDiff = None

    def test_real_provider_inventories_and_rule_counts_stay_stable(self) -> None:
        for case in _PROVIDER_INVENTORY_CASES:
            with self.subTest(provider=case.provider):
                result = TfStride(provider=case.provider).analyze_plan(case.fixture_path)
                inventory = result.inventory
                source_resources = {
                    resource.address: resource for resource in load_terraform_plan(case.fixture_path).resources
                }
                resources_by_address = {resource.address: resource for resource in inventory.resources}

                self.assertEqual(inventory.provider, case.provider)
                self.assertEqual(
                    tuple(resource.address for resource in inventory.resources),
                    case.expected_addresses,
                )
                self.assertEqual(
                    tuple(resource.resource_type for resource in inventory.resources),
                    tuple(address.split(".", 1)[0] for address in case.expected_addresses),
                )
                self.assertTrue(all(resource.provider == case.provider for resource in inventory.resources))
                self.assertEqual(
                    tuple(inventory.unsupported_resources),
                    case.expected_unsupported_resources,
                )

                self.assertEqual(len(case.supported_resource_types), case.expected_supported_type_count)
                expected_metadata: dict[str, object] = {
                    InventoryMetadata.SUPPORTED_RESOURCE_TYPES.key: sorted(case.supported_resource_types),
                    InventoryMetadata.TOTAL_INPUT_RESOURCES.key: case.expected_input_count,
                    InventoryMetadata.PROVIDER_RESOURCE_COUNT.key: case.expected_input_count,
                    InventoryMetadata.NORMALIZED_RESOURCE_COUNT.key: len(case.expected_addresses),
                    InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.key: dict(case.expected_unsupported_resource_types),
                }
                if case.expected_primary_account_id is not None:
                    expected_metadata[InventoryMetadata.PRIMARY_ACCOUNT_ID.key] = case.expected_primary_account_id
                self.assertEqual(inventory.metadata_snapshot(), expected_metadata)
                self.assertEqual(inventory.primary_account_id, case.expected_primary_account_id)

                for resource in inventory.resources:
                    source = source_resources[resource.address]
                    self.assertEqual(resource.provider_config_key, source.provider_config_key)
                    self.assertEqual(resource.reference_resolutions, source.reference_resolutions)
                    with self.assertRaisesRegex(RuntimeError, "decoration state is frozen"):
                        resource.add_attached_role_arn("arn:test:late-decoration")

                for expected in case.expected_decorated_resources:
                    with self.subTest(provider=case.provider, resource=expected.address):
                        self.assertEqual(
                            _decorated_resource_snapshot(
                                resources_by_address[expected.address],
                                expected.metadata.keys(),
                            ),
                            expected,
                        )

                resource_coverage = result.analysis_coverage.resources
                self.assertEqual(resource_coverage.total_resources, case.expected_input_count)
                self.assertEqual(resource_coverage.provider_resources, case.expected_input_count)
                self.assertEqual(resource_coverage.normalized_resources, len(case.expected_addresses))
                self.assertEqual(
                    resource_coverage.unsupported_resources,
                    len(case.expected_unsupported_resources),
                )
                self.assertEqual(
                    resource_coverage.unsupported_resource_types,
                    dict(case.expected_unsupported_resource_types),
                )

                rule_coverage = result.analysis_coverage.rules
                self.assertEqual(
                    rule_coverage.registered_rule_count,
                    case.expected_registered_rule_count,
                )
                self.assertEqual(
                    len(rule_coverage.enabled_rules),
                    case.expected_registered_rule_count,
                )
                self.assertTrue(all(rule_id.startswith(f"{case.provider}-") for rule_id in rule_coverage.enabled_rules))

                finding_profile = case.expected_finding_profile
                self.assertEqual(
                    Counter(finding.severity.value for finding in result.findings),
                    Counter(finding_profile.severity_counts),
                )
                self.assertEqual(
                    Counter(finding.rule_id for finding in result.findings),
                    Counter(finding_profile.rule_counts),
                )
                self.assertEqual(
                    len(result.findings),
                    sum(finding_profile.rule_counts.values()),
                )

    def test_azure_managed_identity_role_relationships_stay_stable(self) -> None:
        result = TfStride(provider="azure").analyze_plan(AZURE_IDENTITY_FIXTURE_PATH)
        resources = {resource.address: resource for resource in result.inventory.resources}
        identity_facts = azure_facts(resources["azurerm_user_assigned_identity.deploy"])

        self.assertEqual(
            tuple(
                (
                    assignment["source"],
                    assignment["role_definition_name"],
                    assignment["scope_kind"],
                    assignment.get("target_resource_address"),
                )
                for assignment in identity_facts.managed_identity_role_assignments
            ),
            (
                (
                    "azurerm_role_assignment.subscription_owner",
                    "Owner",
                    "subscription",
                    None,
                ),
                (
                    "azurerm_role_assignment.storage_owner",
                    "Storage Blob Data Owner",
                    "resource",
                    "azurerm_storage_account.logs",
                ),
            ),
        )
        self.assertEqual(
            tuple(
                (
                    grant.assignment_source_address,
                    grant.role_name,
                    grant.assignment_scope.scope_kind.value,
                    grant.assignment_scope.source_address,
                )
                for grant in identity_facts.privileged_access_grants
            ),
            (
                (
                    "azurerm_role_assignment.subscription_owner",
                    "Owner",
                    "subscription",
                    "azurerm_role_assignment.subscription_owner",
                ),
                (
                    "azurerm_role_assignment.storage_owner",
                    "Storage Blob Data Owner",
                    "resource",
                    "azurerm_storage_account.logs",
                ),
            ),
        )

        for assignment_address in (
            "azurerm_role_assignment.subscription_owner",
            "azurerm_role_assignment.storage_owner",
        ):
            with self.subTest(assignment=assignment_address):
                self.assertEqual(
                    azure_facts(resources[assignment_address]).resolved_managed_identity_address,
                    "azurerm_user_assigned_identity.deploy",
                )

        self.assertEqual(
            azure_facts(resources["azurerm_linux_virtual_machine.web"]).attached_identity_references,
            ["azurerm_user_assigned_identity.deploy.id"],
        )


if __name__ == "__main__":
    unittest.main()
