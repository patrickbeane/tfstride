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
                "rds_publicly_accessible_state": "enabled",
                "rds_backup_retention_period": 7,
                "rds_deletion_protection_state": "enabled",
                "rds_multi_az_state": "disabled",
                "rds_kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/rds",
                "rds_posture_uncertainties": ["backup_retention_period is unknown after planning"],
                "trust_statements": [{"Effect": "Allow"}],
                "s3_versioning_status": "Enabled",
                "s3_versioning_source_address": "aws_s3_bucket_versioning.logs",
                "s3_versioning_configuration": {"status": "Enabled"},
                "s3_encryption_algorithm": "aws:kms",
                "s3_kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/storage",
                "s3_bucket_key_enabled_state": "enabled",
                "s3_encryption_source_address": "aws_s3_bucket_server_side_encryption_configuration.logs",
                "s3_server_side_encryption_configuration": {"rule": []},
                "s3_posture_uncertainties": ["aws_s3_bucket_versioning.logs: status is unknown"],
                "eks_cluster_arn": "arn:aws:eks:us-east-1:111122223333:cluster/app",
                "eks_cluster_role_arn": "arn:aws:iam::111122223333:role/eks-control-plane",
                "eks_kubernetes_version": "1.29",
                "eks_endpoint_public_access_state": "enabled",
                "eks_endpoint_private_access_state": "disabled",
                "eks_public_access_cidrs": ["0.0.0.0/0"],
                "eks_public_access_cidrs_state": "configured",
                "eks_subnet_ids": ["subnet-a", "subnet-b"],
                "eks_security_group_ids": ["sg-client"],
                "eks_cluster_security_group_id": "sg-cluster",
                "eks_vpc_config": {"endpoint_public_access": True},
                "eks_enabled_cluster_log_types": ["api", "audit", "authenticator"],
                "eks_control_plane_logging_state": "configured",
                "eks_encryption_config": [
                    {
                        "key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks",
                        "resources": ["secrets"],
                    }
                ],
                "eks_encryption_config_state": "configured",
                "eks_secrets_encryption_state": "enabled",
                "eks_encryption_key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks",
                "eks_encryption_resources": ["secrets"],
                "eks_access_config_state": "configured",
                "eks_authentication_mode": "API_AND_CONFIG_MAP",
                "eks_bootstrap_cluster_creator_admin_permissions_state": "enabled",
                "eks_access_config": {"authentication_mode": "API_AND_CONFIG_MAP"},
                "eks_posture_uncertainties": ["vpc_config.endpoint_public_access is unknown after planning"],
            }
        )

        facts = aws_facts(resource)

        self.assertIsInstance(facts, AwsResourceFacts)
        self.assertEqual(facts.cluster_reference, "arn:aws:ecs:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.task_definition_reference, "app:7")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(facts.requires_compatibilities, ["FARGATE"])
        self.assertEqual(facts.engine, "postgres")
        self.assertEqual(facts.rds_publicly_accessible_state, "enabled")
        self.assertTrue(facts.rds_publicly_accessible)
        self.assertEqual(facts.rds_backup_retention_period, 7)
        self.assertEqual(facts.rds_deletion_protection_state, "enabled")
        self.assertTrue(facts.rds_deletion_protection)
        self.assertEqual(facts.rds_multi_az_state, "disabled")
        self.assertFalse(facts.rds_multi_az)
        self.assertEqual(facts.rds_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/rds")
        self.assertEqual(facts.rds_posture_uncertainties, ["backup_retention_period is unknown after planning"])
        self.assertEqual(facts.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.s3_versioning_status, "Enabled")
        self.assertTrue(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_source_address, "aws_s3_bucket_versioning.logs")
        self.assertEqual(facts.s3_versioning_configuration, {"status": "Enabled"})
        self.assertEqual(facts.s3_encryption_algorithm, "aws:kms")
        self.assertEqual(facts.s3_kms_master_key_id, "arn:aws:kms:us-east-1:111122223333:key/storage")
        self.assertEqual(facts.s3_bucket_key_enabled_state, "enabled")
        self.assertTrue(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_encryption_source_address,
            "aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        self.assertEqual(facts.s3_server_side_encryption_configuration, {"rule": []})
        self.assertEqual(facts.s3_posture_uncertainties, ["aws_s3_bucket_versioning.logs: status is unknown"])
        self.assertEqual(facts.eks_cluster_arn, "arn:aws:eks:us-east-1:111122223333:cluster/app")
        self.assertEqual(facts.eks_cluster_role_arn, "arn:aws:iam::111122223333:role/eks-control-plane")
        self.assertEqual(facts.eks_kubernetes_version, "1.29")
        self.assertEqual(facts.eks_endpoint_public_access_state, "enabled")
        self.assertEqual(facts.eks_endpoint_private_access_state, "disabled")
        self.assertEqual(facts.eks_public_access_cidrs, ["0.0.0.0/0"])
        self.assertEqual(facts.eks_public_access_cidrs_state, "configured")
        self.assertEqual(facts.eks_subnet_ids, ["subnet-a", "subnet-b"])
        self.assertEqual(facts.eks_security_group_ids, ["sg-client"])
        self.assertEqual(facts.eks_cluster_security_group_id, "sg-cluster")
        self.assertEqual(facts.eks_vpc_config, {"endpoint_public_access": True})
        self.assertEqual(facts.eks_enabled_cluster_log_types, ["api", "audit", "authenticator"])
        self.assertEqual(facts.eks_control_plane_logging_state, "configured")
        self.assertEqual(
            facts.eks_encryption_config,
            [{"key_arn": "arn:aws:kms:us-east-1:111122223333:key/eks", "resources": ["secrets"]}],
        )
        self.assertEqual(facts.eks_encryption_config_state, "configured")
        self.assertEqual(facts.eks_secrets_encryption_state, "enabled")
        self.assertEqual(facts.eks_encryption_key_arn, "arn:aws:kms:us-east-1:111122223333:key/eks")
        self.assertEqual(facts.eks_encryption_resources, ["secrets"])
        self.assertEqual(facts.eks_access_config_state, "configured")
        self.assertEqual(facts.eks_authentication_mode, "API_AND_CONFIG_MAP")
        self.assertEqual(facts.eks_bootstrap_cluster_creator_admin_permissions_state, "enabled")
        self.assertEqual(facts.eks_access_config, {"authentication_mode": "API_AND_CONFIG_MAP"})
        self.assertEqual(
            facts.eks_posture_uncertainties,
            ["vpc_config.endpoint_public_access is unknown after planning"],
        )

    def test_writes_aws_provider_metadata_through_resource_fields(self) -> None:
        resource = _resource()
        facts = aws_facts(resource)

        facts.set_network_mode("awsvpc")
        facts.set_task_role_arn("arn:aws:iam::111122223333:role/task")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_unresolved_task_definition_reference("app:7")
        facts.add_public_exposure_reason("service is internet-facing")
        facts.set_s3_versioning_posture(
            status="Suspended",
            configuration={"status": "Suspended"},
            source_address="aws_s3_bucket_versioning.logs",
        )
        facts.set_s3_encryption_posture(
            algorithm="AES256",
            kms_master_key_id=None,
            bucket_key_enabled_state="disabled",
            configuration={"rule": []},
            source_address="aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        facts.extend_s3_posture_uncertainties(["status is unknown", "status is unknown"])

        self.assertEqual(facts.network_mode, "awsvpc")
        self.assertEqual(facts.task_role_arn, "arn:aws:iam::111122223333:role/task")
        self.assertEqual(
            resource.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES),
            ["app:7"],
        )
        self.assertEqual(resource.public_exposure_reasons, ["service is internet-facing"])
        self.assertEqual(facts.s3_versioning_status, "Suspended")
        self.assertFalse(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_source_address, "aws_s3_bucket_versioning.logs")
        self.assertEqual(facts.s3_versioning_configuration, {"status": "Suspended"})
        self.assertEqual(facts.s3_encryption_algorithm, "AES256")
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertEqual(facts.s3_bucket_key_enabled_state, "disabled")
        self.assertFalse(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_encryption_source_address,
            "aws_s3_bucket_server_side_encryption_configuration.logs",
        )
        self.assertEqual(facts.s3_server_side_encryption_configuration, {"rule": []})
        self.assertEqual(facts.s3_posture_uncertainties, ["status is unknown"])
        self.assertFalse(hasattr(resource, "task_role_arn"))

    def test_s3_posture_facts_default_to_missing_when_not_modeled(self) -> None:
        facts = aws_facts(_resource())

        self.assertIsNone(facts.s3_versioning_status)
        self.assertIsNone(facts.s3_versioning_enabled)
        self.assertIsNone(facts.s3_versioning_source_address)
        self.assertEqual(facts.s3_versioning_configuration, {})
        self.assertIsNone(facts.s3_encryption_algorithm)
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertIsNone(facts.s3_bucket_key_enabled_state)
        self.assertIsNone(facts.s3_bucket_key_enabled)
        self.assertIsNone(facts.s3_encryption_source_address)
        self.assertEqual(facts.s3_server_side_encryption_configuration, {})
        self.assertEqual(facts.s3_posture_uncertainties, [])
        self.assertIsNone(facts.eks_cluster_arn)
        self.assertIsNone(facts.eks_cluster_role_arn)
        self.assertIsNone(facts.eks_kubernetes_version)
        self.assertIsNone(facts.eks_endpoint_public_access_state)
        self.assertIsNone(facts.eks_endpoint_private_access_state)
        self.assertEqual(facts.eks_public_access_cidrs, [])
        self.assertIsNone(facts.eks_public_access_cidrs_state)
        self.assertEqual(facts.eks_subnet_ids, [])
        self.assertEqual(facts.eks_security_group_ids, [])
        self.assertIsNone(facts.eks_cluster_security_group_id)
        self.assertEqual(facts.eks_vpc_config, {})
        self.assertEqual(facts.eks_enabled_cluster_log_types, [])
        self.assertIsNone(facts.eks_control_plane_logging_state)
        self.assertEqual(facts.eks_encryption_config, [])
        self.assertIsNone(facts.eks_encryption_config_state)
        self.assertIsNone(facts.eks_secrets_encryption_state)
        self.assertIsNone(facts.eks_encryption_key_arn)
        self.assertEqual(facts.eks_encryption_resources, [])
        self.assertIsNone(facts.eks_access_config_state)
        self.assertIsNone(facts.eks_authentication_mode)
        self.assertIsNone(facts.eks_bootstrap_cluster_creator_admin_permissions_state)
        self.assertEqual(facts.eks_access_config, {})
        self.assertIsNone(facts.rds_publicly_accessible_state)
        self.assertIsNone(facts.rds_publicly_accessible)
        self.assertIsNone(facts.rds_backup_retention_period)
        self.assertIsNone(facts.rds_deletion_protection_state)
        self.assertIsNone(facts.rds_deletion_protection)
        self.assertIsNone(facts.rds_multi_az_state)
        self.assertIsNone(facts.rds_multi_az)
        self.assertIsNone(facts.rds_kms_key_id)
        self.assertEqual(facts.rds_posture_uncertainties, [])
        self.assertEqual(facts.eks_posture_uncertainties, [])

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
            "uniform_bucket_level_access",
            "public_access_prevention",
            "versioning_enabled",
            "default_kms_key_name",
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
            "authorized_networks",
            "backup_enabled",
            "point_in_time_recovery_enabled",
            "ipv4_enabled",
            "private_network",
            "require_ssl",
            "ssl_mode",
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
                AwsResourceMetadata.RDS_BACKUP_RETENTION_PERIOD: 7,
                AwsResourceMetadata.RDS_DELETION_PROTECTION_STATE: "enabled",
                AwsResourceMetadata.RDS_PUBLICLY_ACCESSIBLE_STATE: "disabled",
                AwsResourceMetadata.S3_VERSIONING_STATUS: "Enabled",
            }
        )

        domains = aws_fact_domains(resource)

        self.assertIsInstance(domains.storage, AwsStorageFacts)
        self.assertIsInstance(domains.iam, AwsIamFacts)
        self.assertIsInstance(domains.sql, AwsSqlFacts)
        self.assertIsInstance(domains.compute, NeutralProviderComputeFacts)
        self.assertIsInstance(domains.workload, NeutralProviderWorkloadFacts)
        self.assertEqual(domains.storage.bucket_name, "logs")
        self.assertEqual(domains.storage.bucket_acl, "private")
        self.assertTrue(domains.storage.s3_versioning_enabled)
        self.assertIsNone(domains.storage.uniform_bucket_level_access)
        self.assertEqual(domains.iam.policy_document, {"Statement": []})
        self.assertEqual(domains.iam.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(domains.iam.reference_values, [])
        self.assertIsNone(domains.iam.service_account_email)
        self.assertEqual(domains.sql.engine, "postgres")
        self.assertTrue(domains.sql.backup_enabled)
        self.assertTrue(domains.sql.deletion_protection)
        self.assertFalse(domains.sql.ipv4_enabled)
        self.assertEqual(domains.sql.authorized_networks, [])
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
