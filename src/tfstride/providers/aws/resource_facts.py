from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.resource_metadata import MetadataField, StringListMetadataField


_MetadataValue = TypeVar("_MetadataValue")


@dataclass(frozen=True, slots=True)
class AwsResourceFacts:
    """AWS-owned view over provider-specific resource metadata."""

    resource: NormalizedResource

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        self.resource.set_metadata_field(field, value)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        self.resource.extend_metadata_field(field, values)

    @property
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        return None

    @property
    def gcs_public_access_prevention(self) -> str | None:
        return None

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        return None

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        return None

    @property
    def project(self) -> str | None:
        return None

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        return []

    @property
    def custom_role_id(self) -> str | None:
        return None

    @property
    def custom_role_permissions(self) -> list[str]:
        return []

    @property
    def organization_id(self) -> str | None:
        return None

    @property
    def folder_id(self) -> str | None:
        return None

    @property
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        return []

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        return None

    @property
    def cloud_sql_private_network(self) -> str | None:
        return None

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        return None

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        return None

    @property
    def deletion_protection(self) -> bool | None:
        return None

    @property
    def service_account_email(self) -> str | None:
        return None

    @property
    def service_account_member(self) -> str | None:
        return None

    @property
    def service_account_reference(self) -> str | None:
        return None

    @property
    def workload_identity_members(self) -> list[str]:
        return []

    @property
    def workload_identity_scopes(self) -> list[str]:
        return []

    @property
    def gke_endpoint(self) -> str | None:
        return None

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return None

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return None

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return []

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return None

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return None

    @property
    def gke_node_service_account(self) -> str | None:
        return None

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return []

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return None

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return None

    @property
    def security_group_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SECURITY_GROUP_ID)

    @property
    def role_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.ROLE_REFERENCE)

    @property
    def role_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.ROLE_REFERENCES)

    @property
    def resolved_role_references(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOLVED_ROLE_REFERENCES)

    @property
    def iam_instance_profile(self) -> str | None:
        return self.get(AwsResourceMetadata.IAM_INSTANCE_PROFILE)

    @property
    def policy_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.POLICY_ARN)

    @property
    def policy_name(self) -> str | None:
        return self.get(AwsResourceMetadata.POLICY_NAME)

    @property
    def cluster_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.CLUSTER_REFERENCE)

    @property
    def name(self) -> str | None:
        return self.get(AwsResourceMetadata.NAME)

    @property
    def resource_name(self) -> str | None:
        return self.name

    @property
    def reference_values(self) -> list[str]:
        return []

    @property
    def iam_target_reference(self) -> str | None:
        return None

    @property
    def task_definition_reference(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REFERENCE)

    @property
    def task_definition_family(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_FAMILY)

    @property
    def task_definition_revision(self) -> int | None:
        return self.get(AwsResourceMetadata.TASK_DEFINITION_REVISION)

    @property
    def network_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.NETWORK_MODE)

    @property
    def requires_compatibilities(self) -> list[str]:
        return self.get(AwsResourceMetadata.REQUIRES_COMPATIBILITIES)

    @property
    def task_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.TASK_ROLE_ARN)

    @property
    def execution_role_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.EXECUTION_ROLE_ARN)

    @property
    def secret_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.SECRET_ARN)

    @property
    def function_name(self) -> str | None:
        return self.get(AwsResourceMetadata.FUNCTION_NAME)

    @property
    def route_table_id(self) -> str | None:
        return self.get(AwsResourceMetadata.ROUTE_TABLE_ID)

    @property
    def subnet_id(self) -> str | None:
        return self.get(AwsResourceMetadata.SUBNET_ID)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.ROUTES)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return self.get(AwsResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH)

    @property
    def block_public_acls(self) -> bool:
        return self.get(AwsResourceMetadata.BLOCK_PUBLIC_ACLS)

    @property
    def block_public_policy(self) -> bool:
        return self.get(AwsResourceMetadata.BLOCK_PUBLIC_POLICY)

    @property
    def ignore_public_acls(self) -> bool:
        return self.get(AwsResourceMetadata.IGNORE_PUBLIC_ACLS)

    @property
    def restrict_public_buckets(self) -> bool:
        return self.get(AwsResourceMetadata.RESTRICT_PUBLIC_BUCKETS)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.POLICY_DOCUMENT)

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self.get(AwsResourceMetadata.PUBLIC_ACCESS_BLOCK)

    @property
    def bucket_name(self) -> str | None:
        return self.get(AwsResourceMetadata.BUCKET_NAME)

    @property
    def bucket_acl(self) -> str:
        return self.get(AwsResourceMetadata.BUCKET_ACL) or ""

    @property
    def engine(self) -> str | None:
        return self.get(AwsResourceMetadata.ENGINE)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.TRUST_STATEMENTS)

    def set_resolved_role_references(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.RESOLVED_ROLE_REFERENCES, values)

    def set_network_mode(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.NETWORK_MODE, value)

    def set_requires_compatibilities(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.REQUIRES_COMPATIBILITIES, values)

    def set_task_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.TASK_ROLE_ARN, value)

    def set_execution_role_arn(self, value: str | None) -> None:
        self.set(AwsResourceMetadata.EXECUTION_ROLE_ARN, value)

    def set_public_access_block(self, value: dict[str, bool] | None) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_BLOCK, value)

    def set_route_table_ids(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.ROUTE_TABLE_IDS, values)

    def set_internet_ingress(self, value: bool) -> None:
        self.set(AwsResourceMetadata.INTERNET_INGRESS, value)

    def set_public_access_configured(self, value: bool) -> None:
        self.set(AwsResourceMetadata.PUBLIC_ACCESS_CONFIGURED, value)

    def has_public_access_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_ACCESS_REASONS)

    def has_public_exposure_reasons(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS)

    def add_public_exposure_reason(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.PUBLIC_EXPOSURE_REASONS, value)

    def set_fronted_by_internet_facing_load_balancer(self, value: bool) -> None:
        self.set(AwsResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, value)

    def set_internet_facing_load_balancer_addresses(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES, values)

    def set_policy_document(self, value: dict[str, Any] | None) -> None:
        self.set(AwsResourceMetadata.POLICY_DOCUMENT, value)

    def add_standalone_rule_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.STANDALONE_RULE_ADDRESSES, value)

    def add_inline_policy_resource_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES, value)

    def add_inline_policy_name(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.INLINE_POLICY_NAMES, value)

    def add_unresolved_attached_policy_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.ATTACHED_POLICY_ADDRESSES, value)

    def add_unresolved_role_references(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.UNRESOLVED_ROLE_REFERENCES, values)

    def add_resolved_role_addresses(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.RESOLVED_ROLE_ADDRESSES, values)

    def add_unresolved_instance_profile(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_INSTANCE_PROFILES, value)

    def add_resolved_instance_profile_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_INSTANCE_PROFILE_ADDRESSES, value)

    def add_unresolved_cluster_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_CLUSTER_REFERENCES, value)

    def add_resolved_cluster_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_CLUSTER_ADDRESSES, value)

    def add_unresolved_task_definition_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES, value)

    def add_resolved_task_definition_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES, value)

    def add_resolved_task_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES, value)

    def add_unresolved_task_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS, value)

    def add_resolved_execution_role_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOLVED_EXECUTION_ROLE_ADDRESSES, value)

    def add_unresolved_execution_role_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_EXECUTION_ROLE_ARNS, value)

    def add_unresolved_bucket_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_BUCKET_REFERENCES, value)

    def add_unresolved_secret_arn(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_SECRET_ARNS, value)

    def add_unresolved_function_reference(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES, value)

    def add_resource_policy_source_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, value)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    @property
    def network_tags(self) -> list[str]:
        return []

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return []

    @property
    def iam_role(self) -> str | None:
        return None

    @property
    def iam_member(self) -> str | None:
        return None


def aws_facts(resource: NormalizedResource) -> AwsResourceFacts:
    return AwsResourceFacts(resource)