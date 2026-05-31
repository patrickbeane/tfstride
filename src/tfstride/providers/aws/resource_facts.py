from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from tfstride.models import NormalizedResource
from tfstride.resource_metadata import MetadataField, ResourceMetadata, StringListMetadataField


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
    def security_group_id(self) -> str | None:
        return self.get(ResourceMetadata.SECURITY_GROUP_ID)

    @property
    def role_reference(self) -> str | None:
        return self.get(ResourceMetadata.ROLE_REFERENCE)

    @property
    def role_references(self) -> list[str]:
        return self.get(ResourceMetadata.ROLE_REFERENCES)

    @property
    def resolved_role_references(self) -> list[str]:
        return self.get(ResourceMetadata.RESOLVED_ROLE_REFERENCES)

    @property
    def iam_instance_profile(self) -> str | None:
        return self.get(ResourceMetadata.IAM_INSTANCE_PROFILE)

    @property
    def policy_arn(self) -> str | None:
        return self.get(ResourceMetadata.POLICY_ARN)

    @property
    def policy_name(self) -> str | None:
        return self.get(ResourceMetadata.POLICY_NAME)

    @property
    def cluster_reference(self) -> str | None:
        return self.get(ResourceMetadata.CLUSTER_REFERENCE)

    @property
    def name(self) -> str | None:
        return self.get(ResourceMetadata.NAME)

    @property
    def task_definition_reference(self) -> str | None:
        return self.get(ResourceMetadata.TASK_DEFINITION_REFERENCE)

    @property
    def task_definition_family(self) -> str | None:
        return self.get(ResourceMetadata.TASK_DEFINITION_FAMILY)

    @property
    def task_definition_revision(self) -> int | None:
        return self.get(ResourceMetadata.TASK_DEFINITION_REVISION)

    @property
    def network_mode(self) -> str | None:
        return self.get(ResourceMetadata.NETWORK_MODE)

    @property
    def requires_compatibilities(self) -> list[str]:
        return self.get(ResourceMetadata.REQUIRES_COMPATIBILITIES)

    @property
    def task_role_arn(self) -> str | None:
        return self.get(ResourceMetadata.TASK_ROLE_ARN)

    @property
    def execution_role_arn(self) -> str | None:
        return self.get(ResourceMetadata.EXECUTION_ROLE_ARN)

    @property
    def secret_arn(self) -> str | None:
        return self.get(ResourceMetadata.SECRET_ARN)

    @property
    def function_name(self) -> str | None:
        return self.get(ResourceMetadata.FUNCTION_NAME)

    @property
    def route_table_id(self) -> str | None:
        return self.get(ResourceMetadata.ROUTE_TABLE_ID)

    @property
    def subnet_id(self) -> str | None:
        return self.get(ResourceMetadata.SUBNET_ID)

    @property
    def routes(self) -> list[dict[str, Any]]:
        return self.get(ResourceMetadata.ROUTES)

    @property
    def map_public_ip_on_launch(self) -> bool:
        return self.get(ResourceMetadata.MAP_PUBLIC_IP_ON_LAUNCH)

    @property
    def block_public_acls(self) -> bool:
        return self.get(ResourceMetadata.BLOCK_PUBLIC_ACLS)

    @property
    def block_public_policy(self) -> bool:
        return self.get(ResourceMetadata.BLOCK_PUBLIC_POLICY)

    @property
    def ignore_public_acls(self) -> bool:
        return self.get(ResourceMetadata.IGNORE_PUBLIC_ACLS)

    @property
    def restrict_public_buckets(self) -> bool:
        return self.get(ResourceMetadata.RESTRICT_PUBLIC_BUCKETS)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(ResourceMetadata.POLICY_DOCUMENT)

    @property
    def bucket_name(self) -> str | None:
        return self.get(ResourceMetadata.BUCKET_NAME)

    @property
    def bucket_acl(self) -> str:
        return self.get(ResourceMetadata.BUCKET_ACL) or ""

    def set_resolved_role_references(self, values: list[str]) -> None:
        self.set(ResourceMetadata.RESOLVED_ROLE_REFERENCES, values)

    def set_network_mode(self, value: str | None) -> None:
        self.set(ResourceMetadata.NETWORK_MODE, value)

    def set_requires_compatibilities(self, values: list[str]) -> None:
        self.set(ResourceMetadata.REQUIRES_COMPATIBILITIES, values)

    def set_task_role_arn(self, value: str | None) -> None:
        self.set(ResourceMetadata.TASK_ROLE_ARN, value)

    def set_execution_role_arn(self, value: str | None) -> None:
        self.set(ResourceMetadata.EXECUTION_ROLE_ARN, value)

    def set_public_access_block(self, value: dict[str, bool] | None) -> None:
        self.set(ResourceMetadata.PUBLIC_ACCESS_BLOCK, value)

    def set_route_table_ids(self, values: list[str]) -> None:
        self.set(ResourceMetadata.ROUTE_TABLE_IDS, values)

    def set_internet_ingress(self, value: bool) -> None:
        self.set(ResourceMetadata.INTERNET_INGRESS, value)

    def set_public_access_configured(self, value: bool) -> None:
        self.set(ResourceMetadata.PUBLIC_ACCESS_CONFIGURED, value)

    def has_public_access_reasons(self) -> bool:
        return self.resource.has_metadata_field(ResourceMetadata.PUBLIC_ACCESS_REASONS)

    def has_public_exposure_reasons(self) -> bool:
        return self.resource.has_metadata_field(ResourceMetadata.PUBLIC_EXPOSURE_REASONS)

    def add_public_exposure_reason(self, value: str | None) -> None:
        self.append(ResourceMetadata.PUBLIC_EXPOSURE_REASONS, value)

    def set_fronted_by_internet_facing_load_balancer(self, value: bool) -> None:
        self.set(ResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER, value)

    def set_internet_facing_load_balancer_addresses(self, values: list[str]) -> None:
        self.set(ResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES, values)

    def set_policy_document(self, value: dict[str, Any] | None) -> None:
        self.set(ResourceMetadata.POLICY_DOCUMENT, value)

    def add_standalone_rule_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.STANDALONE_RULE_ADDRESSES, value)

    def add_inline_policy_resource_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES, value)

    def add_inline_policy_name(self, value: str | None) -> None:
        self.append(ResourceMetadata.INLINE_POLICY_NAMES, value)

    def add_unresolved_attached_policy_arn(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_arn(self, value: str | None) -> None:
        self.append(ResourceMetadata.ATTACHED_POLICY_ARNS, value)

    def add_attached_policy_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.ATTACHED_POLICY_ADDRESSES, value)

    def add_unresolved_role_references(self, values: Sequence[str | None]) -> None:
        self.extend(ResourceMetadata.UNRESOLVED_ROLE_REFERENCES, values)

    def add_resolved_role_addresses(self, values: Sequence[str | None]) -> None:
        self.extend(ResourceMetadata.RESOLVED_ROLE_ADDRESSES, values)

    def add_unresolved_instance_profile(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_INSTANCE_PROFILES, value)

    def add_resolved_instance_profile_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOLVED_INSTANCE_PROFILE_ADDRESSES, value)

    def add_unresolved_cluster_reference(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_CLUSTER_REFERENCES, value)

    def add_resolved_cluster_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOLVED_CLUSTER_ADDRESSES, value)

    def add_unresolved_task_definition_reference(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_TASK_DEFINITION_REFERENCES, value)

    def add_resolved_task_definition_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES, value)

    def add_resolved_task_role_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES, value)

    def add_unresolved_task_role_arn(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS, value)

    def add_resolved_execution_role_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOLVED_EXECUTION_ROLE_ADDRESSES, value)

    def add_unresolved_execution_role_arn(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_EXECUTION_ROLE_ARNS, value)

    def add_unresolved_bucket_reference(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_BUCKET_REFERENCES, value)

    def add_unresolved_secret_arn(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_SECRET_ARNS, value)

    def add_unresolved_function_reference(self, value: str | None) -> None:
        self.append(ResourceMetadata.UNRESOLVED_FUNCTION_REFERENCES, value)

    def add_resource_policy_source_address(self, value: str | None) -> None:
        self.append(ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, value)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)


def aws_facts(resource: NormalizedResource) -> AwsResourceFacts:
    return AwsResourceFacts(resource)