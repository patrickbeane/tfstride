from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts


class AwsIamFacts(AwsBaseFacts):
    __slots__ = ()

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
    def unresolved_attached_policy_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.UNRESOLVED_ATTACHED_POLICY_ARNS)

    @property
    def attached_policy_arns(self) -> list[str]:
        return self.get(AwsResourceMetadata.ATTACHED_POLICY_ARNS)

    @property
    def attached_policy_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.ATTACHED_POLICY_ADDRESSES)

    @property
    def inline_policy_resource_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.INLINE_POLICY_RESOURCE_ADDRESSES)

    @property
    def inline_policy_names(self) -> list[str]:
        return self.get(AwsResourceMetadata.INLINE_POLICY_NAMES)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self.get(AwsResourceMetadata.TRUST_STATEMENTS)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.get(AwsResourceMetadata.POLICY_DOCUMENT)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.get(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)

    def set_resolved_role_references(self, values: list[str]) -> None:
        self.set(AwsResourceMetadata.RESOLVED_ROLE_REFERENCES, values)

    def set_trust_statements(self, values: list[dict[str, Any]]) -> None:
        self.set(AwsResourceMetadata.TRUST_STATEMENTS, values)

    def set_policy_document(self, value: dict[str, Any] | None) -> None:
        self.set(AwsResourceMetadata.POLICY_DOCUMENT, value)

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

    def add_resource_policy_source_address(self, value: str | None) -> None:
        self.append(AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES, value)
