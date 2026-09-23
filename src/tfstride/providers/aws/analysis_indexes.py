from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.models import NormalizedResource, ResourceInventory
from tfstride.providers.aws.account_identity import AwsAccountIdentityIndex
from tfstride.providers.aws.resource_index import (
    AwsReferenceRelationshipKey,
    AwsResourceIndex,
    AwsResourceIndexBuilder,
    aws_reference_relationship_key,
)


@dataclass(frozen=True, slots=True)
class AwsSecurityGroupRelationships:
    resource_index: AwsResourceIndex
    resources_by_security_group: Mapping[AwsReferenceRelationshipKey, tuple[NormalizedResource, ...]]
    public_resources_by_security_group: Mapping[AwsReferenceRelationshipKey, tuple[NormalizedResource, ...]]

    def reference_key(
        self,
        reference: str | None,
        *,
        source: NormalizedResource,
    ) -> AwsReferenceRelationshipKey | None:
        return aws_reference_relationship_key(
            self.resource_index.security_groups,
            reference,
            source=source,
        )

    def attached_security_groups(self, resource: NormalizedResource) -> tuple[NormalizedResource, ...]:
        groups: list[NormalizedResource] = []
        seen_addresses: set[str] = set()
        for reference in resource.security_group_ids:
            security_group = self.resource_index.security_groups.get(
                reference,
                source=resource,
            )
            if security_group is None or security_group.address in seen_addresses:
                continue
            seen_addresses.add(security_group.address)
            groups.append(security_group)
        return tuple(groups)

    def resources_attached_to(
        self,
        reference: str | None,
        *,
        source: NormalizedResource,
        public_only: bool = False,
    ) -> tuple[NormalizedResource, ...]:
        key = self.reference_key(reference, source=source)
        if key is None:
            return ()
        groups = self.public_resources_by_security_group if public_only else self.resources_by_security_group
        return groups.get(key, ())


@dataclass(frozen=True, slots=True)
class AwsAnalysisIndexes:
    security_group_relationships: AwsSecurityGroupRelationships

    @property
    def account_identities(self) -> AwsAccountIdentityIndex:
        return self.security_group_relationships.resource_index.account_identities


def build_aws_analysis_indexes(inventory: ResourceInventory) -> AwsAnalysisIndexes:
    resource_index = AwsResourceIndexBuilder().build(list(inventory.resources))
    resources_by_security_group: dict[AwsReferenceRelationshipKey, dict[str, NormalizedResource]] = {}
    public_resources_by_security_group: dict[AwsReferenceRelationshipKey, dict[str, NormalizedResource]] = {}

    for resource in inventory.resources:
        for reference in resource.security_group_ids:
            key = aws_reference_relationship_key(
                resource_index.security_groups,
                reference,
                source=resource,
            )
            if key is None:
                continue
            resources_by_security_group.setdefault(key, {}).setdefault(resource.address, resource)
            if resource.public_exposure:
                public_resources_by_security_group.setdefault(key, {}).setdefault(resource.address, resource)

    return AwsAnalysisIndexes(
        security_group_relationships=AwsSecurityGroupRelationships(
            resource_index=resource_index,
            resources_by_security_group=_freeze_resource_groups(resources_by_security_group),
            public_resources_by_security_group=_freeze_resource_groups(public_resources_by_security_group),
        )
    )


def aws_analysis_indexes(
    indexes: AnalysisIndexes,
    inventory: ResourceInventory,
) -> AwsAnalysisIndexes:
    if indexes.provider_extension is None:
        return build_aws_analysis_indexes(inventory)
    return indexes.require_provider_extension(AwsAnalysisIndexes)


def _freeze_resource_groups(
    groups: dict[AwsReferenceRelationshipKey, dict[str, NormalizedResource]],
) -> Mapping[AwsReferenceRelationshipKey, tuple[NormalizedResource, ...]]:
    return MappingProxyType(
        {
            key: tuple(sorted(resources.values(), key=lambda resource: resource.address))
            for key, resources in groups.items()
        }
    )
