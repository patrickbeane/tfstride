from __future__ import annotations

from typing import TYPE_CHECKING

from tfstride.providers.aws.limitations import AWS_LIMITATIONS
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_capabilities import AWS_RESOURCE_CAPABILITIES
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_fact_domains
from tfstride.providers.plugin import ProviderPlugin

if TYPE_CHECKING:
    from tfstride.analysis.boundaries.types import BoundaryContributor
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.rule_definitions import RuleContribution


def _aws_boundary_contributor() -> BoundaryContributor:
    from tfstride.providers.aws.boundaries import AwsBoundaryContributor

    return AwsBoundaryContributor()


def _aws_rule_contribution(finding_factory: FindingFactory) -> RuleContribution:
    from tfstride.providers.aws.rules import build_aws_rule_contribution

    return build_aws_rule_contribution(finding_factory)


def aws_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="aws",
        normalizer_factory=AwsNormalizer,
        resource_facts_factory=aws_fact_domains,
        metadata_namespace=AwsResourceMetadata,
        supported_resource_types=frozenset(SUPPORTED_AWS_TYPES),
        resource_capabilities=AWS_RESOURCE_CAPABILITIES,
        limitations=AWS_LIMITATIONS,
        resource_decorator_factory=AwsResourceDecorator,
        rule_contribution_factory=_aws_rule_contribution,
        boundary_contributor_factory=_aws_boundary_contributor,
    )
