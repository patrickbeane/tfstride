from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts.audit import AwsAuditFacts
from tfstride.providers.aws.resource_facts.compute import AwsComputeFacts
from tfstride.providers.aws.resource_facts.data import AwsDataFacts
from tfstride.providers.aws.resource_facts.ecr import AwsEcrFacts
from tfstride.providers.aws.resource_facts.edge import AwsEdgeFacts
from tfstride.providers.aws.resource_facts.iam import AwsIamFacts
from tfstride.providers.aws.resource_facts.identity import AwsIdentityFacts
from tfstride.providers.aws.resource_facts.messaging import AwsMessagingFacts
from tfstride.providers.aws.resource_facts.network import AwsNetworkFacts
from tfstride.providers.aws.resource_facts.storage import AwsStorageFacts


class AwsResourceFacts(
    AwsStorageFacts,
    AwsIamFacts,
    AwsIdentityFacts,
    AwsNetworkFacts,
    AwsComputeFacts,
    AwsEdgeFacts,
    AwsDataFacts,
    AwsEcrFacts,
    AwsMessagingFacts,
    AwsAuditFacts,
):
    __slots__ = ()


def aws_facts(resource: NormalizedResource) -> AwsResourceFacts:
    return AwsResourceFacts(resource)


__all__ = ["AwsResourceFacts", "aws_facts"]
