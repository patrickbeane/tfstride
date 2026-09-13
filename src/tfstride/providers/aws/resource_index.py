from __future__ import annotations

from dataclasses import dataclass, field

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_utils import (
    ecs_task_definition_identifier,
    route_table_has_internet_route,
)
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    ResourceReferenceResolution,
    build_resource_reference_index,
)

_AWS_ADDRESS_REFERENCE_SUFFIXES_BY_RESOURCE_TYPE: dict[str, tuple[str, ...]] = {
    "aws_secretsmanager_secret": ("id", "arn"),
    "aws_sns_topic": ("id", "arn"),
    "aws_sqs_queue": ("id", "arn", "url"),
    "aws_dynamodb_table": ("id", "arn"),
    "aws_kms_key": ("id", "key_id", "arn"),
    "aws_lb": ("id", "arn"),
    "aws_lb_listener": ("id", "arn"),
    "aws_lb_target_group": ("id", "arn", "name"),
    "aws_iam_openid_connect_provider": ("arn",),
}


@dataclass(frozen=True, slots=True)
class AwsResourceReferenceView:
    """Resolve one AWS resource type without discarding ambiguous aliases."""

    _index: ResourceReferenceIndex
    _resources_by_address: dict[str, NormalizedResource]
    _resource_types: frozenset[str]
    resources: tuple[NormalizedResource, ...]

    def resolve(
        self,
        reference: str | None,
        *,
        source: NormalizedResource | None = None,
    ) -> ResourceReferenceResolution:
        """Resolve exact and strong identities before provider-scoped weak aliases."""

        if reference:
            exact = self._resources_by_address.get(reference)
            if exact is not None:
                if exact.resource_type in self._resource_types:
                    return ResourceReferenceResolution(candidates=(exact,))
                return ResourceReferenceResolution(candidates=())

        resolution = self._index.resolve(
            reference,
            candidate_filter=lambda candidate: candidate.resource_type in self._resource_types,
        )
        strong_candidates = tuple(
            candidate
            for candidate in resolution.candidates
            if reference is not None and _aws_reference_is_strong_for_candidate(reference, candidate)
        )
        candidates = strong_candidates or resolution.candidates

        provider_config_key = source.provider_config_key if source is not None else None
        if provider_config_key is None:
            return ResourceReferenceResolution(candidates=candidates)

        scoped_candidates = tuple(
            candidate for candidate in candidates if candidate.provider_config_key == provider_config_key
        )
        if scoped_candidates:
            return ResourceReferenceResolution(candidates=scoped_candidates)
        if strong_candidates:
            return ResourceReferenceResolution(candidates=strong_candidates)
        return ResourceReferenceResolution(candidates=())

    def get(
        self,
        reference: str | None,
        default: NormalizedResource | None = None,
        *,
        source: NormalizedResource | None = None,
    ) -> NormalizedResource | None:
        selected = self.resolve(reference, source=source).selected_candidate
        return selected if selected is not None else default


@dataclass(slots=True)
class AwsResourceIndex:
    subnets: AwsResourceReferenceView
    security_groups: AwsResourceReferenceView
    route_tables: AwsResourceReferenceView
    buckets: AwsResourceReferenceView
    secrets: AwsResourceReferenceView
    sns_topics: AwsResourceReferenceView
    sqs_queues: AwsResourceReferenceView
    dynamodb_tables: AwsResourceReferenceView
    kms_keys: AwsResourceReferenceView
    lambda_functions: AwsResourceReferenceView
    ecs_clusters: AwsResourceReferenceView
    ecs_task_definitions: AwsResourceReferenceView
    ecr_repositories: AwsResourceReferenceView
    load_balancers: AwsResourceReferenceView
    load_balancer_listeners: AwsResourceReferenceView
    load_balancer_listener_rules: tuple[NormalizedResource, ...]
    load_balancer_target_groups: AwsResourceReferenceView
    role_index: AwsResourceReferenceView
    instance_profile_index: AwsResourceReferenceView
    policy_index: AwsResourceReferenceView
    oidc_provider_index: AwsResourceReferenceView
    api_gateway_rest_apis: AwsResourceReferenceView
    apigatewayv2_apis: AwsResourceReferenceView
    vpcs_with_igw: set[str]
    vpcs_with_public_routes: set[str]
    nat_gateway_ids: set[str]
    resources_by_address: dict[str, NormalizedResource]


@dataclass(slots=True)
class AwsDecorationContext:
    index: AwsResourceIndex
    public_subnet_ids: set[str] = field(default_factory=set)


class AwsResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> AwsResourceIndex:
        resource_tuple = tuple(resources)
        resources_by_address: dict[str, NormalizedResource] = {}
        resources_by_type: dict[str, list[NormalizedResource]] = {}
        vpcs_with_igw: set[str] = set()
        vpcs_with_public_routes: set[str] = set()
        nat_gateway_ids: set[str] = set()

        for resource in resource_tuple:
            resources_by_address.setdefault(resource.address, resource)
            resources_by_type.setdefault(resource.resource_type, []).append(resource)
            facts = aws_facts(resource)
            if resource.resource_type == "aws_route_table":
                if resource.vpc_id and route_table_has_internet_route(facts.routes):
                    vpcs_with_public_routes.add(resource.vpc_id)
            elif resource.resource_type == "aws_internet_gateway":
                if resource.vpc_id:
                    vpcs_with_igw.add(resource.vpc_id)
            elif resource.resource_type == "aws_nat_gateway":
                if resource.identifier:
                    nat_gateway_ids.add(resource.identifier)

        reference_index = build_resource_reference_index(
            resource_tuple,
            references_for_resource=_aws_resource_references,
        )

        def view(resource_type: str) -> AwsResourceReferenceView:
            return AwsResourceReferenceView(
                _index=reference_index,
                _resources_by_address=resources_by_address,
                _resource_types=frozenset({resource_type}),
                resources=tuple(resources_by_type.get(resource_type, ())),
            )

        return AwsResourceIndex(
            subnets=view("aws_subnet"),
            security_groups=view("aws_security_group"),
            route_tables=view("aws_route_table"),
            buckets=view("aws_s3_bucket"),
            secrets=view("aws_secretsmanager_secret"),
            sns_topics=view("aws_sns_topic"),
            sqs_queues=view("aws_sqs_queue"),
            dynamodb_tables=view("aws_dynamodb_table"),
            kms_keys=view("aws_kms_key"),
            lambda_functions=view("aws_lambda_function"),
            ecs_clusters=view("aws_ecs_cluster"),
            ecs_task_definitions=view("aws_ecs_task_definition"),
            ecr_repositories=view("aws_ecr_repository"),
            load_balancers=view("aws_lb"),
            load_balancer_listeners=view("aws_lb_listener"),
            load_balancer_listener_rules=tuple(resources_by_type.get("aws_lb_listener_rule", ())),
            load_balancer_target_groups=view("aws_lb_target_group"),
            role_index=view("aws_iam_role"),
            instance_profile_index=view("aws_iam_instance_profile"),
            policy_index=view("aws_iam_policy"),
            oidc_provider_index=view("aws_iam_openid_connect_provider"),
            api_gateway_rest_apis=view("aws_api_gateway_rest_api"),
            apigatewayv2_apis=view("aws_apigatewayv2_api"),
            vpcs_with_igw=vpcs_with_igw,
            vpcs_with_public_routes=vpcs_with_public_routes,
            nat_gateway_ids=nat_gateway_ids,
            resources_by_address=resources_by_address,
        )


def _aws_resource_references(resource: NormalizedResource) -> tuple[str | None, ...]:
    facts = aws_facts(resource)
    resource_type = resource.resource_type
    address = resource.address
    address_aliases = _aws_address_reference_aliases(resource)

    if resource_type in {"aws_subnet", "aws_security_group", "aws_route_table"}:
        aliases = (resource.identifier,)
    elif resource_type == "aws_s3_bucket":
        aliases = (resource.identifier, resource.arn)
    elif resource_type == "aws_secretsmanager_secret":
        aliases = (
            resource.identifier,
            *address_aliases,
            resource.arn,
            facts.name,
        )
    elif resource_type == "aws_sns_topic":
        aliases = (
            *address_aliases,
            resource.arn,
        )
    elif resource_type == "aws_sqs_queue":
        aliases = (
            *address_aliases,
            resource.arn,
            facts.sqs_queue_url,
        )
    elif resource_type == "aws_dynamodb_table":
        aliases = (
            *address_aliases,
            resource.identifier,
            resource.arn,
            facts.dynamodb_table_arn,
        )
    elif resource_type == "aws_kms_key":
        aliases = (
            resource.identifier,
            *address_aliases,
            resource.arn,
            facts.kms_key_id,
        )
    elif resource_type == "aws_lambda_function":
        aliases = (resource.identifier, resource.arn)
    elif resource_type == "aws_ecs_cluster":
        aliases = (resource.identifier, resource.arn, facts.name)
    elif resource_type == "aws_ecs_task_definition":
        aliases = (
            resource.identifier,
            resource.arn,
            facts.task_definition_family,
            ecs_task_definition_identifier(
                facts.task_definition_family,
                facts.task_definition_revision,
            ),
        )
    elif resource_type == "aws_ecr_repository":
        aliases = (
            facts.ecr_repository_url,
            resource.identifier,
            resource.arn,
        )
    elif resource_type == "aws_lb":
        aliases = (
            resource.identifier,
            *address_aliases,
            resource.arn,
            resource.name,
        )
    elif resource_type == "aws_lb_listener":
        aliases = (
            resource.identifier,
            *address_aliases,
            resource.arn,
        )
    elif resource_type == "aws_lb_target_group":
        aliases = (
            resource.identifier,
            *address_aliases,
            resource.arn,
            resource.name,
            facts.name,
        )
    elif resource_type in {
        "aws_iam_role",
        "aws_iam_instance_profile",
        "aws_iam_policy",
    }:
        aliases = (resource.identifier, resource.arn)
    elif resource_type == "aws_iam_openid_connect_provider":
        aliases = (
            resource.arn,
            facts.oidc_provider_arn,
            *address_aliases,
        )
    elif resource_type in {"aws_api_gateway_rest_api", "aws_apigatewayv2_api"}:
        aliases = (facts.api_gateway_api_id,)
    else:
        aliases = ()

    return (address, *aliases)


def _aws_address_reference_aliases(
    resource: NormalizedResource,
) -> tuple[str, ...]:
    return tuple(
        f"{resource.address}.{suffix}"
        for suffix in _AWS_ADDRESS_REFERENCE_SUFFIXES_BY_RESOURCE_TYPE.get(
            resource.resource_type,
            (),
        )
    )


def _aws_reference_is_strong_for_candidate(
    reference: str,
    candidate: NormalizedResource,
) -> bool:
    """Return whether the reference identifies the candidate outside provider scope."""

    if reference == candidate.address or reference in _aws_address_reference_aliases(candidate):
        return True

    facts = aws_facts(candidate)
    strong_native_references = {
        candidate.arn,
        facts.dynamodb_table_arn,
        facts.ecr_repository_url,
        facts.oidc_provider_arn,
        facts.sqs_queue_url,
    }
    if facts.kms_key_id and facts.kms_key_id.startswith("arn:"):
        strong_native_references.add(facts.kms_key_id)
    return reference in strong_native_references
