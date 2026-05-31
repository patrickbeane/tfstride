from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.analysis.policy_conditions import (
    PrincipalAssessment,
    federated_provider_description,
    policy_statement_principal_assessments,
    trust_statement_principal_assessments,
)
from tfstride.analysis.resource_concepts import (
    DATA_STORE_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    WORKLOAD_RESOURCE_TYPES,
    is_database_resource,
    is_identity_role_resource,
    is_object_storage_resource,
    is_public_edge_resource,
    is_secret_store_resource,
)
from tfstride.models import BoundaryType, NormalizedResource, ResourceInventory, TrustBoundary
from tfstride.resource_metadata import ResourceMetadata


@dataclass(frozen=True, slots=True)
class _DataStoreCandidateIndex:
    data_store_positions: Mapping[int, int]
    object_storage: tuple[NormalizedResource, ...]
    secret_stores: tuple[NormalizedResource, ...]
    direct_internet_databases: tuple[NormalizedResource, ...]
    databases_by_vpc: Mapping[str, tuple[NormalizedResource, ...]]
    databases_missing_security_groups_by_vpc: Mapping[str, tuple[NormalizedResource, ...]]
    databases_by_trusted_workload_security_group: Mapping[str, tuple[NormalizedResource, ...]]


def detect_trust_boundaries(
    inventory: ResourceInventory,
    indexes: AnalysisIndexes | None = None,
) -> list[TrustBoundary]:
    boundaries: list[TrustBoundary] = []
    seen: set[tuple[str, str, str]] = set()

    def add_boundary(
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
    ) -> None:
        # Multiple heuristics can arrive at the same crossing; dedupe by logical edge so
        # the report stays readable and stable across rule changes.
        key = (boundary_type.value, source, target)
        if key in seen:
            return
        seen.add(key)
        boundaries.append(
            TrustBoundary(
                identifier=f"{boundary_type.value}:{source}->{target}",
                boundary_type=boundary_type,
                source=source,
                target=target,
                description=description,
                rationale=rationale,
            )
        )

    resources = inventory.resources
    analysis_indexes = indexes if indexes is not None else build_analysis_indexes(inventory)

    for resource in resources:
        if resource.direct_internet_reachable and is_public_edge_resource(resource):
            add_boundary(
                BoundaryType.INTERNET_TO_SERVICE,
                "internet",
                resource.address,
                f"Traffic can cross from the public internet to {resource.display_name}.",
                "The resource is directly reachable or intentionally exposed to unauthenticated network clients.",
            )

    public_subnets = [
        resource
        for resource in resources
        if resource.resource_type == "aws_subnet" and resource.is_public_subnet
    ]
    private_subnets_by_vpc = _private_subnets_by_vpc(resources)
    for public_subnet in public_subnets:
        if not public_subnet.vpc_id:
            continue
        for private_subnet in private_subnets_by_vpc.get(public_subnet.vpc_id, ()):
            # Model segmentation at the trust-zone level rather than every possible route;
            # for review purposes, "public subnet can reach private subnet" is the key edge.
            add_boundary(
                BoundaryType.PUBLIC_TO_PRIVATE,
                public_subnet.address,
                private_subnet.address,
                f"Traffic can move from {public_subnet.display_name} toward {private_subnet.display_name}.",
                "The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.",
            )

    workloads = inventory.by_type(*WORKLOAD_RESOURCE_TYPES)
    data_store_candidates = _build_data_store_candidate_index(
        inventory.by_type(*DATA_STORE_RESOURCE_TYPES),
        analysis_indexes,
    )
    for workload in workloads:
        attached_role = resolve_workload_role(workload, analysis_indexes.role_index)
        for data_store in _candidate_data_stores_for_workload(
            workload,
            attached_role,
            data_store_candidates,
        ):
            reachability_rationale = _workload_reaches_data_store(
                workload,
                data_store,
                attached_role,
                analysis_indexes,
            )
            if reachability_rationale:
                add_boundary(
                    BoundaryType.WORKLOAD_TO_DATA_STORE,
                    workload.address,
                    data_store.address,
                    f"{workload.display_name} can interact with {data_store.display_name}.",
                    reachability_rationale,
                )
        if attached_role is not None:
            add_boundary(
                BoundaryType.CONTROL_TO_WORKLOAD,
                attached_role.address,
                workload.address,
                f"{attached_role.display_name} governs actions performed by {workload.display_name}.",
                "IAM configuration acts as a control-plane boundary because the workload inherits whatever privileges the role carries.",
            )

    primary_account_id = inventory.primary_account_id
    for role in inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
        seen_role_principals: set[tuple[str, str]] = set()
        for trust_statement in role.get_metadata_field(ResourceMetadata.TRUST_STATEMENTS):
            for assessment in trust_statement_principal_assessments(trust_statement, primary_account_id):
                principal_key = (assessment.principal_kind, assessment.principal)
                if principal_key in seen_role_principals:
                    continue
                seen_role_principals.add(principal_key)
                if assessment.is_service:
                    continue
                add_boundary(
                    BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                    assessment.principal,
                    role.address,
                    _role_trust_description(role, assessment),
                    _role_trust_rationale(assessment),
                )

    for resource in resources:
        if is_identity_role_resource(resource):
            continue
        for assessment in _resource_policy_principals(resource, primary_account_id):
            principal = assessment.principal
            if assessment.is_service:
                continue
            if assessment.is_wildcard:
                description = f"{resource.display_name} allows any principal through a resource policy."
            else:
                description = f"{resource.display_name} allows {principal} through a resource policy."
            if assessment.is_wildcard or assessment.is_foreign_account:
                rationale = "A broad or foreign AWS principal can cross into this resource's policy boundary."
            else:
                rationale = "An additional account-level principal can cross into this resource's policy boundary."
            add_boundary(
                BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                principal,
                resource.address,
                description,
                rationale,
            )

    return boundaries


def _private_subnets_by_vpc(resources: Sequence[NormalizedResource]) -> dict[str, tuple[NormalizedResource, ...]]:
    grouped: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != "aws_subnet" or resource.is_public_subnet or not resource.vpc_id:
            continue
        grouped.setdefault(resource.vpc_id, []).append(resource)
    return {vpc_id: tuple(subnets) for vpc_id, subnets in grouped.items()}


def _build_data_store_candidate_index(
    data_stores: Sequence[NormalizedResource],
    indexes: AnalysisIndexes,
) -> _DataStoreCandidateIndex:
    direct_internet_databases: list[NormalizedResource] = []
    object_storage: list[NormalizedResource] = []
    secret_stores: list[NormalizedResource] = []
    databases_by_vpc: dict[str, list[NormalizedResource]] = {}
    databases_missing_security_groups_by_vpc: dict[str, list[NormalizedResource]] = {}
    databases_by_trusted_workload_security_group: dict[str, list[NormalizedResource]] = {}

    for data_store in data_stores:
        if is_database_resource(data_store):
            if data_store.direct_internet_reachable:
                direct_internet_databases.append(data_store)
            if data_store.vpc_id:
                databases_by_vpc.setdefault(data_store.vpc_id, []).append(data_store)
                if not data_store.security_group_ids:
                    databases_missing_security_groups_by_vpc.setdefault(
                        data_store.vpc_id,
                        [],
                    ).append(data_store)
            for trusted_group_id in _trusted_workload_security_group_ids(data_store, indexes):
                databases_by_trusted_workload_security_group.setdefault(
                    trusted_group_id,
                    [],
                ).append(data_store)
        elif is_object_storage_resource(data_store):
            object_storage.append(data_store)
        elif is_secret_store_resource(data_store):
            secret_stores.append(data_store)

    return _DataStoreCandidateIndex(
        data_store_positions={id(resource): index for index, resource in enumerate(data_stores)},
        object_storage=tuple(object_storage),
        secret_stores=tuple(secret_stores),
        direct_internet_databases=tuple(direct_internet_databases),
        databases_by_vpc=_freeze_resource_groups_by_key(databases_by_vpc),
        databases_missing_security_groups_by_vpc=_freeze_resource_groups_by_key(
            databases_missing_security_groups_by_vpc
        ),
        databases_by_trusted_workload_security_group=_freeze_resource_groups_by_key(
            databases_by_trusted_workload_security_group
        ),
    )


def _candidate_data_stores_for_workload(
    workload: NormalizedResource,
    attached_role: NormalizedResource | None,
    index: _DataStoreCandidateIndex,
) -> tuple[NormalizedResource, ...]:
    candidates: dict[int, NormalizedResource] = {}

    def add_many(data_stores: Sequence[NormalizedResource]) -> None:
        for data_store in data_stores:
            candidates.setdefault(id(data_store), data_store)

    for security_group_id in workload.security_group_ids:
        add_many(index.databases_by_trusted_workload_security_group.get(security_group_id, ()))
    if _workload_has_general_egress_path(workload):
        add_many(index.direct_internet_databases)
    if workload.vpc_id:
        if workload.security_group_ids:
            add_many(index.databases_missing_security_groups_by_vpc.get(workload.vpc_id, ()))
        else:
            add_many(index.databases_by_vpc.get(workload.vpc_id, ()))
    if attached_role is not None:
        if _role_allows_object_storage_access(attached_role):
            add_many(index.object_storage)
        if _role_allows_secret_read(attached_role):
            add_many(index.secret_stores)

    return tuple(
        sorted(
            candidates.values(),
            key=lambda resource: index.data_store_positions[id(resource)],
        )
    )


def _trusted_workload_security_group_ids(
    data_store: NormalizedResource,
    indexes: AnalysisIndexes,
) -> set[str]:
    trusted_group_ids: set[str] = set()
    for security_group_id in data_store.security_group_ids:
        security_group = indexes.security_groups_by_reference.get(security_group_id)
        if security_group is None:
            continue
        for rule in security_group.network_rules:
            if rule.direction == "ingress":
                trusted_group_ids.update(rule.referenced_security_group_ids)
    return trusted_group_ids


def _freeze_resource_groups_by_key(
    grouped: dict[str, list[NormalizedResource]],
) -> Mapping[str, tuple[NormalizedResource, ...]]:
    return {key: tuple(resources) for key, resources in grouped.items()}


def _role_allows_object_storage_access(role: NormalizedResource) -> bool:
    return any(
        statement.effect == "Allow"
        and any(action == "*" or action.startswith("s3:") for action in statement.actions)
        for statement in role.policy_statements
    )


def _role_allows_secret_read(role: NormalizedResource) -> bool:
    return any(
        statement.effect == "Allow"
        and any(_allows_secret_read(action) for action in statement.actions)
        for statement in role.policy_statements
    )


def _workload_reaches_data_store(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    attached_role: NormalizedResource | None,
    indexes: AnalysisIndexes,
) -> str | None:
    if is_database_resource(data_store):
        return _database_reachability_rationale(workload, data_store, indexes)
    if is_object_storage_resource(data_store):
        if attached_role is None:
            return None
        allowed_actions = sorted(
            {
                action
                for statement in attached_role.policy_statements
                if statement.effect == "Allow"
                for action in statement.actions
                if action == "*" or action.startswith("s3:")
            }
        )
        if not allowed_actions:
            return None
        action_text = ", ".join(allowed_actions)
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when their "
            f"attached role allows S3 actions such as {action_text}."
        )
    if is_secret_store_resource(data_store):
        if attached_role is None:
            return None
        allowed_actions = sorted(
            {
                action
                for statement in attached_role.policy_statements
                if statement.effect == "Allow"
                for action in statement.actions
                if _allows_secret_read(action)
            }
        )
        if not allowed_actions:
            return None
        action_text = ", ".join(allowed_actions)
        return (
            "Application or function workloads cross into a higher-sensitivity secret plane when their "
            f"attached role allows Secrets Manager retrieval actions such as {action_text}."
        )
    return None


def _database_reachability_rationale(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    indexes: AnalysisIndexes,
) -> str | None:
    if workload.vpc_id and data_store.vpc_id and workload.vpc_id != data_store.vpc_id:
        if not data_store.direct_internet_reachable:
            return None

    if _database_allows_workload_security_group(workload, data_store, indexes):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "database ingress security groups explicitly trust the workload security group."
        )

    if data_store.direct_internet_reachable and _workload_has_general_egress_path(workload):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "a directly internet-reachable database is reachable from a workload subnet with general egress."
        )

    if (not workload.security_group_ids or not data_store.security_group_ids) and (
        workload.vpc_id and data_store.vpc_id and workload.vpc_id == data_store.vpc_id
    ):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "they share a VPC with the database and the plan does not provide tighter security-group evidence."
        )
    return None


def _database_allows_workload_security_group(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    indexes: AnalysisIndexes,
) -> bool:
    if not workload.security_group_ids or not data_store.security_group_ids:
        return False
    workload_group_ids = set(workload.security_group_ids)
    for security_group_id in data_store.security_group_ids:
        security_group = indexes.security_groups_by_reference.get(security_group_id)
        if security_group is None:
            continue
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            if workload_group_ids.intersection(rule.referenced_security_group_ids):
                return True
    return False


def _workload_has_general_egress_path(workload: NormalizedResource) -> bool:
    if workload.resource_type == "aws_lambda_function" and not workload.vpc_enabled:
        return True
    return workload.in_public_subnet or workload.has_nat_gateway_egress


def _resource_policy_principals(
    resource: NormalizedResource,
    primary_account_id: str | None,
) -> list[PrincipalAssessment]:
    principals: list[PrincipalAssessment] = []
    seen_principals: set[str] = set()
    for statement in resource.policy_statements:
        if statement.effect != "Allow":
            continue
        for assessment in policy_statement_principal_assessments(statement, primary_account_id):
            if assessment.is_service:
                continue
            if is_object_storage_resource(resource) and assessment.is_wildcard:
                continue
            if assessment.scope_description is None:
                continue
            if assessment.principal in seen_principals:
                continue
            seen_principals.add(assessment.principal)
            principals.append(assessment)
    return principals


def _role_trust_description(role: NormalizedResource, assessment: PrincipalAssessment) -> str:
    if assessment.is_wildcard:
        return f"{role.display_name} trusts any principal."
    if assessment.is_federated:
        return (
            f"{role.display_name} trusts {assessment.principal} as a "
            f"{federated_provider_description(assessment.federated_provider_type)}."
        )
    return f"{role.display_name} trusts {assessment.principal}."


def _role_trust_rationale(assessment: PrincipalAssessment) -> str:
    if assessment.is_federated:
        if assessment.is_foreign_account:
            return "A foreign federated identity provider can cross into this role's trust boundary."
        return "A federated identity provider can cross into this role's trust boundary."
    if assessment.is_foreign_account:
        return "A foreign AWS account can cross into this role's trust boundary."
    return "An additional role or principal can cross into this role's trust boundary."


def _allows_secret_read(action: str) -> bool:
    return action == "*" or action == "secretsmanager:*" or action.startswith("secretsmanager:GetSecretValue")