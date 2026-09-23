from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.analysis.boundaries.shared import contribute_control_to_workload_boundary
from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.resource_concepts import (
    DATA_STORE_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    WORKLOAD_RESOURCE_TYPES,
    has_provider_managed_egress_without_vpc,
    is_database_resource,
    is_identity_role_resource,
    is_object_storage_resource,
    is_secret_store_resource,
)
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.models import BoundaryType, NormalizedResource
from tfstride.providers.aws.account_identity_evidence import AwsAccountResolution
from tfstride.providers.aws.analysis_indexes import (
    AwsSecurityGroupRelationships,
    aws_analysis_indexes,
)
from tfstride.providers.aws.policy_conditions import (
    PrincipalAssessment,
    federated_provider_description,
    policy_statement_principal_assessments,
    trust_statement_principal_assessments,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsReferenceRelationshipKey
from tfstride.providers.aws.resource_utils import AwsScopedReferenceKey, aws_scoped_reference_key

_Key = TypeVar("_Key")


@dataclass(frozen=True, slots=True)
class _AwsDataStoreCandidateIndex:
    data_store_positions: Mapping[int, int]
    object_storage: tuple[NormalizedResource, ...]
    secret_stores: tuple[NormalizedResource, ...]
    databases: tuple[NormalizedResource, ...]
    direct_internet_databases: tuple[NormalizedResource, ...]
    databases_by_vpc: Mapping[AwsScopedReferenceKey, tuple[NormalizedResource, ...]]
    databases_missing_security_groups_by_vpc: Mapping[AwsScopedReferenceKey, tuple[NormalizedResource, ...]]
    databases_by_trusted_workload_security_group: Mapping[
        AwsReferenceRelationshipKey,
        tuple[NormalizedResource, ...],
    ]


class AwsBoundaryContributor:
    def contribute(self, context: BoundaryContributionContext) -> None:
        if context.inventory.provider != "aws":
            return

        inventory = context.inventory
        resources = inventory.resources
        indexes = context.indexes
        security_group_relationships = aws_analysis_indexes(indexes, inventory).security_group_relationships

        data_store_candidates = _build_data_store_candidate_index(
            resources,
            security_group_relationships,
        )
        for workload in inventory.by_type(*WORKLOAD_RESOURCE_TYPES):
            attached_role = resolve_workload_role(workload, indexes.role_index)
            for data_store in _candidate_data_stores_for_workload(
                workload,
                attached_role,
                data_store_candidates,
                security_group_relationships,
            ):
                reachability_rationale = _workload_reaches_data_store(
                    workload,
                    data_store,
                    attached_role,
                    security_group_relationships,
                )
                if reachability_rationale:
                    context.add_boundary(
                        BoundaryType.WORKLOAD_TO_DATA_STORE,
                        workload.address,
                        data_store.address,
                        f"{workload.display_name} can interact with {data_store.display_name}.",
                        reachability_rationale,
                    )
            contribute_control_to_workload_boundary(context, workload, attached_role)

        account_identities = security_group_relationships.resource_index.account_identities
        for role in inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
            target_account = account_identities.resolve(role)
            seen_role_principals: set[tuple[str, str]] = set()
            for trust_statement in aws_facts(role).trust_statements:
                for assessment in trust_statement_principal_assessments(
                    trust_statement,
                    target_account.account_id,
                    target_partition=target_account.partition,
                ):
                    principal_key = (assessment.principal_kind, assessment.principal)
                    if principal_key in seen_role_principals:
                        continue
                    seen_role_principals.add(principal_key)
                    if assessment.is_service:
                        continue
                    context.add_boundary(
                        BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                        assessment.principal,
                        role.address,
                        _role_trust_description(role, assessment),
                        _role_trust_rationale(assessment),
                    )

        for resource in resources:
            if is_identity_role_resource(resource):
                continue
            for assessment in _resource_policy_principals(resource, account_identities.resolve(resource)):
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
                context.add_boundary(
                    BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                    principal,
                    resource.address,
                    description,
                    rationale,
                )


def _build_data_store_candidate_index(
    resources: Sequence[NormalizedResource],
    security_group_relationships: AwsSecurityGroupRelationships,
) -> _AwsDataStoreCandidateIndex:
    data_stores = [resource for resource in resources if resource.resource_type in DATA_STORE_RESOURCE_TYPES]
    direct_internet_databases: list[NormalizedResource] = []
    databases: list[NormalizedResource] = []
    object_storage: list[NormalizedResource] = []
    secret_stores: list[NormalizedResource] = []
    databases_by_vpc: dict[AwsScopedReferenceKey, list[NormalizedResource]] = {}
    databases_missing_security_groups_by_vpc: dict[AwsScopedReferenceKey, list[NormalizedResource]] = {}
    databases_by_trusted_workload_security_group: dict[
        AwsReferenceRelationshipKey,
        list[NormalizedResource],
    ] = {}

    for data_store in data_stores:
        if is_database_resource(data_store):
            databases.append(data_store)
            if data_store.direct_internet_reachable:
                direct_internet_databases.append(data_store)
            scoped_vpc_key = aws_scoped_reference_key(
                data_store.provider_config_key,
                data_store.vpc_id,
            )
            if scoped_vpc_key is not None:
                databases_by_vpc.setdefault(scoped_vpc_key, []).append(data_store)
                if not data_store.security_group_ids:
                    databases_missing_security_groups_by_vpc.setdefault(
                        scoped_vpc_key,
                        [],
                    ).append(data_store)
            for trusted_group_key in _trusted_workload_security_group_keys(
                data_store,
                security_group_relationships,
            ):
                databases_by_trusted_workload_security_group.setdefault(
                    trusted_group_key,
                    [],
                ).append(data_store)
        elif is_object_storage_resource(data_store):
            object_storage.append(data_store)
        elif is_secret_store_resource(data_store):
            secret_stores.append(data_store)

    return _AwsDataStoreCandidateIndex(
        data_store_positions={id(resource): index for index, resource in enumerate(data_stores)},
        object_storage=tuple(object_storage),
        secret_stores=tuple(secret_stores),
        databases=tuple(databases),
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
    index: _AwsDataStoreCandidateIndex,
    security_group_relationships: AwsSecurityGroupRelationships,
) -> tuple[NormalizedResource, ...]:
    candidates: dict[int, NormalizedResource] = {}

    def add_many(data_stores: Sequence[NormalizedResource]) -> None:
        for data_store in data_stores:
            candidates.setdefault(id(data_store), data_store)

    for security_group_id in workload.security_group_ids:
        security_group_key = security_group_relationships.reference_key(
            security_group_id,
            source=workload,
        )
        if security_group_key is not None:
            add_many(index.databases_by_trusted_workload_security_group.get(security_group_key, ()))
    if _workload_has_general_egress_path(workload):
        add_many(index.direct_internet_databases)
    scoped_vpc_key = aws_scoped_reference_key(workload.provider_config_key, workload.vpc_id)
    if scoped_vpc_key is not None:
        if workload.security_group_ids:
            add_many(index.databases_missing_security_groups_by_vpc.get(scoped_vpc_key, ()))
        else:
            add_many(index.databases_by_vpc.get(scoped_vpc_key, ()))
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


def _trusted_workload_security_group_keys(
    data_store: NormalizedResource,
    relationships: AwsSecurityGroupRelationships,
) -> set[AwsReferenceRelationshipKey]:
    trusted_group_keys: set[AwsReferenceRelationshipKey] = set()
    for security_group in relationships.attached_security_groups(data_store):
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            for reference in rule.referenced_security_group_ids:
                key = relationships.reference_key(reference, source=security_group)
                if key is not None:
                    trusted_group_keys.add(key)
    return trusted_group_keys


def _freeze_resource_groups_by_key(
    grouped: dict[_Key, list[NormalizedResource]],
) -> Mapping[_Key, tuple[NormalizedResource, ...]]:
    return {key: tuple(resources) for key, resources in grouped.items()}


def _role_allows_object_storage_access(role: NormalizedResource) -> bool:
    return any(
        statement.effect == "Allow" and any(action == "*" or action.startswith("s3:") for action in statement.actions)
        for statement in role.policy_statements
    )


def _role_allows_secret_read(role: NormalizedResource) -> bool:
    return any(
        statement.effect == "Allow" and any(_allows_secret_read(action) for action in statement.actions)
        for statement in role.policy_statements
    )


def _workload_reaches_data_store(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    attached_role: NormalizedResource | None,
    security_group_relationships: AwsSecurityGroupRelationships,
) -> str | None:
    if is_database_resource(data_store):
        return _database_reachability_rationale(
            workload,
            data_store,
            security_group_relationships,
        )
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
    security_group_relationships: AwsSecurityGroupRelationships,
) -> str | None:
    workload_vpc_key = aws_scoped_reference_key(workload.provider_config_key, workload.vpc_id)
    data_store_vpc_key = aws_scoped_reference_key(data_store.provider_config_key, data_store.vpc_id)
    if workload_vpc_key is not None and data_store_vpc_key is not None and workload_vpc_key != data_store_vpc_key:
        if not data_store.direct_internet_reachable:
            return None

    if _database_allows_workload_security_group(
        workload,
        data_store,
        security_group_relationships,
    ):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "database ingress security groups explicitly trust the workload security group."
        )

    if data_store.direct_internet_reachable and _workload_has_general_egress_path(workload):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "a directly internet-reachable database is reachable from a workload subnet with general egress."
        )

    if (
        (not workload.security_group_ids or not data_store.security_group_ids)
        and workload_vpc_key is not None
        and workload_vpc_key == data_store_vpc_key
    ):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "they share a VPC with the database and the plan does not provide tighter security-group evidence."
        )
    return None


def _database_allows_workload_security_group(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    relationships: AwsSecurityGroupRelationships,
) -> bool:
    if not workload.security_group_ids or not data_store.security_group_ids:
        return False
    workload_group_keys = {
        key
        for reference in workload.security_group_ids
        if (key := relationships.reference_key(reference, source=workload)) is not None
    }
    if not workload_group_keys:
        return False
    for security_group in relationships.attached_security_groups(data_store):
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            trusted_group_keys = {
                key
                for reference in rule.referenced_security_group_ids
                if (key := relationships.reference_key(reference, source=security_group)) is not None
            }
            if workload_group_keys.intersection(trusted_group_keys):
                return True
    return False


def _workload_has_general_egress_path(workload: NormalizedResource) -> bool:
    if has_provider_managed_egress_without_vpc(workload):
        return True
    return workload.in_public_subnet or workload.has_nat_gateway_egress


def _resource_policy_principals(
    resource: NormalizedResource,
    target_account: AwsAccountResolution,
) -> list[PrincipalAssessment]:
    principals: list[PrincipalAssessment] = []
    seen_principals: set[str] = set()
    for statement in resource.policy_statements:
        if statement.effect != "Allow":
            continue
        for assessment in policy_statement_principal_assessments(
            statement,
            target_account.account_id,
            target_partition=target_account.partition,
        ):
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
