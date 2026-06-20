from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tfstride.analysis.boundaries.shared import contribute_control_to_workload_boundary
from tfstride.analysis.boundaries.types import BoundaryContributionContext
from tfstride.analysis.gcp.custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_allows_data_store_access,
)
from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.analysis.policy_conditions import (
    PrincipalAssessment,
    federated_provider_description,
    policy_statement_principal_assessments,
    trust_statement_principal_assessments,
)
from tfstride.analysis.resource_concepts import (
    DATA_STORE_RESOURCE_TYPES,
    IDENTITY_ROLE_RESOURCE_TYPES,
    KEY_MANAGEMENT_RESOURCE_TYPES,
    WORKLOAD_RESOURCE_TYPES,
    has_provider_managed_egress_without_vpc,
    is_database_resource,
    is_identity_role_resource,
    is_key_management_resource,
    is_object_storage_resource,
    is_secret_store_resource,
)
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.role_helpers import resolve_workload_role
from tfstride.models import BoundaryType, NormalizedResource
from tfstride.providers.gcp.constants import GCP_PROJECT_IAM_RESOURCE_TYPES
from tfstride.providers.gcp.resource_utils import binding_members, dedupe


@dataclass(frozen=True, slots=True)
class _DataStoreCandidateIndex:
    data_store_positions: Mapping[int, int]
    object_storage: tuple[NormalizedResource, ...]
    secret_stores: tuple[NormalizedResource, ...]
    key_management: tuple[NormalizedResource, ...]
    cloud_data_stores: tuple[NormalizedResource, ...]
    databases: tuple[NormalizedResource, ...]
    direct_internet_databases: tuple[NormalizedResource, ...]
    databases_by_vpc: Mapping[str, tuple[NormalizedResource, ...]]
    databases_missing_security_groups_by_vpc: Mapping[str, tuple[NormalizedResource, ...]]
    databases_by_trusted_workload_security_group: Mapping[str, tuple[NormalizedResource, ...]]
    project_iam_resources: tuple[NormalizedResource, ...]
    gcp_custom_roles: GcpCustomRoleIndex


def contribute_trust_boundaries(context: BoundaryContributionContext) -> None:
    inventory = context.inventory
    resources = inventory.resources
    analysis_indexes = context.indexes
    add_boundary = context.add_boundary

    workloads = inventory.by_type(*WORKLOAD_RESOURCE_TYPES)
    data_store_candidates = _build_data_store_candidate_index(
        resources,
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
                data_store_candidates,
            )
            if reachability_rationale:
                add_boundary(
                    BoundaryType.WORKLOAD_TO_DATA_STORE,
                    workload.address,
                    data_store.address,
                    f"{workload.display_name} can interact with {data_store.display_name}.",
                    reachability_rationale,
                )
        contribute_control_to_workload_boundary(context, workload, attached_role)

    primary_account_id = inventory.primary_account_id
    for role in inventory.by_type(*IDENTITY_ROLE_RESOURCE_TYPES):
        seen_role_principals: set[tuple[str, str]] = set()
        for trust_statement in analysis_facts(role).iam.trust_statements:
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


def _build_data_store_candidate_index(
    resources: Sequence[NormalizedResource],
    indexes: AnalysisIndexes,
) -> _DataStoreCandidateIndex:
    candidate_types = set(DATA_STORE_RESOURCE_TYPES) | set(KEY_MANAGEMENT_RESOURCE_TYPES)
    data_stores = [resource for resource in resources if resource.resource_type in candidate_types]
    direct_internet_databases: list[NormalizedResource] = []
    databases: list[NormalizedResource] = []
    object_storage: list[NormalizedResource] = []
    secret_stores: list[NormalizedResource] = []
    key_management: list[NormalizedResource] = []
    cloud_data_stores: list[NormalizedResource] = []
    databases_by_vpc: dict[str, list[NormalizedResource]] = {}
    databases_missing_security_groups_by_vpc: dict[str, list[NormalizedResource]] = {}
    databases_by_trusted_workload_security_group: dict[str, list[NormalizedResource]] = {}
    project_iam_resources: list[NormalizedResource] = []

    for resource in resources:
        if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
            project_iam_resources.append(resource)

    for data_store in data_stores:
        if is_database_resource(data_store):
            databases.append(data_store)
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
        elif is_key_management_resource(data_store):
            key_management.append(data_store)
        else:
            cloud_data_stores.append(data_store)

    return _DataStoreCandidateIndex(
        data_store_positions={id(resource): index for index, resource in enumerate(data_stores)},
        object_storage=tuple(object_storage),
        secret_stores=tuple(secret_stores),
        key_management=tuple(key_management),
        cloud_data_stores=tuple(cloud_data_stores),
        databases=tuple(databases),
        direct_internet_databases=tuple(direct_internet_databases),
        databases_by_vpc=_freeze_resource_groups_by_key(databases_by_vpc),
        databases_missing_security_groups_by_vpc=_freeze_resource_groups_by_key(
            databases_missing_security_groups_by_vpc
        ),
        databases_by_trusted_workload_security_group=_freeze_resource_groups_by_key(
            databases_by_trusted_workload_security_group
        ),
        project_iam_resources=tuple(project_iam_resources),
        gcp_custom_roles=build_gcp_custom_role_index(resources),
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
    if _gcp_workload_identity_members(workload):
        add_many(index.databases)
        add_many(index.object_storage)
        add_many(index.secret_stores)
        add_many(index.key_management)
        add_many(index.cloud_data_stores)

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
    indexes: AnalysisIndexes,
    candidate_index: _DataStoreCandidateIndex,
) -> str | None:
    if workload.provider == "gcp" and data_store.provider == "gcp":
        return _gcp_workload_reaches_data_store(workload, data_store, indexes, candidate_index)
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


_GCP_BROAD_DATA_ACCESS_ROLES = frozenset({"roles/owner", "roles/editor"})
_GCP_OBJECT_STORAGE_ACCESS_ROLES = frozenset(
    {
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectCreator",
        "roles/storage.objectUser",
        "roles/storage.objectViewer",
    }
)
_GCP_SECRET_ACCESS_ROLES = frozenset(
    {
        "roles/secretmanager.admin",
        "roles/secretmanager.secretAccessor",
    }
)
_GCP_KMS_ACCESS_ROLES = frozenset(
    {
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    }
)
_GCP_CLOUD_SQL_ACCESS_ROLES = frozenset(
    {
        "roles/cloudsql.admin",
        "roles/cloudsql.client",
    }
)
_GCP_BIGQUERY_ACCESS_ROLES = frozenset(
    {
        "roles/bigquery.admin",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.dataViewer",
        "roles/bigquery.user",
    }
)
_GCP_PUBSUB_ACCESS_ROLES = frozenset(
    {
        "roles/pubsub.admin",
        "roles/pubsub.editor",
        "roles/pubsub.publisher",
        "roles/pubsub.subscriber",
        "roles/pubsub.viewer",
    }
)


def _gcp_workload_reaches_data_store(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    indexes: AnalysisIndexes,
    candidate_index: _DataStoreCandidateIndex,
) -> str | None:
    iam_rationale = _gcp_iam_reachability_rationale(workload, data_store, candidate_index)
    if not is_database_resource(data_store):
        return iam_rationale

    network_rationale = _database_reachability_rationale(workload, data_store, indexes)
    if network_rationale and iam_rationale:
        return f"{network_rationale} {iam_rationale}"
    return network_rationale or iam_rationale


def _gcp_iam_reachability_rationale(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    candidate_index: _DataStoreCandidateIndex,
) -> str | None:
    if not _gcp_workload_scopes_allow_access(workload, data_store):
        return None
    access_grants = _gcp_matching_iam_access_grants(workload, data_store, candidate_index)
    if not access_grants:
        return None
    grant_text = "; ".join(access_grants[:3])
    if len(access_grants) > 3:
        grant_text = f"{grant_text}; and {len(access_grants) - 3} more grants"
    return (
        "GCP workloads cross into a higher-sensitivity data plane when their attached "
        f"service account is granted data access through IAM: {grant_text}."
    )


def _gcp_matching_iam_access_grants(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    candidate_index: _DataStoreCandidateIndex,
) -> list[str]:
    workload_members = set(_gcp_workload_identity_members(workload))
    if not workload_members:
        return []

    grants: list[str] = []
    for binding in analysis_facts(data_store).iam.bindings:
        role = str(binding.get("role") or "")
        if not _gcp_role_allows_data_store_access(data_store, role, candidate_index.gcp_custom_roles):
            continue
        for member in sorted(workload_members.intersection(binding_members(binding))):
            source = str(binding.get("source") or data_store.address)
            grants.append(f"{source} grants {role} to {member}")

    data_store_project = analysis_facts(data_store).iam.project
    for project_iam_resource in candidate_index.project_iam_resources:
        project_iam_facts = analysis_facts(project_iam_resource)
        if not data_store_project or project_iam_facts.iam.project != data_store_project:
            continue
        for role, member in _project_iam_binding_members(project_iam_resource):
            if member not in workload_members or not _gcp_role_allows_data_store_access(
                data_store, role, candidate_index.gcp_custom_roles
            ):
                continue
            grants.append(f"{project_iam_resource.address} grants {role} to {member} at project scope")
    return dedupe(grants)


def _project_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    bindings = analysis_facts(resource).iam.bindings
    if not bindings:
        facts = analysis_facts(resource)
        role = facts.iam.role
        member = facts.iam.member
        if role and member:
            return [(role, member)]
        return []

    members: list[tuple[str, str]] = []
    for binding in bindings:
        role = str(binding.get("role") or "")
        for member in binding_members(binding):
            members.append((role, member))
    return members


def _gcp_workload_identity_members(workload: NormalizedResource) -> list[str]:
    return analysis_facts(workload).workload.identity_members


def _gcp_workload_scopes_allow_access(
    workload: NormalizedResource,
    data_store: NormalizedResource,
) -> bool:
    scopes = {scope.lower() for scope in analysis_facts(workload).workload.identity_scopes}
    if not scopes:
        return True
    if any(scope.endswith("/cloud-platform") or scope == "cloud-platform" for scope in scopes):
        return True
    if is_object_storage_resource(data_store):
        return any("devstorage" in scope for scope in scopes)
    if is_database_resource(data_store):
        return any("sqlservice.admin" in scope for scope in scopes)
    if data_store.resource_type in {"google_bigquery_dataset", "google_bigquery_table"}:
        return any("bigquery" in scope for scope in scopes)
    if data_store.resource_type in {"google_pubsub_subscription", "google_pubsub_topic"}:
        return any("pubsub" in scope for scope in scopes)
    return False


def _gcp_role_allows_data_store_access(
    resource: NormalizedResource,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> bool:
    if role in _GCP_BROAD_DATA_ACCESS_ROLES:
        return True
    if is_object_storage_resource(resource) and role in _GCP_OBJECT_STORAGE_ACCESS_ROLES:
        return True
    if is_secret_store_resource(resource) and role in _GCP_SECRET_ACCESS_ROLES:
        return True
    if is_key_management_resource(resource) and role in _GCP_KMS_ACCESS_ROLES:
        return True
    if is_database_resource(resource) and role in _GCP_CLOUD_SQL_ACCESS_ROLES:
        return True
    if resource.resource_type in {"google_bigquery_dataset", "google_bigquery_table"}:
        return role in _GCP_BIGQUERY_ACCESS_ROLES or custom_role_allows_data_store_access(resource, role, custom_roles)
    if resource.resource_type in {"google_pubsub_subscription", "google_pubsub_topic"}:
        return role in _GCP_PUBSUB_ACCESS_ROLES or custom_role_allows_data_store_access(resource, role, custom_roles)
    return custom_role_allows_data_store_access(resource, role, custom_roles)


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
    if has_provider_managed_egress_without_vpc(workload):
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
