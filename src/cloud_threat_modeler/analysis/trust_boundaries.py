from __future__ import annotations

from cloud_threat_modeler.analysis.policy_conditions import PrincipalAssessment, assess_principal
from cloud_threat_modeler.models import BoundaryType, NormalizedResource, ResourceInventory, TrustBoundary


WORKLOAD_TYPES = {"aws_instance", "aws_lambda_function"}
DATA_STORE_TYPES = {"aws_db_instance", "aws_s3_bucket", "aws_secretsmanager_secret"}


class TrustBoundaryDetector:
    def detect(self, inventory: ResourceInventory) -> list[TrustBoundary]:
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
        role_index = _role_index(resources)

        for resource in resources:
            if resource.metadata.get("direct_internet_reachable") and resource.resource_type in {
                "aws_instance",
                "aws_lb",
                "aws_db_instance",
                "aws_s3_bucket",
            }:
                add_boundary(
                    BoundaryType.INTERNET_TO_SERVICE,
                    "internet",
                    resource.address,
                    f"Traffic can cross from the public internet to {resource.display_name}.",
                    "The resource is directly reachable or intentionally exposed to unauthenticated network clients.",
                )

        public_subnets = [resource for resource in resources if resource.resource_type == "aws_subnet" and resource.metadata.get("is_public_subnet")]
        private_subnets = [resource for resource in resources if resource.resource_type == "aws_subnet" and not resource.metadata.get("is_public_subnet")]
        for public_subnet in public_subnets:
            for private_subnet in private_subnets:
                # Model segmentation at the trust-zone level rather than every possible route;
                # for review purposes, "public subnet can reach private subnet" is the key edge.
                if public_subnet.vpc_id and public_subnet.vpc_id == private_subnet.vpc_id:
                    add_boundary(
                        BoundaryType.PUBLIC_TO_PRIVATE,
                        public_subnet.address,
                        private_subnet.address,
                        f"Traffic can move from {public_subnet.display_name} toward {private_subnet.display_name}.",
                        "The VPC contains both publicly routable and private network segments that should be treated as separate trust zones.",
                    )

        workloads = [resource for resource in resources if resource.resource_type in WORKLOAD_TYPES]
        data_stores = [resource for resource in resources if resource.resource_type in DATA_STORE_TYPES]
        for workload in workloads:
            attached_role = _resolve_role_for_workload(workload, role_index)
            for data_store in data_stores:
                reachability_rationale = _workload_reaches_data_store(workload, data_store, attached_role, inventory)
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

        primary_account_id = inventory.metadata.get("primary_account_id")
        for role in inventory.by_type("aws_iam_role"):
            for principal in role.metadata.get("trust_principals", []):
                assessment = assess_principal(principal, primary_account_id)
                if assessment.is_service:
                    continue
                if assessment.is_wildcard:
                    description = f"{role.display_name} trusts any principal."
                else:
                    description = f"{role.display_name} trusts {principal}."
                if assessment.is_foreign_account:
                    rationale = "A foreign AWS account can cross into this role's trust boundary."
                else:
                    rationale = "An additional role or principal can cross into this role's trust boundary."
                add_boundary(
                    BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                    principal,
                    role.address,
                    description,
                    rationale,
                )

        for resource in resources:
            if resource.resource_type == "aws_iam_role":
                continue
            for assessment in _resource_policy_principals(resource, primary_account_id):
                principal = assessment.principal
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


def _role_index(resources: list[NormalizedResource]) -> dict[str, NormalizedResource]:
    index: dict[str, NormalizedResource] = {}
    for resource in resources:
        if resource.resource_type != "aws_iam_role":
            continue
        if resource.arn:
            index[resource.arn] = resource
        index[resource.address] = resource
        if resource.identifier:
            index[resource.identifier] = resource
    return index


def _resolve_role_for_workload(
    workload: NormalizedResource,
    role_index: dict[str, NormalizedResource],
) -> NormalizedResource | None:
    for role_arn in workload.attached_role_arns:
        if role_arn in role_index:
            return role_index[role_arn]
    return None


def _workload_reaches_data_store(
    workload: NormalizedResource,
    data_store: NormalizedResource,
    attached_role: NormalizedResource | None,
    inventory: ResourceInventory,
) -> str | None:
    if data_store.resource_type == "aws_db_instance":
        return _database_reachability_rationale(workload, data_store, inventory)
    if data_store.resource_type == "aws_s3_bucket":
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
    if data_store.resource_type == "aws_secretsmanager_secret":
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
    inventory: ResourceInventory,
) -> str | None:
    if workload.vpc_id and data_store.vpc_id and workload.vpc_id != data_store.vpc_id:
        if not data_store.metadata.get("direct_internet_reachable"):
            return None

    if _database_allows_workload_security_group(workload, data_store, inventory):
        return (
            "Application or function workloads cross into a higher-sensitivity data plane when "
            "database ingress security groups explicitly trust the workload security group."
        )

    if data_store.metadata.get("direct_internet_reachable") and _workload_has_general_egress_path(workload):
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
    inventory: ResourceInventory,
) -> bool:
    if not workload.security_group_ids or not data_store.security_group_ids:
        return False
    workload_group_ids = set(workload.security_group_ids)
    for security_group_id in data_store.security_group_ids:
        security_group = inventory.get_by_identifier(security_group_id)
        if security_group is None or security_group.resource_type != "aws_security_group":
            continue
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            if workload_group_ids.intersection(rule.referenced_security_group_ids):
                return True
    return False


def _workload_has_general_egress_path(workload: NormalizedResource) -> bool:
    if workload.resource_type == "aws_lambda_function" and not workload.metadata.get("vpc_enabled", True):
        return True
    return bool(workload.metadata.get("public_subnet") or workload.metadata.get("has_nat_gateway_egress"))


def _resource_policy_principals(
    resource: NormalizedResource,
    primary_account_id: str | None,
) -> list[PrincipalAssessment]:
    principals: list[PrincipalAssessment] = []
    for statement in resource.policy_statements:
        if statement.effect != "Allow":
            continue
        for principal in statement.principals:
            assessment = assess_principal(principal, primary_account_id)
            if assessment.is_service:
                continue
            if resource.resource_type == "aws_s3_bucket" and assessment.is_wildcard:
                continue
            if assessment.scope_description is None:
                continue
            if all(existing.principal != assessment.principal for existing in principals):
                principals.append(assessment)
    return principals


def _allows_secret_read(action: str) -> bool:
    return action == "*" or action == "secretsmanager:*" or action.startswith("secretsmanager:GetSecretValue")
