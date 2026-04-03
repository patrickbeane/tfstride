from __future__ import annotations

from cloud_threat_modeler.models import BoundaryType, NormalizedResource, ResourceInventory, TrustBoundary


WORKLOAD_TYPES = {"aws_instance", "aws_lambda_function"}
DATA_STORE_TYPES = {"aws_db_instance", "aws_s3_bucket"}


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
            if resource.public_exposure and resource.resource_type in {
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
                if _workload_reaches_data_store(workload, data_store, attached_role):
                    add_boundary(
                        BoundaryType.WORKLOAD_TO_DATA_STORE,
                        workload.address,
                        data_store.address,
                        f"{workload.display_name} can interact with {data_store.display_name}.",
                        "Application or function workloads cross into a higher-sensitivity data plane when they reach databases or object storage.",
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
                if principal.endswith(".amazonaws.com"):
                    continue
                account_id = _parse_account_id_from_principal(principal)
                if principal == "*":
                    description = f"{role.display_name} trusts any principal."
                else:
                    description = f"{role.display_name} trusts {principal}."
                if account_id and primary_account_id and account_id != primary_account_id:
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
) -> bool:
    if data_store.resource_type == "aws_db_instance":
        # RDS reachability is approximated as "same VPC" in v1; finer-grained network path
        # modeling can be layered on later without changing the boundary type.
        return bool(workload.vpc_id and data_store.vpc_id and workload.vpc_id == data_store.vpc_id)
    if data_store.resource_type == "aws_s3_bucket":
        if attached_role is None:
            return False
        # For S3, the meaningful boundary is permission-based rather than network-based.
        return any(
            any(action == "*" or action.startswith("s3:") for action in statement.actions)
            for statement in attached_role.policy_statements
            if statement.effect == "Allow"
        )
    return False


def _parse_account_id_from_principal(principal: str) -> str | None:
    if principal == "*":
        return None
    if principal.startswith("arn:"):
        parts = principal.split(":")
        if len(parts) >= 5:
            return parts[4] or None
    return None
