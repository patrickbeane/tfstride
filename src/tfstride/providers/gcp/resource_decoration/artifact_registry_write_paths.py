from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_ARTIFACT_REGISTRY_REPOSITORY = GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY
_ARTIFACT_REGISTRY_WRITE_ROLE_KINDS = {
    "roles/artifactregistry.writer": "writer",
    "roles/artifactregistry.createOnPushWriter": "writer",
    "roles/artifactregistry.repoAdmin": "admin",
    "roles/artifactregistry.createOnPushRepoAdmin": "admin",
    "roles/artifactregistry.admin": "admin",
}


class ModelCloudRunArtifactRegistryWritePathsStage:
    name = "model_cloud_run_artifact_registry_write_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_artifact_registry_write_paths(workload, context)
            facts = gcp_facts(workload)
            facts.set_artifact_registry_write_paths(paths)
            facts.extend_artifact_registry_write_path_uncertainties(uncertainties)


def _cloud_run_artifact_registry_write_paths(
    workload: NormalizedResource,
    context: GcpDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = gcp_facts(workload)
    artifact_images: list[Mapping[str, Any]] = []
    uncertainties: list[str] = []
    for reference in workload_facts.container_image_references:
        repository_path = reference.get("artifact_registry_repository_path")
        if not isinstance(repository_path, str) or not repository_path:
            continue
        if reference.get("is_resolved") is not True:
            uncertainties.append(
                f"{workload.address}: Artifact Registry image reference is unresolved at "
                f"{reference.get('path') or 'unknown path'}"
            )
            continue
        artifact_images.append(reference)

    if not artifact_images:
        return [], _dedupe_strings(uncertainties)

    service_account_member = workload_facts.service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    paths: list[dict[str, Any]] = []
    for image_reference in artifact_images:
        repository_path = image_reference["artifact_registry_repository_path"]
        repository = _repository_for_path(repository_path, context)
        if repository is None:
            uncertainties.append(
                f"{workload.address}: Artifact Registry repository path {repository_path} is not modeled"
            )
            continue

        repository_references = _repository_exact_references(repository)
        for iam_resource in context.index.artifact_registry_iam_resources:
            iam_facts = gcp_facts(iam_resource)
            target_reference = iam_facts.target_reference
            if target_reference is None:
                uncertainties.extend(
                    f"{workload.address}: {iam_resource.address}: {uncertainty}"
                    for uncertainty in iam_facts.artifact_registry_iam_posture_uncertainties
                )
                if not iam_facts.artifact_registry_iam_posture_uncertainties:
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address}: repository reference is unresolved"
                    )
                continue
            if gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES) not in repository_references:
                continue

            for binding in iam_bindings(iam_resource):
                members = binding_members(binding)
                if service_account_member not in members:
                    if any(
                        "member" in uncertainty or "members" in uncertainty
                        for uncertainty in iam_facts.artifact_registry_iam_posture_uncertainties
                    ):
                        uncertainties.extend(
                            f"{workload.address}: {iam_resource.address}: {uncertainty}"
                            for uncertainty in iam_facts.artifact_registry_iam_posture_uncertainties
                        )
                    continue
                role = str(binding.get("role") or "").strip()
                role_kind = _ARTIFACT_REGISTRY_WRITE_ROLE_KINDS.get(role)
                if role_kind is None:
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address}: role {role or 'unknown'} "
                        "is not classified as a deterministic Artifact Registry writer/admin role"
                    )
                    continue
                condition = binding.get("condition")
                if condition:
                    uncertainties.append(
                        f"{workload.address}: {iam_resource.address}: conditional {role} grant "
                        "was not treated as deterministic"
                    )
                    continue
                paths.append(
                    _write_path_record(
                        workload,
                        workload_facts.service_account_email,
                        service_account_member,
                        image_reference,
                        repository,
                        iam_resource,
                        role,
                        role_kind,
                    )
                )

    return paths, _dedupe_strings(uncertainties)


def _repository_for_path(
    repository_path: str,
    context: GcpDecorationContext,
) -> NormalizedResource | None:
    repository = context.index.resources_by_reference.get(
        gcp_reference_key(repository_path, GCP_NETWORK_REFERENCE_SUFFIXES)
    )
    if repository is None or repository.resource_type != _ARTIFACT_REGISTRY_REPOSITORY:
        return None
    return repository


def _repository_exact_references(repository: NormalizedResource) -> set[str]:
    references = {
        gcp_reference_key(repository.address, GCP_NETWORK_REFERENCE_SUFFIXES),
        gcp_reference_key(f"{repository.address}.id", GCP_NETWORK_REFERENCE_SUFFIXES),
        gcp_reference_key(f"{repository.address}.name", GCP_NETWORK_REFERENCE_SUFFIXES),
    }
    path = gcp_facts(repository).artifact_registry_repository_path
    if path:
        references.add(gcp_reference_key(path, GCP_NETWORK_REFERENCE_SUFFIXES))
    return references


def _write_path_record(
    workload: NormalizedResource,
    service_account_email: str | None,
    service_account_member: str,
    image_reference: Mapping[str, Any],
    repository: NormalizedResource,
    iam_resource: NormalizedResource,
    role: str,
    role_kind: str,
) -> dict[str, Any]:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "image_reference": image_reference.get("raw"),
        "image_reference_path": image_reference.get("path"),
        "image_tag": image_reference.get("tag"),
        "image_digest": image_reference.get("digest"),
        "image_digest_pinned": image_reference.get("digest_pinned"),
        "artifact_registry_repository_address": repository.address,
        "artifact_registry_repository_path": image_reference.get("artifact_registry_repository_path"),
        "iam_resource_address": iam_resource.address,
        "role": role,
        "role_kind": role_kind,
        "grant_basis": "artifact_registry_repository_iam",
        "repository_scope": "exact_repository_path",
    }


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
