from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_index import GcpResourceIndex, gcp_resource_references
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)


def derive_public_bucket_exposure(bucket: NormalizedResource, index: GcpResourceIndex) -> None:
    public_access_reasons = _bucket_public_access_reasons(bucket, index)
    gcp_mutations(bucket).set_public_access(
        configured=bool(public_access_reasons),
        reasons=public_access_reasons,
    )

    public_exposure = bool(public_access_reasons) and not _public_access_prevention_enforced(bucket)
    gcp_mutations(bucket).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _bucket_public_access_reasons(bucket: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    reasons: list[str] = []
    bucket_references = set(gcp_resource_references(bucket))
    for iam_resource in index.bucket_iam_resources:
        iam_bucket = iam_resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
        if not iam_bucket or gcp_reference_key(iam_bucket, GCP_NETWORK_REFERENCE_SUFFIXES) not in bucket_references:
            continue
        for binding in iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            public_members = sorted(member for member in binding_members(binding) if member in PUBLIC_GCP_IAM_MEMBERS)
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)


def _public_access_prevention_enforced(bucket: NormalizedResource) -> bool:
    value = bucket.get_metadata_field(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)
    return value is not None and value.strip().lower() == "enforced"
