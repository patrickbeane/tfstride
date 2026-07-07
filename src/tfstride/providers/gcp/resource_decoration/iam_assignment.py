from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.iam_assignment_posture import (
    build_gcp_custom_role_index,
    build_gcp_privileged_access_posture,
    serialize_privileged_access_posture,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_IAM_GRANT_RESOURCE_TYPES


class NormalizeIamAssignmentPostureStage:
    name = "normalize_iam_assignment_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        custom_roles = build_gcp_custom_role_index(resources)
        for resource in resources:
            if resource.resource_type not in GCP_IAM_GRANT_RESOURCE_TYPES:
                continue
            posture = build_gcp_privileged_access_posture(resource, custom_roles=custom_roles)
            facts = gcp_facts(resource)
            facts.set_privileged_access_grants(serialize_privileged_access_posture(posture))
            facts.extend_iam_assignment_posture_uncertainties(posture.unresolved_assignments)
