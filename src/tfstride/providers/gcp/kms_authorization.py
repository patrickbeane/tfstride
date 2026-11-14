from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.kms_evidence import (
    GcpCloudRunKmsManagementPath,
    GcpCloudRunKmsOperationPath,
    GcpKmsManagementIamGrant,
)
from tfstride.providers.gcp.resource_decoration.kms_iam import (
    evaluate_kms_key_grants,
    evaluate_kms_key_ring_grants,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import (
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)


@dataclass(frozen=True, slots=True)
class GcpKmsAuthorizationContext:
    """Current IAM dependencies and lazy grants for one analysis preparation.

    Construct a fresh context after resource mutations. Cached grants are derived
    from current bindings, role definitions and references, never decoration
    evidence. Include all IAM managers so a new conflicting policy or binding
    can invalidate a previously deterministic path.
    """

    _iam_resources: tuple[NormalizedResource, ...]
    _custom_roles: GcpCustomRoleIndex
    _decoration_context: GcpDecorationContext
    _grants: dict[str, tuple[GcpKmsManagementIamGrant, ...]] = field(default_factory=dict)

    @classmethod
    def build(cls, resources: Sequence[NormalizedResource]) -> GcpKmsAuthorizationContext:
        current_resources = list(resources)
        return cls(
            _iam_resources=tuple(
                resource
                for resource in current_resources
                if resource.resource_type
                in (
                    GCP_PROJECT_IAM_RESOURCE_TYPES
                    | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
                    | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
                )
            ),
            _custom_roles=build_gcp_custom_role_index(current_resources),
            _decoration_context=GcpDecorationContext(GcpResourceIndexBuilder().build(current_resources)),
        )

    def authorizes(
        self,
        path: GcpCloudRunKmsOperationPath | GcpCloudRunKmsManagementPath,
        member: str,
        target: NormalizedResource,
    ) -> bool:
        """Validate a retained proof's source, scope, member and operation.

        Callers also check the workload and target identities and operation
        compatibility. This validates existing paths; discovering new paths
        after changing inputs still requires decoration.
        """
        return any(
            grant["source"] == path["iam_resource_address"]
            and grant["source_type"] == path["iam_resource_type"]
            and grant["role"] == path["role"]
            and grant["scope_type"] == path["scope_type"]
            and grant["scope"] == path["scope"]
            and grant["grant_basis"] == path["grant_basis"]
            and grant["project"] == path["key_project"]
            and grant["key_ring"] == path["key_ring"]
            and grant["authorization_state"] == "granted"
            and grant["management_state"] == "unambiguous"
            and grant["condition_state"] == "not_configured"
            and member in grant["members"]
            and path["operation"] in grant["scope_effective_permissions"]
            for grant in self._grants_for(target)
        )

    def _grants_for(self, target: NormalizedResource) -> tuple[GcpKmsManagementIamGrant, ...]:
        if target.address not in self._grants:
            if target.resource_type == GcpResourceType.KMS_CRYPTO_KEY:
                grants, _ = evaluate_kms_key_grants(
                    target, self._iam_resources, self._custom_roles, self._decoration_context
                )
                self._grants[target.address] = tuple(grants)
            elif target.resource_type == GcpResourceType.KMS_KEY_RING:
                ring_grants, _ = evaluate_kms_key_ring_grants(
                    target, self._iam_resources, self._custom_roles, self._decoration_context
                )
                self._grants[target.address] = tuple(ring_grants)
            else:
                return ()
        return self._grants[target.address]
