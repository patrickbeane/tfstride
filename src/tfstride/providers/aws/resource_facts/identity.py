from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.identity import PrivilegedAccessGrant, PrivilegedAccessPosture
from tfstride.providers.aws.iam_assignment_posture import deserialize_privileged_access_grants
from tfstride.providers.aws.metadata import AwsResourceMetadata


class AwsIdentityFacts:
    __slots__ = ()

    @property
    def privileged_access_grants(self) -> tuple[PrivilegedAccessGrant, ...]:
        return deserialize_privileged_access_grants(self.get(AwsResourceMetadata.PRIVILEGED_ACCESS_GRANTS))

    @property
    def iam_assignment_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES)

    @property
    def privileged_access_posture(self) -> PrivilegedAccessPosture:
        return PrivilegedAccessPosture(
            provider="aws",
            grants=self.privileged_access_grants,
            unresolved_assignments=self.iam_assignment_posture_uncertainties,
        )

    def set_privileged_access_grants(self, values: Sequence[dict[str, Any]]) -> None:
        self.set(AwsResourceMetadata.PRIVILEGED_ACCESS_GRANTS, list(values))

    def extend_iam_assignment_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(AwsResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES, values)
