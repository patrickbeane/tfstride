from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.identity import PrivilegedAccessGrant, PrivilegedAccessPosture
from tfstride.providers.aws.account_identity_evidence import AwsAccountArnInput
from tfstride.providers.aws.iam_assignment_posture import deserialize_privileged_access_grants
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_facts.base import AwsBaseFacts


class AwsIdentityFacts(AwsBaseFacts):
    __slots__ = ()

    @property
    def has_account_identity_inputs(self) -> bool:
        return self.resource.has_metadata_field(AwsResourceMetadata.ACCOUNT_IDENTITY_SOURCE_MODE)

    @property
    def account_identity_source_mode(self) -> str | None:
        return self.get(AwsResourceMetadata.ACCOUNT_IDENTITY_SOURCE_MODE)

    @property
    def account_identity_arn_inputs(self) -> list[AwsAccountArnInput]:
        return self.get(AwsResourceMetadata.ACCOUNT_IDENTITY_ARN_INPUTS)

    def set_account_identity_inputs(self, mode: str, inputs: list[AwsAccountArnInput]) -> None:
        self.set(AwsResourceMetadata.ACCOUNT_IDENTITY_SOURCE_MODE, mode)
        self.set(AwsResourceMetadata.ACCOUNT_IDENTITY_ARN_INPUTS, inputs)

    @property
    def caller_identity_account_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_ID)

    @property
    def caller_identity_account_id_state(self) -> str | None:
        return self.get(AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_ID_STATE)

    @property
    def caller_identity_account_evidence(self) -> list[str]:
        return self.get(AwsResourceMetadata.CALLER_IDENTITY_ACCOUNT_EVIDENCE)

    @property
    def caller_identity_user_id(self) -> str | None:
        return self.get(AwsResourceMetadata.CALLER_IDENTITY_USER_ID)

    @property
    def caller_identity_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.CALLER_IDENTITY_POSTURE_UNCERTAINTIES)

    @property
    def oidc_provider_url(self) -> str | None:
        return self.get(AwsResourceMetadata.OIDC_PROVIDER_URL)

    @property
    def oidc_provider_arn(self) -> str | None:
        return self.get(AwsResourceMetadata.OIDC_PROVIDER_ARN)

    @property
    def oidc_provider_client_ids(self) -> list[str]:
        return self.get(AwsResourceMetadata.OIDC_PROVIDER_CLIENT_IDS)

    @property
    def oidc_provider_thumbprints(self) -> list[str]:
        return self.get(AwsResourceMetadata.OIDC_PROVIDER_THUMBPRINTS)

    @property
    def oidc_provider_posture_uncertainties(self) -> list[str]:
        return self.get(AwsResourceMetadata.OIDC_PROVIDER_POSTURE_UNCERTAINTIES)

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
