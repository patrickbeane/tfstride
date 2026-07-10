from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from tfstride.identity import PrivilegedAccessGrant, PrivilegedAccessPosture
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.iam_assignment_posture import deserialize_privileged_access_grants
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts
from tfstride.providers.gcp.resource_utils import service_account_member


class GcpIdentityFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def privileged_access_grants(self) -> tuple[PrivilegedAccessGrant, ...]:
        return deserialize_privileged_access_grants(self.get(GcpResourceMetadata.PRIVILEGED_ACCESS_GRANTS))

    @property
    def iam_assignment_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES)

    @property
    def privileged_access_posture(self) -> PrivilegedAccessPosture:
        return PrivilegedAccessPosture(
            provider="gcp",
            grants=self.privileged_access_grants,
            unresolved_assignments=self.iam_assignment_posture_uncertainties,
        )

    @property
    def service_account_key_keepers(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_KEEPERS)

    @property
    def service_account_key_algorithm(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM)

    @property
    def service_account_public_key_type(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE)

    @property
    def service_account_id(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_ID)

    @property
    def service_account_key_valid_after(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER)

    @property
    def service_account_key_valid_before(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE)

    @property
    def service_account_email(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL)

    @property
    def service_account_member(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER)

    @property
    def service_account_reference(self) -> str | None:
        return self.get(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE)

    @property
    def identity_members(self) -> list[str]:
        members: list[str] = []
        for account in self.get(GcpResourceMetadata.SERVICE_ACCOUNTS):
            email = _service_account_email(account)
            if email is None:
                continue
            member = service_account_member(email)
            if member is not None:
                members.append(member)
        return dedupe(members)

    @property
    def identity_scopes(self) -> list[str]:
        scopes: list[str] = []
        for account in self.get(GcpResourceMetadata.SERVICE_ACCOUNTS):
            if not isinstance(account, dict):
                continue
            account_scopes = account.get("scopes")
            if isinstance(account_scopes, list):
                scopes.extend(str(scope) for scope in account_scopes if scope not in (None, ""))
            elif account_scopes not in (None, ""):
                scopes.append(str(account_scopes))
        return dedupe(scopes)

    def set_privileged_access_grants(self, values: Sequence[dict[str, Any]]) -> None:
        self.set(GcpResourceMetadata.PRIVILEGED_ACCESS_GRANTS, list(values))

    def extend_iam_assignment_posture_uncertainties(self, values: Sequence[str | None]) -> None:
        self.extend(GcpResourceMetadata.IAM_ASSIGNMENT_POSTURE_UNCERTAINTIES, values)


def _service_account_email(value: Any) -> str | None:
    if isinstance(value, dict):
        email = value.get("email")
    else:
        email = value
    if email in (None, "", "default"):
        return None
    text = str(email).strip()
    if not text or text == "default":
        return None
    if text.startswith("serviceAccount:"):
        return text.removeprefix("serviceAccount:")
    return text
