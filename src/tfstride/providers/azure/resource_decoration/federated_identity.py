from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key
from tfstride.providers.resource_reference_index import (
    ResourceReferenceIndex,
    build_resource_reference_index,
)

_USER_ASSIGNED_IDENTITY_ARM_ID = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.managedidentity/userassignedidentities/[^/]+/?$",
    re.IGNORECASE,
)


class ModelFederatedManagedIdentityTrustPathsStage:
    name = "model_federated_managed_identity_trust_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        del context
        identity_index = _user_assigned_identity_reference_index(resources)
        for credential in sorted(
            (
                resource
                for resource in resources
                if resource.resource_type == AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL
            ),
            key=lambda resource: resource.address,
        ):
            self._model_credential_path(credential, identity_index)

    def _model_credential_path(
        self,
        credential: NormalizedResource,
        identity_index: ResourceReferenceIndex,
    ) -> None:
        credential_facts = azure_facts(credential)
        parent_id = credential_facts.federated_identity_credential_parent_id
        parent_key = _exact_parent_reference_key(parent_id)
        if not parent_key:
            credential_facts.extend_federated_managed_identity_trust_path_uncertainties(
                _credential_resolution_uncertainties(
                    credential,
                    "parent user-assigned identity ID is missing or unresolved",
                )
            )
            return

        resolution = identity_index.resolve(parent_key)
        identity = resolution.selected_candidate
        if identity is None:
            reason = (
                "matches multiple modeled user-assigned identities"
                if resolution.state == "ambiguous"
                else "does not resolve to a modeled user-assigned identity by exact Terraform reference or ARM ID"
            )
            credential_facts.extend_federated_managed_identity_trust_path_uncertainties(
                _credential_resolution_uncertainties(credential, f"parent identity reference {parent_id} {reason}")
            )
            return

        credential_facts.set_resolved_managed_identity_address(identity.address)
        identity_facts = azure_facts(identity)
        identity_facts.add_federated_managed_identity_trust_path(_trust_path_record(credential, identity))
        identity_facts.extend_federated_managed_identity_trust_path_uncertainties(
            f"{credential.address}: {uncertainty}"
            for uncertainty in credential_facts.federated_identity_credential_uncertainties
        )


def _user_assigned_identity_reference_index(
    resources: Iterable[NormalizedResource],
) -> ResourceReferenceIndex:
    return build_resource_reference_index(
        (resource for resource in resources if resource.resource_type == AzureResourceType.USER_ASSIGNED_IDENTITY),
        references_for_resource=_exact_user_assigned_identity_references,
        reference_key=_exact_parent_reference_key,
    )


def _exact_user_assigned_identity_references(identity: NormalizedResource) -> tuple[str, ...]:
    references = {identity.address, f"{identity.address}.id"}
    if _USER_ASSIGNED_IDENTITY_ARM_ID.fullmatch(identity.identifier or ""):
        references.add(identity.identifier or "")
    return tuple(references)


def _exact_parent_reference_key(value: str | None) -> str:
    if value is None:
        return ""
    text = value.strip()
    if not text:
        return ""
    if text.startswith("$" + "{") and text.endswith("}"):
        text = text[2:-1].strip()
    if "$" + "{" in text or "}" in text or any(character.isspace() for character in text):
        return ""
    return azure_reference_key(text)


def _credential_resolution_uncertainties(
    credential: NormalizedResource,
    resolution_uncertainty: str,
) -> list[str]:
    facts = azure_facts(credential)
    values = [
        *(f"{credential.address}: {value}" for value in facts.federated_identity_credential_uncertainties),
        f"{credential.address}: {resolution_uncertainty}",
    ]
    return list(dict.fromkeys(values))


def _trust_path_record(
    credential: NormalizedResource,
    identity: NormalizedResource,
) -> dict[str, Any]:
    credential_facts = azure_facts(credential)
    identity_facts = azure_facts(identity)
    return {
        "credential_address": credential.address,
        "credential_id": credential.identifier,
        "identity_address": identity.address,
        "identity_id": identity.identifier,
        "identity_principal_id": identity_facts.principal_id,
        "identity_client_id": identity_facts.client_id,
        "issuer": credential_facts.federated_identity_credential_issuer,
        "subject": credential_facts.federated_identity_credential_subject,
        "audiences": credential_facts.federated_identity_credential_audiences,
        "parent_identity_id": credential_facts.federated_identity_credential_parent_id,
        "grant_basis": "federated_identity_credential",
    }
